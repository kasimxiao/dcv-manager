"""批量任务引擎：后台线程执行，逐台记录结果，前端通过任务中心查看进度。

- 电源操作：并发 20（EC2 API，秒级完成）
- 应用权限模板：并发 10（每台经 SSM 重建会话约 10–20 秒）
- 巡检：单条 SSM 命令批量下发，每批 50 台
同一台机器同时只允许一个未完成的任务，避免重建会话与电源操作冲突。
"""
import logging
import threading
import time
import concurrent.futures as cf

import aws_service
import dcv_service
import db
import store
import inspect_service

log = logging.getLogger("dcv.jobs")

POWER_ZH = {"start": "开机", "stop": "关机", "reboot": "重启"}
# 共享盘配置变化时正忙的服务器，任务结束后自动补同步
PENDING_SHARE_SYNC = set()


def _flush_pending_share_sync():
    ids = [i for i in list(PENDING_SHARE_SYNC) if i not in store.running_jobs_for([i])]
    if not ids:
        return
    for i in ids:
        PENDING_SHARE_SYNC.discard(i)
    try:
        jid = start_share_sync(ids, "系统（补同步共享盘）", f"补同步共享盘（{len(ids)} 台）")
        log.info("补同步共享盘任务 #%s：%s", jid, ids)
    except Exception:  # noqa: BLE001
        log.exception("补同步共享盘失败")
        PENDING_SHARE_SYNC.update(ids)


class BusyError(Exception):
    pass


def _names(instance_ids):
    by_id = {i["instance_id"]: i for i in aws_service.list_instances()}
    missing = [x for x in instance_ids if x not in by_id]
    if missing:
        raise ValueError(f"以下实例不存在或未纳管：{', '.join(missing)}")
    return by_id


def _start(jtype, title, params, instance_ids, operator, worker):
    ids = list(dict.fromkeys(instance_ids))
    if not ids:
        raise ValueError("请至少选择一台服务器")
    by_id = _names(ids)
    busy = store.running_jobs_for(ids)
    if busy:
        names = "、".join(by_id[i]["name"] or i for i in busy)
        raise BusyError(f"以下服务器有未完成的任务，请稍后再试：{names}")
    jid = store.create_job(jtype, title, params, [(i, by_id[i]["name"]) for i in ids], operator)

    def run():
        try:
            worker(jid, [by_id[i] for i in ids])
        except Exception as e:  # noqa: BLE001
            log.exception("任务 #%s 异常", jid)
            for i in ids:
                store.update_item(jid, i, "failed", f"任务异常：{e}")
        finally:
            aws_service.invalidate_cache()
            store.finish_job(jid)
            if PENDING_SHARE_SYNC & set(ids):
                threading.Thread(target=_flush_pending_share_sync, daemon=True).start()

    threading.Thread(target=run, name=f"job-{jid}", daemon=True).start()
    return jid


def _pool(jid, insts, fn, workers):
    def wrap(inst):
        iid = inst["instance_id"]
        store.update_item(jid, iid, "running")
        try:
            # 每台在其所在区域执行（ec2/ssm 代理按线程内的区域路由）
            with aws_service.use_region(inst.get("region")):
                status, msg = fn(inst)
        except Exception as e:  # noqa: BLE001
            status, msg = "failed", str(e)
        store.update_item(jid, iid, status, msg)
        store.refresh_progress(jid)
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(wrap, insts))


# ---------------- 电源 ----------------

def start_power(instance_ids, action, operator, fallback_types=None):
    """fallback_types: 开机遇到容量不足时，按顺序改成这些机型再试（仅对已停止的服务器有效）。

    None 表示按各服务器自己的备选机型设置；[] 表示本次不换机型。
    """
    if action not in POWER_ZH:
        raise ValueError("非法操作")
    if fallback_types is not None:
        fallback_types = [t for t in fallback_types if t]

    def start_with_fallback(inst):
        iid = inst["instance_id"]
        try:
            aws_service.power_action(iid, "start")
            return "success", "指令已提交"
        except Exception as e:  # noqa: BLE001
            if not aws_service.is_capacity_error(e):
                raise
        tried = [inst["instance_type"]]
        chain = inst.get("fallback_types", []) if fallback_types is None else fallback_types
        for t in chain:
            if t in tried:
                continue
            tried.append(t)
            aws_service.change_instance_type(iid, t)
            db.add_audit(iid, "change_type", operator, f"{inst['instance_type']} 容量不足，自动改为 {t}（批量任务 #{jid_holder[0]}）")
            try:
                aws_service.power_action(iid, "start")
                aws_service.mark_fallback(iid, inst["instance_type"])
                return "success", f"{inst['instance_type']} 容量不足，已改为 {t} 并开机（关机后自动改回 {inst['instance_type']}）"
            except Exception as e:  # noqa: BLE001
                if not aws_service.is_capacity_error(e):
                    raise
        if len(tried) > 1:  # 全部失败：改回原机型，保持原状
            aws_service.change_instance_type(iid, inst["instance_type"])
        return "failed", (f"容量不足：{inst['az']} 暂无 {'、'.join(tried)} 可用。"
                          "可稍后重试、改用其他机型，或在「容量检测」查看各可用区情况")

    def fn(inst):
        state = inst["state"]
        if action == "start" and state in ("running", "pending"):
            return "skipped", "已在运行"
        if action in ("stop", "reboot") and state in ("stopped", "stopping"):
            return "skipped", "已关机"
        if action == "reboot" and state != "running":
            return "skipped", f"当前状态 {state}，无法重启"
        if action == "start":
            st, msg = start_with_fallback(inst)
            db.add_audit(inst["instance_id"], "start", operator, f"批量任务 #{jid_holder[0]}：{msg}")
            return st, msg
        aws_service.power_action(inst["instance_id"], action)
        db.add_audit(inst["instance_id"], action, operator, f"批量任务 #{jid_holder[0]}")
        return "success", "指令已提交"

    jid_holder = [None]

    def worker(jid, insts):
        jid_holder[0] = jid
        _pool(jid, insts, fn, 20)
        if action == "start":
            import capacity_service
            capacity_service.invalidate()  # 各区域的容量结论都可能变化

    n = len(instance_ids)
    return _start("power", f"批量{POWER_ZH[action]}（{n} 台）", {"action": action, "fallback_types": fallback_types},
                  instance_ids, operator, worker)


# ---------------- 应用权限模板 ----------------

def start_apply_template(instance_ids, template_id, operator, owner=None, init_shares=False):
    tpl = store.get_template(template_id)
    if not tpl:
        raise ValueError("模板不存在")

    def fn(inst):
        iid = inst["instance_id"]
        if inst["state"] != "running":
            return "skipped", "实例未运行，未下发（开机后可在服务器列表中重新应用）"
        if inst.get("ssm") != "Online":
            return "failed", "SSM 代理离线，无法下发"
        res = dcv_service.apply_permissions(iid, tpl["spec"], owner)
        if not res.get("verified"):
            detail = []
            if not res.get("file_ok"):
                detail.append("权限文件核对不一致")
            if not res.get("session_ok"):
                detail.append("会话未按属主重建")
            return "failed", "；".join(detail) or res.get("error") or res.get("status")
        store.bind_template(iid, tpl["id"], tpl["version"], operator)
        db.add_audit(iid, "permissions", operator, f"应用模板「{tpl['name']}」v{tpl['version']}（批量任务 #{jid_holder[0]}）")
        return "success", f"已生效并核对通过（属主 {res['owner']}）"

    jid_holder = [None]

    def worker(jid, insts):
        jid_holder[0] = jid
        _pool(jid, insts, fn, 10)
        # 应用完顺带巡检，刷新合规状态
        ok_ids = [i["instance_id"] for i in insts if i["state"] == "running" and i.get("ssm") == "Online"]
        if ok_ids:
            try:
                inspect_service.inspect_many(ok_ids, on_result=store.save_inspection)
            except Exception:  # noqa: BLE001
                log.exception("应用模板后巡检失败")
        if init_shares:
            # 新服务器初始化：模板应用后立即挂载共享盘，不必等待后台巡检
            PENDING_SHARE_SYNC.update(ok_ids)

    n = len(instance_ids)
    return _start("apply_template", f"应用权限模板「{tpl['name']}」（{n} 台）",
                  {"template_id": tpl["id"], "template_name": tpl["name"], "version": tpl["version"]},
                  instance_ids, operator, worker)


# ---------------- 巡检 ----------------

def start_inspect(instance_ids, operator):
    def worker(jid, insts):
        targets = []
        for inst in insts:
            iid = inst["instance_id"]
            if inst["state"] != "running":
                store.update_item(jid, iid, "skipped", "实例未运行")
            elif inst.get("ssm") != "Online":
                store.update_item(jid, iid, "failed", "SSM 代理离线")
            else:
                targets.append(iid)
                store.update_item(jid, iid, "running")
        store.refresh_progress(jid)

        def on_result(iid, data):
            store.save_inspection(iid, data)
            if data.get("error"):
                store.update_item(jid, iid, "failed", data["error"])
            else:
                store.update_item(jid, iid, "success",
                                  f"DCV {data.get('dcv_service')}，会话属主 {data.get('session_owner')}，连接 {data.get('connections')}")
            store.refresh_progress(jid)
        if targets:
            inspect_service.inspect_many(targets, on_result=on_result)

    return _start("inspect", f"巡检（{len(instance_ids)} 台）", {}, instance_ids, operator, worker)


# ---------------- 新服务器自动应用模板 ----------------

def start_pending_template_watcher(interval_sec=60):
    """从快照创建时指定了模板的服务器，开机且 SSM 上线后自动应用该模板。

    同时会写入开机自动会话配置，避免旧快照创建的机器出现 "No sessions available"。
    """
    def loop():
        time.sleep(15)
        while True:
            try:
                for inst in aws_service.list_instances():
                    tid = inst.get("pending_template")
                    if not tid or inst["state"] != "running" or inst.get("ssm") != "Online" or inst.get("busy"):
                        continue
                    iid = inst["instance_id"]
                    if store.running_jobs_for([iid]):
                        continue
                    try:
                        if store.get_template(int(tid)):
                            jid = start_apply_template([iid], int(tid), "系统（新服务器初始化）", init_shares=True)
                            log.info("新服务器 %s 自动应用模板 %s，任务 #%s", iid, tid, jid)
                        else:
                            log.warning("新服务器 %s 指定的模板 %s 不存在，已忽略", iid, tid)
                    finally:
                        aws_service.set_mgmt_tags([iid], {"pending_template": ""})
            except Exception:  # noqa: BLE001
                log.exception("待应用模板检查失败")
            time.sleep(interval_sec)

    threading.Thread(target=loop, name="pending-template", daemon=True).start()


# ---------------- 共享盘同步 ----------------

def _sync_one(inst, operator, jid=None):
    """把一台服务器的共享盘同步到平台期望状态，返回 (状态, 说明)。"""
    import share_service
    if inst["state"] != "running":
        return "skipped", "未运行，开机后自动挂载"
    if inst.get("ssm") != "Online":
        return "failed", "SSM 代理离线"
    desired = share_service.desired_for(inst["instance_id"], store.list_shares())
    r = share_service.sync_host(inst["instance_id"], desired)
    if r.get("fatal"):
        return "failed", r["fatal"]
    parts = [("✓ " if x["ok"] else "✗ ") + f"{x['drive']}: {x['message']}" for x in r.get("shares", [])]
    if r.get("removed"):
        parts.append(f"已卸载 {len(r['removed'])} 个不再授权的共享盘")
    if r.get("installed"):
        parts.append("已安装 " + "、".join(r["installed"]))
    parts += r.get("errors", [])
    bad = [x for x in r.get("shares", []) if not x["ok"]] or r.get("errors")
    try:
        store.save_inspection(inst["instance_id"], inspect_service.inspect_many([inst["instance_id"]])[inst["instance_id"]])
    except Exception:  # noqa: BLE001
        log.exception("同步后巡检失败")
    return ("failed" if bad else "success"), "；".join(parts) or "无需挂载共享盘"


def start_share_sync(instance_ids, operator, title=None):
    def worker(jid, insts):
        _pool(jid, insts, lambda i: _sync_one(i, operator, jid), 10)
    return _start("share_sync", title or f"同步共享盘（{len(instance_ids)} 台）", {}, instance_ids, operator, worker)


def start_share_delete(share, instance_ids, operator):
    """共享盘记录已删除后调用：先在各主机卸载（此时 IAM 授权仍在，缓存可写回 S3），全部完成后撤销授权。"""
    import share_service

    def worker(jid, insts):
        _pool(jid, insts, lambda i: _sync_one(i, operator, jid), 10)
        share_service.delete_iam(share)
        log.info("共享盘 %s 的 IAM 授权已撤销", share["id"])

    if not instance_ids:
        share_service.delete_iam(share)
        return None
    return _start("share_sync", f"卸载并删除共享盘「{share['name']}」（{len(instance_ids)} 台）", {}, instance_ids, operator, worker)


def auto_remount(insts, insps, shares):
    """后台：发现共享盘缺失/参数过期/未授权残留时自动同步（避免与其他任务冲突）。"""
    import share_service
    need = []
    for inst in insts:
        if inst["state"] != "running" or inst.get("ssm") != "Online":
            continue
        _, drift, _ = share_service.evaluate(inst, insps.get(inst["instance_id"]), shares)
        if drift:
            need.append(inst["instance_id"])
    need = [i for i in need if i not in store.running_jobs_for(need)]
    if need:
        jid = start_share_sync(need, "系统（自动补挂）", f"自动补挂共享盘（{len(need)} 台）")
        log.info("自动补挂共享盘任务 #%s：%s", jid, need)


def ensure_gpu_guard(insts, insps):
    """后台：给尚未部署「开机显卡自检」的运行中主机自动部署（换机型后首次开机自动加载显卡驱动）。"""
    import gpu_guard
    need = [i["instance_id"] for i in insts if i["state"] == "running" and i.get("ssm") == "Online"
            and (insps.get(i["instance_id"]) or {}).get("gpu_guard") is False]
    need = [i for i in need if i not in store.running_jobs_for(need)]

    def one(iid):
        ok, msg = gpu_guard.install(iid)
        if ok:
            db.add_audit(iid, "host_agent", "系统", "部署开机显卡自检")
        else:
            log.warning("部署开机显卡自检失败 %s：%s", iid, msg)
    if need:
        with cf.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(one, need))
        log.info("已部署开机显卡自检：%d 台", len(need))


# ---------------- 后台定时巡检 ----------------

def start_background_inspection(interval_min):
    if interval_min <= 0:
        log.info("后台自动巡检已关闭")
        return

    def loop():
        time.sleep(20)
        while True:
            try:
                insts = aws_service.list_instances(use_cache=False)
                ids = [i["instance_id"] for i in insts if i["state"] == "running" and i.get("ssm") == "Online"]
                busy = store.running_jobs_for(ids)
                ids = [i for i in ids if i not in busy]
                if ids:
                    inspect_service.inspect_many(ids, on_result=store.save_inspection)
                    log.info("后台巡检完成：%d 台", len(ids))
                ensure_gpu_guard(aws_service.list_instances(use_cache=False), store.all_inspections())
                shares = store.list_shares()
                if shares or any("shares" in (v or {}) and v["shares"] for v in store.all_inspections().values()):
                    auto_remount(aws_service.list_instances(use_cache=False), store.all_inspections(), shares)
            except Exception:  # noqa: BLE001
                log.exception("后台巡检失败")
            time.sleep(interval_min * 60)

    threading.Thread(target=loop, name="auto-inspect", daemon=True).start()
    log.info("后台自动巡检已启动，间隔 %d 分钟", interval_min)


# ---------------- 跨可用区迁移 ----------------

def start_migrate(instance_ids, operator, target_zone="auto", instance_type=None, delete_old=True, keep_stopped=False):
    """把已停止的服务器迁移到其他可用区（镜像 → 新可用区重建 → 平台数据改指 → 删除原服务器）。

    每台约 10–30 分钟，主要耗时在制作镜像；并发 5 台。
    """
    import migrate_service
    import share_service

    def fn(jid, inst):
        iid = inst["instance_id"]
        if inst["state"] != "stopped":
            return "skipped", "请先关机再迁移"
        r = migrate_service.migrate_one(inst, target_zone, instance_type, delete_old, keep_stopped, operator,
                                        progress=lambda m: store.update_item(jid, iid, "running", m))
        db.add_audit(iid, "migrate", operator, f"批量任务 #{jid}：{r['message']}")
        db.add_audit(r["new_id"], "migrate", operator, f"由 {iid}（{inst['az']}）迁移而来，批量任务 #{jid}")
        if not keep_stopped and share_service.desired_for(r["new_id"], store.list_shares()):
            PENDING_SHARE_SYNC.add(r["new_id"])
        return ("success" if r["ok"] else "failed"), r["message"]

    def worker(jid, insts):
        _pool(jid, insts, lambda inst: fn(jid, inst), 5)
        import capacity_service
        capacity_service.invalidate()
        threading.Thread(target=_flush_pending_share_sync, daemon=True).start()

    n = len(instance_ids)
    return _start("migrate", f"迁移可用区（{n} 台）", {"target_zone": target_zone, "instance_type": instance_type,
                                                    "delete_old": delete_old, "keep_stopped": keep_stopped},
                  instance_ids, operator, worker)


# ---------------- 删除服务器 ----------------

def start_terminate(instance_ids, operator, backup=False):
    """删除服务器（终止实例）。backup=True 时先制作含全部磁盘的备份快照，完成后再删除。"""
    import terminate_service

    def fn(jid, inst):
        iid = inst["instance_id"]
        r = terminate_service.terminate_one(inst, backup, operator,
                                            progress=lambda m: store.update_item(jid, iid, "running", m))
        db.add_audit(iid, "terminate", operator, f"批量任务 #{jid}：删除服务器 {inst.get('name') or iid}（{inst.get('region')} {inst.get('instance_type')}）；{r['message']}")
        PENDING_SHARE_SYNC.discard(iid)
        return "success", r["message"]

    def worker(jid, insts):
        _pool(jid, insts, lambda inst: fn(jid, inst), 5 if backup else 20)

    n = len(instance_ids)
    return _start("terminate", f"删除服务器（{n} 台）", {"backup": backup}, instance_ids, operator, worker)
