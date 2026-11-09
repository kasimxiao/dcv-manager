"""DCV 企业管理平台 - FastAPI 后端入口。

角色（Cognito 用户组）：
  desktop  桌面用户：只能查看分配给自己的服务器，并对其开机、关机、重启
  viewer   只读：服务器、任务、历史、审计
  operator 运维：开关机、巡检、应用模板/自定义权限、标签、快照创建、重置 DCV 密码
  admin    管理员：以上全部 + 用户、权限模板、定时任务、从快照创建服务器、删除快照
"""
import os
import json
import time
import secrets
import logging
import datetime as dt
from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel

import config
import db
import store
import aws_service
import dcv_service
import eb_scheduler
import history_service
import inspect_service
import jobs
from dcv_features import FEATURE_GROUPS, DEFAULT_SPEC, ALL_FEATURE_KEYS, RULE_DESC

if config.cognito_enabled():
    import cognito_auth
else:
    cognito_auth = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("dcv.app")

app = FastAPI(title="DCV 企业管理平台", version="2.0")
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")

ROLE_RANK = {"desktop": 0, "viewer": 1, "operator": 2, "admin": 3}
ROLE_ZH = {"desktop": "桌面用户", "viewer": "只读", "operator": "运维", "admin": "管理员"}

# ---------------- 鉴权 ----------------
_tokens: Dict[str, float] = {}
_TOKEN_TTL = 12 * 3600


def _auth(authorization: Optional[str] = Header(None), x_auth_token: Optional[str] = Header(None)) -> dict:
    # 经 CloudFront 访问时 Authorization 头可能不转发到源站，前端同时在 X-Auth-Token 中携带令牌
    if authorization and authorization.startswith("Bearer "):
        tok = authorization[7:]
    elif x_auth_token:
        tok = x_auth_token
    else:
        raise HTTPException(status_code=401, detail="未登录")
    if cognito_auth:
        try:
            claims = cognito_auth.verify(tok)
        except Exception as e:  # noqa: BLE001
            log.info("令牌校验失败: %s: %s", type(e).__name__, e)
            raise HTTPException(status_code=401, detail="令牌无效或已过期")
        return {"username": claims.get("cognito:username") or "unknown", "role": cognito_auth.role_from_claims(claims)}
    exp = _tokens.get(tok)
    if not exp or time.time() > exp:
        _tokens.pop(tok, None)
        raise HTTPException(status_code=401, detail="令牌无效或已过期")
    return {"username": "admin", "role": "admin"}


def role(min_role: str):
    def dep(user=Depends(_auth)):
        if ROLE_RANK[user["role"]] < ROLE_RANK[min_role]:
            raise HTTPException(status_code=403, detail=f"权限不足：该操作需要「{ROLE_ZH[min_role]}」及以上角色")
        return user
    return dep


DESKTOP, VIEWER, OPERATOR, ADMIN = role("desktop"), role("viewer"), role("operator"), role("admin")


def _fail(prefix, e, code=500):
    if isinstance(e, HTTPException):
        raise e
    if isinstance(e, (ValueError, jobs.BusyError)):
        raise HTTPException(status_code=409 if isinstance(e, jobs.BusyError) else 400, detail=str(e))
    log.exception(prefix)
    raise HTTPException(status_code=code, detail=f"{prefix}: {e}")


def _audit(target, action, user, detail=""):
    db.add_audit(target or "-", action, user["username"], detail)


# ---------------- 请求模型 ----------------
class LoginReq(BaseModel):
    username: Optional[str] = None
    password: str


class NewPasswordReq(BaseModel):
    username: str
    session: str
    new_password: str


class UserReq(BaseModel):
    username: str
    password: str
    email: Optional[str] = ""
    role: str = "viewer"


class UserPasswordReq(BaseModel):
    password: str


class UserEnableReq(BaseModel):
    enabled: bool


class UserRoleReq(BaseModel):
    role: str


class DcvPasswordReq(BaseModel):
    password: str
    username: Optional[str] = None


class MyPasswordReq(BaseModel):
    old_password: str
    new_password: str


class PowerReq(BaseModel):
    action: str


class PermReq(BaseModel):
    spec: Dict[str, str]
    owner: Optional[str] = None


class BatchReq(BaseModel):
    instance_ids: List[str]


class BatchPowerReq(BatchReq):
    action: str
    # None：按各服务器的备选机型设置；[]：本次不换机型
    fallback_types: Optional[List[str]] = None


class FallbackReq(BatchReq):
    # None 恢复默认顺序；[] 关闭自动换机型
    types: Optional[List[str]] = None


class MigrateReq(BatchReq):
    target_zone: str = "auto"
    instance_type: Optional[str] = None
    delete_old: bool = True
    keep_stopped: bool = False


class ChangeTypeReq(BaseModel):
    instance_type: str


class ProbeReq(BaseModel):
    pairs: List[List[str]]      # [[az, type], ...]
    count: int = 1


class BatchTemplateReq(BatchReq):
    template_id: int
    owner: Optional[str] = None


class TagsReq(BatchReq):
    group: Optional[str] = None
    assignee: Optional[str] = None
    department: Optional[str] = None
    note: Optional[str] = None


class RenameReq(BaseModel):
    name: str


class TemplateReq(BaseModel):
    name: str
    description: Optional[str] = ""
    level: Optional[str] = "中"
    spec: Dict[str, str]


class ScheduleReq(BaseModel):
    instance_ids: list
    action: str
    cron: str
    timezone: Optional[str] = None
    note: Optional[str] = ""
    enabled: bool = True


class SchedulePatch(BaseModel):
    instance_ids: Optional[list] = None
    action: Optional[str] = None
    cron: Optional[str] = None
    timezone: Optional[str] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None


class SnapshotReq(BaseModel):
    name: str
    description: Optional[str] = ""
    no_reboot: bool = True


class LaunchReq(BaseModel):
    instance_type: str
    name: str
    count: int = 1
    group: Optional[str] = ""
    assignee: Optional[str] = ""
    department: Optional[str] = ""
    template_id: Optional[int] = None
    share_ids: List[int] = []
    zone: str = "auto"          # auto 自动选择容量最好的可用区 / spread 多可用区均衡 / 具体可用区名


# ---------------- 生命周期 ----------------
@app.on_event("startup")
def _startup():
    db.init_db()
    store.init()
    store.mark_stale_jobs()
    try:
        import capacity_service
        capacity_service.cleanup_probes()
    except Exception:  # noqa: BLE001
        log.exception("清理残留容量探测失败")
    try:
        import pricing_service
        pricing_service.warm()
    except Exception:  # noqa: BLE001
        log.exception("预热价格失败")
    jobs.start_background_inspection(config.INSPECT_INTERVAL_MIN)
    jobs.start_pending_template_watcher()
    if not cognito_auth and config.ADMIN_PASSWORD == "changeme":
        log.warning("⚠️  正在使用默认管理口令 'changeme'，请通过环境变量 DCV_ADMIN_PASSWORD 修改！")


# ---------------- 认证 ----------------
@app.post("/api/login")
def login(req: LoginReq):
    if cognito_auth:
        if not req.username:
            raise HTTPException(status_code=400, detail="请输入用户名")
        try:
            res = cognito_auth.login(req.username, req.password)
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=401, detail="用户名或口令错误")
        if res.get("challenge"):
            return res  # 首次登录：需要设置新密码
        db.add_audit("-", "login", req.username, "登录平台")
        return res
    if not secrets.compare_digest(req.password, config.ADMIN_PASSWORD):
        raise HTTPException(status_code=401, detail="口令错误")
    tok = secrets.token_urlsafe(32)
    _tokens[tok] = time.time() + _TOKEN_TTL
    return {"token": tok, "username": "admin", "role": "admin"}


@app.post("/api/login/new-password")
def login_new_password(req: NewPasswordReq):
    """首次登录（临时密码）后设置新密码并完成登录。"""
    if not cognito_auth:
        raise HTTPException(status_code=400, detail="未启用 Cognito")
    try:
        res = cognito_auth.complete_new_password(req.username, req.session, req.new_password)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "InvalidPasswordException" in msg or "Password does not conform" in msg:
            raise HTTPException(status_code=400, detail="新密码不符合要求：至少 12 位，包含大小写字母、数字和符号")
        raise HTTPException(status_code=400, detail="设置新密码失败，请重新登录后再试")
    db.add_audit("-", "login", req.username, "首次登录并设置新密码")
    return res


@app.get("/api/me")
def me(user=Depends(DESKTOP)):
    return user


@app.post("/api/me/password")
def change_my_password(req: MyPasswordReq, user=Depends(DESKTOP)):
    if not cognito_auth:
        raise HTTPException(status_code=400, detail="未启用 Cognito，请通过环境变量修改管理口令")
    try:
        cognito_auth.change_own_password(user["username"], req.old_password, req.new_password)
    except Exception as e:  # noqa: BLE001
        _fail("修改失败", e)
    _audit("-", "user", user, "修改了自己的登录密码")
    return {"ok": True}


# ---------------- 元数据 ----------------
@app.get("/api/features")
def features(_=Depends(VIEWER)):
    return {"groups": FEATURE_GROUPS, "default_spec": DEFAULT_SPEC, "rule_desc": RULE_DESC}


@app.get("/api/config")
def get_cfg(_=Depends(VIEWER)):
    return {
        "region": config.HOME_REGION,
        "regions": config.REGIONS,
        "region_errors": aws_service.list_errors(),
        "tag": f"{config.DCV_TAG_KEY}={config.DCV_TAG_VALUE}",
        "dcv_port": config.DCV_PORT,
        "scheduler_tz": config.SCHEDULER_TZ,
        "cognito": config.cognito_enabled(),
        "inspect_interval_min": config.INSPECT_INTERVAL_MIN,
        "idle_hours": config.IDLE_HOURS,
        "max_launch_count": config.MAX_LAUNCH_COUNT,
        "volume_gb": config.LAUNCH_VOLUME_GB,
        "allowed_types": config.ALLOWED_INSTANCE_TYPES,
        "candidate_types": config.CANDIDATE_TYPES,
        "default_fallback": config.DEFAULT_FALLBACK,
        "managed_start": all(eb_scheduler.power_function_arn(r) for r in config.REGIONS),
        "managed_start_regions": {r: bool(eb_scheduler.power_function_arn(r)) for r in config.REGIONS},
        "setup_saved": bool(config.SETTINGS),
    }


# ---------------- 服务器列表（聚合巡检、模板、合规与健康） ----------------
_INSP_FIELDS = ["dcv_service", "session_owner", "connections", "cpu", "mem_total_mb", "mem_free_mb",
                "gpu_util", "gpu_mem_used", "gpu_mem_total", "disk_total_gb", "disk_free_gb",
                "owner_is_admin", "dcv_version", "license", "boot_time", "last_disconnect", "error"]


def _iso_ts(s):
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


_capf = {"ts": 0, "data": {}}


def _cap_failures():
    """最近 2 小时开机因容量不足失败的实例（缓存 60 秒，避免每次列表都查 CloudTrail）。"""
    if time.time() - _capf["ts"] > 60:
        try:
            import capacity_service
            _capf["data"] = capacity_service.instance_failures(120)
        except Exception:  # noqa: BLE001
            log.exception("读取开机失败记录失败")
        _capf["ts"] = time.time()
    return _capf["data"]


def _enriched():
    import share_service
    insts = aws_service.list_instances()
    insps = store.all_inspections()
    binds = store.all_bindings()
    specs = store.all_specs()
    shares = store.list_shares()
    busy = store.running_jobs_for([i["instance_id"] for i in insts])
    now = time.time()
    cap_fail = _cap_failures()
    out = []
    for inst in insts:
        iid = inst["instance_id"]
        insp = insps.get(iid)
        stale = False
        if insp:
            boot = _iso_ts(inst.get("running_since")) if inst.get("running_since") else None
            # 巡检早于本次开机，或机器已关机：旧数据不再代表当前状态
            if inst["state"] != "running" or (boot and insp["checked_at"] < boot):
                stale = True
        spec, owner = specs.get(iid, (None, None))
        b = binds.get(iid)
        if b and b.get("template_id"):
            # 以内容而非版本号比较：模板改了又改回时不应提示重新应用
            tspec = b.get("template_spec") or {}
            b["outdated"] = any((spec or {}).get(k, "allow") != tspec.get(k, "allow") for k in ALL_FEATURE_KEYS)
        ev = inspect_service.evaluate(inst, None if stale else insp, spec, owner or config.DCV_DEFAULT_OWNER, b)
        idle = bool(ev["idle_since"] and now - ev["idle_since"] > config.IDLE_HOURS * 3600)
        tpl = None
        if b and b.get("template_id"):
            tpl = {"id": b["template_id"], "name": b.get("template_name"), "level": b.get("template_level"),
                   "version": b.get("template_version"), "current_version": b.get("current_version"),
                   "outdated": b["outdated"],
                   "applied_at": b.get("applied_at"), "applied_by": b.get("applied_by")}
        restricted = [k for k in ALL_FEATURE_KEYS if spec and spec.get(k, "allow") != "allow"]
        share_rows, _, share_alerts = share_service.evaluate(inst, None if stale else insp, shares)
        for lv, msg in share_alerts:
            ev["alerts"].append({"level": lv, "message": msg})
        if share_alerts and ev["health"] == "ok":
            ev["health"] = "warn"
        cf_ts = cap_fail.get(inst["instance_id"])
        if cf_ts and inst["state"] == "stopped":
            ev["alerts"].insert(0, {"level": "critical", "message": f"开机失败：{inst['az']} 的 {inst['instance_type']} 容量不足"
                                    f"（{int((now - cf_ts) / 60)} 分钟前）。可改用其他机型开机，或在「容量检测」查看各可用区情况"})
            ev["health"] = "critical"
            ev["start_failed"] = True
        out.append({
            **inst,
            "template": tpl,
            "perm_mode": "template" if tpl else ("custom" if spec else "none"),
            "restricted": restricted,
            "owner": owner,
            "inspection": ({k: insp.get(k) for k in _INSP_FIELDS} | {"checked_at": insp["checked_at"], "stale": stale})
            if insp else None,
            **ev,
            "shares": share_rows,
            "idle": idle,
            "busy": iid in busy,
        })
    return out


@app.get("/api/instances")
def instances(_=Depends(VIEWER)):
    try:
        items = _enriched()
    except Exception as e:  # noqa: BLE001
        _fail("查询服务器失败", e)
    summary = {
        "total": len(items),
        "running": sum(i["state"] == "running" for i in items),
        "stopped": sum(i["state"] == "stopped" for i in items),
        "transition": sum(i["state"] in ("pending", "stopping", "shutting-down") for i in items),
        "connections": sum((i["inspection"] or {}).get("connections") or 0 for i in items
                           if i["inspection"] and not i["inspection"]["stale"]),
        "critical": sum(i["health"] == "critical" for i in items),
        "warn": sum(i["health"] == "warn" for i in items),
        "drift": sum(i["compliance"] == "drift" for i in items),
        "unmanaged": sum(i["compliance"] == "unmanaged" for i in items),
        "outdated": sum(bool(i["template"] and i["template"]["outdated"]) for i in items),
        "idle": sum(i["idle"] for i in items),
        "start_failed": sum(bool(i.get("start_failed")) for i in items),
        "groups": sorted({i["group"] for i in items if i["group"]}),
        "departments": sorted({i["department"] for i in items if i["department"]}),
        "regions": {r: {"total": sum(1 for i in items if i.get("region") == r),
                        "running": sum(1 for i in items if i.get("region") == r and i["state"] == "running")} for r in config.REGIONS},
    }
    return {"instances": items, "summary": summary, "generated_at": time.time(), "region_errors": aws_service.list_errors()}


@app.post("/api/instances/refresh")
def refresh(_=Depends(VIEWER)):
    aws_service.invalidate_cache()
    return {"ok": True}


@app.post("/api/instances/tags")
def set_tags(req: TagsReq, user=Depends(OPERATOR)):
    vals = {k: getattr(req, k) for k in ("group", "assignee", "department", "note") if getattr(req, k) is not None}
    if not vals:
        raise HTTPException(status_code=400, detail="没有要修改的字段")
    try:
        aws_service.set_mgmt_tags(req.instance_ids, vals)
    except Exception as e:  # noqa: BLE001
        _fail("设置标签失败", e)
    zh = {"group": "分组", "assignee": "使用人", "department": "部门", "note": "备注"}
    desc = "，".join(f"{zh[k]}={v or '（清空）'}" for k, v in vals.items())
    for iid in req.instance_ids:
        _audit(iid, "tags", user, desc)
    return {"ok": True, "count": len(req.instance_ids)}


@app.post("/api/instances/{instance_id}/rename")
def rename(instance_id: str, req: RenameReq, user=Depends(OPERATOR)):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="名称不能为空")
    try:
        aws_service.rename_instance(instance_id, req.name)
    except Exception as e:  # noqa: BLE001
        _fail("重命名失败", e)
    _audit(instance_id, "rename", user, f"重命名为 {req.name.strip()}")
    return {"ok": True}


@app.post("/api/instances/{instance_id}/power")
def power(instance_id: str, req: PowerReq, user=Depends(OPERATOR)):
    try:
        jid = jobs.start_power([instance_id], req.action, user["username"])
    except Exception as e:  # noqa: BLE001
        _fail("电源操作失败", e)
    return {"ok": True, "job_id": jid}


# ---------------- 桌面用户自助（只能操作分配给自己的服务器） ----------------
_MY_FIELDS = ["instance_id", "name", "state", "instance_type", "gpu", "region", "az", "public_ip",
              "dcv_url", "running_since", "fallback_from"]
_MY_ACTIONS = {"start", "stop", "reboot"}


def _my_instances(username, use_cache=True):
    return [i for i in aws_service.list_instances(use_cache=use_cache) if i.get("portal_user") == username]


@app.get("/api/my/instances")
def my_instances(user=Depends(DESKTOP)):
    try:
        mine = _my_instances(user["username"])
        busy = store.running_jobs_for([i["instance_id"] for i in mine])
    except Exception as e:  # noqa: BLE001
        _fail("查询服务器失败", e)
    return {"instances": [{k: i.get(k) for k in _MY_FIELDS} | {"busy": i["instance_id"] in busy} for i in mine],
            "cognito": bool(cognito_auth), "generated_at": time.time()}


@app.post("/api/my/instances/{instance_id}/power")
def my_power(instance_id: str, req: PowerReq, user=Depends(DESKTOP)):
    if req.action not in _MY_ACTIONS:
        raise HTTPException(status_code=400, detail="不支持的操作")
    # 授权以 EC2 上的实时标签为准，避免缓存中刚被收回的分配仍然有效
    if not any(i["instance_id"] == instance_id for i in _my_instances(user["username"], use_cache=False)):
        raise HTTPException(status_code=403, detail="这台服务器没有分配给你")
    try:
        jid = jobs.start_power([instance_id], req.action, user["username"])
    except Exception as e:  # noqa: BLE001
        _fail("电源操作失败", e)
    return {"ok": True, "job_id": jid}


@app.get("/api/instances/{instance_id}/history")
def history(instance_id: str, days: int = 30, _=Depends(VIEWER)):
    try:
        return history_service.get_history(instance_id, days)
    except Exception as e:  # noqa: BLE001
        _fail("读取运行历史失败", e)


@app.post("/api/instances/{instance_id}/dcv/password")
def reset_dcv_password(instance_id: str, req: DcvPasswordReq, user=Depends(OPERATOR)):
    if not aws_service.is_ssm_online(instance_id):
        raise HTTPException(status_code=409, detail="实例未运行或 SSM 未上线，无法重置密码（请先开机）")
    try:
        res = dcv_service.reset_password(instance_id, req.password, req.username)
    except Exception as e:  # noqa: BLE001
        _fail("重置失败", e)
    if not res["ok"]:
        raise HTTPException(status_code=500, detail=f"重置失败: {res['error']}")
    _audit(instance_id, "reset_password", user, f"用户 {res['username']}")
    return {"ok": True, "username": res["username"]}


@app.get("/api/instances/{instance_id}/dcv/status")
def dcv_status(instance_id: str, _=Depends(VIEWER)):
    if not aws_service.is_ssm_online(instance_id):
        return {"online": False, "message": "实例未通过 SSM 上线（可能已关机或未装 SSM Agent）"}
    return {"online": True, **dcv_service.get_live_status(instance_id)}


@app.get("/api/instances/{instance_id}/dcv/permissions")
def get_perms(instance_id: str, _=Depends(VIEWER)):
    spec = db.get_permission_spec(instance_id) or dict(DEFAULT_SPEC)
    meta = db.get_meta(instance_id) or {}
    return {"spec": spec, "owner": meta.get("owner")}


@app.post("/api/instances/{instance_id}/dcv/permissions")
def set_perms(instance_id: str, req: PermReq, user=Depends(OPERATOR)):
    if store.running_jobs_for([instance_id]):
        raise HTTPException(status_code=409, detail="该服务器有未完成的任务，请稍后再试")
    if not aws_service.is_ssm_online(instance_id):
        raise HTTPException(status_code=409, detail="实例未通过 SSM 上线，无法下发权限（请先开机）")
    try:
        result = dcv_service.apply_permissions(instance_id, req.spec, req.owner)
    except Exception as e:  # noqa: BLE001
        _fail("下发权限失败", e)
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=f"下发失败: {result.get('error') or result.get('status')}")
    store.unbind_template(instance_id, user["username"])
    denied = [k for k, v in req.spec.items() if v != "allow"]
    _audit(instance_id, "permissions", user, "自定义权限，受限：" + ("、".join(denied) if denied else "无"))
    try:
        store.save_inspection(instance_id, inspect_service.inspect_many([instance_id])[instance_id])
    except Exception:  # noqa: BLE001
        log.exception("下发后巡检失败")
    return result


# ---------------- 批量任务 ----------------
@app.post("/api/jobs/power")
def job_power(req: BatchPowerReq, user=Depends(OPERATOR)):
    try:
        return {"job_id": jobs.start_power(req.instance_ids, req.action, user["username"], req.fallback_types)}
    except Exception as e:  # noqa: BLE001
        _fail("创建任务失败", e)


@app.post("/api/jobs/migrate")
def job_migrate(req: MigrateReq, user=Depends(ADMIN)):
    if req.instance_type and req.instance_type not in config.ALLOWED_INSTANCE_TYPES:
        raise HTTPException(status_code=400, detail=f"不支持的机型：{req.instance_type}")
    insts = {i["instance_id"]: i for i in aws_service.list_instances(use_cache=False)}
    running = [insts[i]["name"] or i for i in req.instance_ids if i in insts and insts[i]["state"] != "stopped"]
    if running:
        raise HTTPException(status_code=400, detail=f"迁移前请先关机：{'、'.join(running)}")
    try:
        return {"job_id": jobs.start_migrate(req.instance_ids, user["username"], req.target_zone, req.instance_type,
                                             req.delete_old, req.keep_stopped)}
    except Exception as e:  # noqa: BLE001
        _fail("创建迁移任务失败", e)


class TerminateReq(BatchReq):
    backup: bool = False
    force_connected: bool = False   # 有用户正在连接时仍然删除


@app.post("/api/jobs/terminate")
def job_terminate(req: TerminateReq, user=Depends(ADMIN)):
    """删除服务器（终止实例，不可恢复）。正在连接的服务器默认拒绝，需显式确认。"""
    if not req.instance_ids:
        raise HTTPException(status_code=400, detail="请至少选择一台服务器")
    insts = {i["instance_id"]: i for i in aws_service.list_instances(use_cache=False)}
    insps = store.all_inspections()
    missing = [i for i in req.instance_ids if i not in insts]
    if missing:
        raise HTTPException(status_code=400, detail=f"以下服务器不存在或未纳管：{'、'.join(missing)}")
    connected = [insts[i]["name"] or i for i in req.instance_ids
                 if insts[i]["state"] == "running" and ((insps.get(i) or {}).get("connections") or 0) > 0]
    if connected and not req.force_connected:
        raise HTTPException(status_code=409, detail=f"以下服务器有用户正在连接：{'、'.join(connected)}。确认要中断并删除时请勾选「仍然删除」")
    try:
        jid = jobs.start_terminate(req.instance_ids, user["username"], req.backup)
    except Exception as e:  # noqa: BLE001
        _fail("创建删除任务失败", e)
    _audit("-", "terminate", user, f"删除服务器 {len(req.instance_ids)} 台：{'、'.join(insts[i]['name'] or i for i in req.instance_ids)}"
           + ("（先备份）" if req.backup else "（不备份）") + (f"；其中 {len(connected)} 台有用户连接" if connected else ""))
    return {"job_id": jid}


@app.post("/api/instances/fallback")
def set_fallback(req: FallbackReq, user=Depends(OPERATOR)):
    try:
        aws_service.set_fallback_types(req.instance_ids, req.types)
    except Exception as e:  # noqa: BLE001
        _fail("设置备选机型失败", e, 400)
    desc = "恢复默认顺序" if req.types is None else ("关闭自动换机型" if not req.types else " → ".join(req.types))
    for i in req.instance_ids:
        _audit(i, "change_type", user, f"备选机型：{desc}")
    return {"ok": True, "count": len(req.instance_ids)}


@app.post("/api/jobs/apply-template")
def job_apply(req: BatchTemplateReq, user=Depends(OPERATOR)):
    try:
        return {"job_id": jobs.start_apply_template(req.instance_ids, req.template_id, user["username"], req.owner)}
    except Exception as e:  # noqa: BLE001
        _fail("创建任务失败", e)


@app.post("/api/jobs/inspect")
def job_inspect(req: BatchReq, user=Depends(OPERATOR)):
    try:
        return {"job_id": jobs.start_inspect(req.instance_ids, user["username"])}
    except Exception as e:  # noqa: BLE001
        _fail("创建任务失败", e)


@app.get("/api/jobs")
def list_jobs(limit: int = 50, _=Depends(VIEWER)):
    return {"jobs": store.list_jobs(min(max(limit, 1), 200))}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: int, _=Depends(VIEWER)):
    j = store.get_job(job_id)
    if not j:
        raise HTTPException(status_code=404, detail="任务不存在")
    return j


# ---------------- 权限模板 ----------------
def _clean_spec(spec):
    bad = [k for k, v in spec.items() if k not in ALL_FEATURE_KEYS or v not in ("allow", "disallow", "deny")]
    if bad:
        raise HTTPException(status_code=400, detail=f"非法的权限项：{', '.join(bad)}")
    return {k: spec.get(k, "allow") for k in ALL_FEATURE_KEYS}


@app.get("/api/templates")
def list_templates(_=Depends(VIEWER)):
    return {"templates": store.list_templates()}


@app.post("/api/templates")
def create_template(req: TemplateReq, user=Depends(ADMIN)):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="模板名称不能为空")
    try:
        tid = store.create_template(req.name.strip(), req.description, req.level, _clean_spec(req.spec), user["username"])
    except Exception as e:  # noqa: BLE001
        _fail("创建模板失败", e, 400)
    _audit("-", "template", user, f"创建模板「{req.name.strip()}」")
    return store.get_template(tid)


@app.put("/api/templates/{tid}")
def update_template(tid: int, req: TemplateReq, user=Depends(ADMIN)):
    old = store.get_template(tid)
    if not old:
        raise HTTPException(status_code=404, detail="模板不存在")
    store.update_template(tid, req.name.strip() or old["name"], req.description, req.level, _clean_spec(req.spec), user["username"])
    new = store.get_template(tid)
    changed = [k for k in ALL_FEATURE_KEYS if old["spec"].get(k) != new["spec"].get(k)]
    _audit("-", "template", user, f"修改模板「{new['name']}」至 v{new['version']}，变更项：{'、'.join(changed) or '仅描述'}")
    return new


@app.delete("/api/templates/{tid}")
def delete_template(tid: int, user=Depends(ADMIN)):
    t = store.get_template(tid)
    if not t:
        raise HTTPException(status_code=404, detail="模板不存在")
    if t["builtin"]:
        raise HTTPException(status_code=400, detail="内置模板不能删除，可复制后修改")
    store.delete_template(tid)
    _audit("-", "template", user, f"删除模板「{t['name']}」（{t['instance_count']} 台服务器转为自定义权限）")
    return {"ok": True}


# ---------------- 定时任务（EventBridge Scheduler） ----------------
@app.get("/api/schedules")
def list_sched(instance_id: Optional[str] = None, _=Depends(VIEWER)):
    try:
        items = eb_scheduler.list_all()
    except Exception as e:  # noqa: BLE001
        _fail("读取定时任务失败", e)
    if instance_id:
        items = [s for s in items if instance_id in s["instance_ids"]]
    return {"schedules": items}


_ACT_ZH = {"start": "开机", "stop": "关机", "reboot": "重启"}


@app.post("/api/schedules")
def create_sched(req: ScheduleReq, user=Depends(ADMIN)):
    if req.action not in _ACT_ZH:
        raise HTTPException(status_code=400, detail="非法操作")
    if not req.instance_ids:
        raise HTTPException(status_code=400, detail="请至少选择一台服务器")
    try:
        made = eb_scheduler.create_many(req.action, req.instance_ids, req.cron,
                                        req.timezone or config.SCHEDULER_TZ, req.note or "", req.enabled)
    except Exception as e:  # noqa: BLE001
        _fail("创建失败", e, 400)
    for s in made:
        _audit("-", "schedule", user, f"创建定时{_ACT_ZH[req.action]} cron({s['cron']})，{s['region']} {len(s['instance_ids'])} 台 {req.note or ''}")
    return {**made[0], "created": made,
            "message": f"所选服务器分布在 {len(made)} 个区域，已按区域创建 {len(made)} 个定时任务" if len(made) > 1 else ""}


@app.put("/api/schedules/{name}")
def update_sched(name: str, req: SchedulePatch, user=Depends(ADMIN)):
    try:
        s = eb_scheduler.update(name, action=req.action, instance_ids=req.instance_ids, cron=req.cron,
                                timezone=req.timezone, note=req.note, enabled=req.enabled)
    except Exception as e:  # noqa: BLE001
        _fail("更新失败", e, 400)
    _audit("-", "schedule", user, f"修改定时任务 {name}（{'启用' if s['enabled'] else '禁用'}，cron({s['cron']})，{len(s['instance_ids'])} 台）")
    return s


@app.delete("/api/schedules/{name}")
def delete_sched(name: str, user=Depends(ADMIN)):
    try:
        eb_scheduler.delete(name)
    except Exception as e:  # noqa: BLE001
        _fail("删除失败", e, 400)
    _audit("-", "schedule", user, f"删除定时任务 {name}")
    return {"ok": True}


# ---------------- 容量检测 ----------------
@app.get("/api/capacity")
def capacity(refresh: bool = False, region: str = "", _=Depends(VIEWER)):
    import capacity_service
    region = region or config.HOME_REGION
    if region not in config.REGIONS:
        raise HTTPException(status_code=400, detail=f"{region} 不是平台管理的区域")
    try:
        return capacity_service.overview(use_cache=not refresh, region=region)
    except Exception as e:  # noqa: BLE001
        _fail("容量检测失败", e)


@app.post("/api/capacity/probe")
def capacity_probe(req: ProbeReq, user=Depends(OPERATOR)):
    import capacity_service
    if not 1 <= len(req.pairs) <= 12:
        raise HTTPException(status_code=400, detail="每次实测 1–12 个组合")
    if not 1 <= req.count <= 20:
        raise HTTPException(status_code=400, detail="实测台数需在 1–20 之间")
    regs = {config.region_of_az(p[0]) for p in req.pairs if p}
    if not regs <= set(config.REGIONS):
        raise HTTPException(status_code=400, detail="包含非管理区域的可用区")
    valid = {(c["az"], c["type"]) for r in regs for c in capacity_service.overview(region=r)["cells"] if c["offered"]}
    pairs = [tuple(p) for p in req.pairs if tuple(p) in valid]
    if not pairs:
        raise HTTPException(status_code=400, detail="所选组合均不提供该机型")
    try:
        res = capacity_service.probe_matrix(pairs, req.count)
    except Exception as e:  # noqa: BLE001
        _fail("实测失败", e)
    capacity_service.invalidate()
    _audit("-", "capacity", user, f"容量实测（{req.count} 台）：" + "；".join(
        f"{r['az']} {r['type']} {'可用' if r['ok'] else r['error']}" for r in res))
    return {"results": res}


@app.get("/api/instances/{instance_id}/capacity")
def instance_capacity(instance_id: str, _=Depends(VIEWER)):
    import capacity_service
    inst = aws_service.get_instance(instance_id)
    if not inst:
        raise HTTPException(status_code=404, detail="服务器不存在")
    return capacity_service.alternatives(inst)


@app.post("/api/instances/{instance_id}/type")
def change_type(instance_id: str, req: ChangeTypeReq, user=Depends(OPERATOR)):
    if store.running_jobs_for([instance_id]):
        raise HTTPException(status_code=409, detail="该服务器有未完成的任务，请稍后再试")
    try:
        old = aws_service.change_instance_type(instance_id, req.instance_type)
    except Exception as e:  # noqa: BLE001
        _fail("修改机型失败", e, 400)
    _audit(instance_id, "change_type", user, f"机型 {old} → {req.instance_type}")
    return {"ok": True, "old": old}


# ---------------- 快照 (AMI) ----------------
@app.get("/api/images")
def list_images(_=Depends(VIEWER)):
    try:
        return {"images": aws_service.list_images(), "allowed_types": aws_service.allowed_types_with_specs()}
    except Exception as e:  # noqa: BLE001
        _fail("读取快照失败", e)


@app.post("/api/instances/{instance_id}/snapshot")
def create_snapshot(instance_id: str, req: SnapshotReq, user=Depends(OPERATOR)):
    try:
        image_id = aws_service.create_image(instance_id, req.name, req.description or "")
    except Exception as e:  # noqa: BLE001
        _fail("创建快照失败", e)
    _audit(instance_id, "snapshot", user, f"{req.name}（{image_id}）")
    return {"ok": True, "image_id": image_id}


@app.post("/api/images/{image_id}/launch")
def launch_image(image_id: str, req: LaunchReq, user=Depends(ADMIN)):
    if not 1 <= req.count <= config.MAX_LAUNCH_COUNT:
        raise HTTPException(status_code=400, detail=f"数量需在 1–{config.MAX_LAUNCH_COUNT} 之间")
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="名称不能为空")
    tpl = store.get_template(req.template_id) if req.template_id else None
    if req.template_id and not tpl:
        raise HTTPException(status_code=400, detail="模板不存在")
    import capacity_service
    region = aws_service.image_region(image_id)
    subs = capacity_service.launch_subnets(region)
    if not subs:
        raise HTTPException(status_code=400, detail=f"{region} 尚未完成网络设置，请先在「系统设置」中配置该区域")
    try:
        ranked = [az for az, st in capacity_service.best_zones(req.instance_type, region) if st != "unavailable"] \
            or [az for az, _ in capacity_service.best_zones(req.instance_type, region)]
    except Exception:  # noqa: BLE001
        log.exception("容量排序失败，使用默认子网")
        ranked = []
    if req.zone not in ("auto", "spread"):
        if req.zone not in subs:
            raise HTTPException(status_code=400, detail=f"可用区 {req.zone} 没有可用于创建服务器的公有子网")
        order = [req.zone]
    else:
        order = [az for az in ranked if az in subs] or list(subs)[:1]
    if req.zone == "spread" and len(order) > 1:
        plan = [[subs[order[(n + k) % len(order)]] for k in range(len(order))] for n in range(req.count)]
    else:
        plan = [[subs[a] for a in order]] * req.count  # 首选容量最好的，失败自动换下一个可用区
    try:
        ids, placed, errs = aws_service.launch_from_image(
            image_id, req.instance_type, req.name.strip(),
            {"group": req.group, "assignee": req.assignee, "department": req.department,
             "pending_template": str(tpl["id"]) if tpl else ""}, req.count, plan, region=region)
    except Exception as e:  # noqa: BLE001
        if aws_service.is_capacity_error(e):
            capacity_service.invalidate()
            raise HTTPException(status_code=409, detail=f"创建失败：{'、'.join(order)} 均暂无 {req.instance_type} 容量。请换机型或稍后重试")
        _fail("创建失败", e, 400)
    capacity_service.invalidate()
    share_msgs = []
    if req.share_ids:
        import share_service
        for s in store.list_shares():
            if s["id"] in req.share_ids and s["scope"] == "selected":
                try:
                    arns = share_service.sync_iam(s, sorted(set(s["target_ids"]) | set(ids)))
                    store.add_share_targets(s["id"], ids, user["username"])
                    store.update_share(s["id"], user["username"], policy_arn=json.dumps(arns))
                    share_msgs.append(f"{s['drive']}:{s['name']}")
                except Exception as e:  # noqa: BLE001
                    log.exception("新服务器授权共享盘失败")
                    share_msgs.append(f"{s['name']}（授权失败：{e}）")
    for iid in ids:
        _audit(iid, "launch", user, f"来自快照 {image_id}（{region}），机型 {req.instance_type}，可用区 {placed[ids.index(iid)]}"
               + (f"，开机后自动应用模板「{tpl['name']}」" if tpl else "")
               + (f"，授权共享盘 {'、'.join(share_msgs)}" if share_msgs else ""))
    from collections import Counter
    return {"ok": True, "instance_ids": ids, "region": region, "zones": dict(Counter(placed)), "requested": req.count,
            "warning": (f"仅创建成功 {len(ids)}/{req.count} 台，其余因容量不足失败" if len(ids) < req.count else "")}


@app.delete("/api/images/{image_id}")
def delete_image(image_id: str, region: str = "", user=Depends(ADMIN)):
    region = region or aws_service.image_region(image_id)
    try:
        aws_service.delete_image(image_id, region)
    except Exception as e:  # noqa: BLE001
        _fail("删除失败", e, 400)
    _audit("-", "snapshot", user, f"删除快照 {image_id}（{region}）")
    return {"ok": True}


class CopyImageReq(BaseModel):
    regions: List[str]


@app.post("/api/images/{image_id}/copy")
def copy_image(image_id: str, req: CopyImageReq, user=Depends(ADMIN)):
    """把快照复制到其他管理区域，用于在那里批量创建相同环境的服务器。"""
    src = aws_service.image_region(image_id)
    out, errs = [], []
    for r in dict.fromkeys(req.regions):
        try:
            new = aws_service.copy_image(image_id, src, r)
            out.append({"region": r, "image_id": new})
            _audit("-", "snapshot", user, f"复制快照 {image_id}（{src}）到 {r}：{new}")
        except Exception as e:  # noqa: BLE001
            errs.append(f"{r}：{e}")
    if not out and errs:
        raise HTTPException(status_code=400, detail="；".join(errs))
    return {"ok": True, "copies": out, "errors": errs}


# ---------------- 用户与角色（Cognito） ----------------
def _cog():
    if not cognito_auth:
        raise HTTPException(status_code=400, detail="未启用 Cognito 用户管理")
    return cognito_auth


def _guard_last_admin(username, losing_admin: bool):
    if losing_admin and _cog().count_admins() <= 1:
        raise HTTPException(status_code=400, detail="至少需要保留一名启用状态的管理员")


@app.get("/api/users")
def list_users(_=Depends(ADMIN)):
    try:
        users = _cog().list_users()
        assigned = {}
        for i in aws_service.list_instances():
            if i.get("portal_user"):
                assigned.setdefault(i["portal_user"], []).append({"instance_id": i["instance_id"], "name": i["name"]})
        for u in users:
            u["instances"] = assigned.get(u["username"], [])
        return {"users": users, "roles": [{"key": k, "name": ROLE_ZH[k]} for k in ROLE_RANK]}
    except Exception as e:  # noqa: BLE001
        _fail("读取用户失败", e)


class UserInstancesReq(BaseModel):
    instance_ids: List[str]


def _assign_instances(username, instance_ids):
    """把服务器分配给用户（标签 dcv:user）：列表中的设为该用户，原先属于该用户但不在列表中的收回。

    一台服务器只分配给一个用户；已分配给他人的会改为该用户。返回 (新增, 收回)。
    """
    insts = {i["instance_id"]: i for i in aws_service.list_instances(use_cache=False)}
    unknown = [x for x in instance_ids if x not in insts]
    if unknown:
        raise HTTPException(status_code=400, detail=f"不是平台管理的服务器：{'、'.join(unknown)}")
    want = set(instance_ids)
    add = [x for x in want if insts[x].get("portal_user") != username]
    drop = [x for x, i in insts.items() if i.get("portal_user") == username and x not in want]
    if add:
        aws_service.set_mgmt_tags(add, {"portal_user": username})
    if drop:
        aws_service.set_mgmt_tags(drop, {"portal_user": ""})
    return add, drop, insts


@app.put("/api/users/{username}/instances")
def set_user_instances(username: str, req: UserInstancesReq, user=Depends(ADMIN)):
    try:
        cur = next((u for u in _cog().list_users() if u["username"] == username), None)
        if not cur:
            raise HTTPException(status_code=404, detail="用户不存在")
        add, drop, insts = _assign_instances(username, list(dict.fromkeys(req.instance_ids)))
    except Exception as e:  # noqa: BLE001
        _fail("分配服务器失败", e, 400)
    for iid in add:
        prev = insts[iid].get("portal_user")
        _audit(iid, "assign", user, f"分配给用户 {username}" + (f"（原属 {prev}）" if prev else ""))
    for iid in drop:
        _audit(iid, "assign", user, f"从用户 {username} 收回")
    return {"ok": True, "added": len(add), "removed": len(drop)}


@app.post("/api/users")
def create_user(req: UserReq, user=Depends(ADMIN)):
    if req.role not in ROLE_RANK:
        raise HTTPException(status_code=400, detail="角色不合法")
    try:
        res = _cog().create_user(req.username.strip(), req.password, req.email or "", req.role)
    except Exception as e:  # noqa: BLE001
        _fail("创建用户失败", e, 400)
    _audit("-", "user", user, f"创建用户 {req.username.strip()}（{ROLE_ZH[req.role]}）")
    return res


@app.put("/api/users/{username}/role")
def set_user_role(username: str, req: UserRoleReq, user=Depends(ADMIN)):
    if req.role not in ROLE_RANK:
        raise HTTPException(status_code=400, detail="角色不合法")
    if username == user["username"] and req.role != "admin":
        raise HTTPException(status_code=400, detail="不能降低自己的角色")
    try:
        cur = next((u for u in _cog().list_users() if u["username"] == username), None)
        if not cur:
            raise HTTPException(status_code=404, detail="用户不存在")
        _guard_last_admin(username, cur["role"] == "admin" and req.role != "admin" and cur["enabled"])
        _cog().set_role(username, req.role)
    except Exception as e:  # noqa: BLE001
        _fail("修改角色失败", e, 400)
    _audit("-", "user", user, f"用户 {username} 角色改为 {ROLE_ZH[req.role]}（重新登录后生效）")
    return {"ok": True}


@app.post("/api/users/{username}/password")
def reset_user_password(username: str, req: UserPasswordReq, user=Depends(ADMIN)):
    try:
        _cog().set_password(username, req.password)
    except Exception as e:  # noqa: BLE001
        _fail("重置口令失败", e, 400)
    _audit("-", "user", user, f"重置用户 {username} 的登录密码")
    return {"ok": True}


@app.post("/api/users/{username}/enabled")
def enable_user(username: str, req: UserEnableReq, user=Depends(ADMIN)):
    if username == user["username"] and not req.enabled:
        raise HTTPException(status_code=400, detail="不能禁用自己")
    try:
        if not req.enabled:
            cur = next((u for u in _cog().list_users() if u["username"] == username), None)
            _guard_last_admin(username, bool(cur and cur["role"] == "admin" and cur["enabled"]))
        _cog().set_enabled(username, req.enabled)
    except Exception as e:  # noqa: BLE001
        _fail("操作失败", e, 400)
    _audit("-", "user", user, f"{'启用' if req.enabled else '禁用'}用户 {username}")
    return {"ok": True}


@app.delete("/api/users/{username}")
def delete_user(username: str, user=Depends(ADMIN)):
    if username == user["username"]:
        raise HTTPException(status_code=400, detail="不能删除自己")
    try:
        cur = next((u for u in _cog().list_users() if u["username"] == username), None)
        _guard_last_admin(username, bool(cur and cur["role"] == "admin" and cur["enabled"]))
        _cog().delete_user(username)
    except Exception as e:  # noqa: BLE001
        _fail("删除用户失败", e, 400)
    try:
        _, dropped, _ = _assign_instances(username, [])
        extra = f"，收回 {len(dropped)} 台服务器" if dropped else ""
    except Exception as e:  # noqa: BLE001
        log.exception("收回用户 %s 的服务器失败", username)
        extra = f"；收回其服务器失败（{e}），请在服务器上清除标签 dcv:user"
    _audit("-", "user", user, f"删除用户 {username}{extra}")
    return {"ok": True}


# ---------------- 审计 ----------------
@app.get("/api/audit")
def audit(q: str = "", action: str = "", operator: str = "", days: int = 30,
          limit: int = 100, offset: int = 0, _=Depends(VIEWER)):
    since = time.time() - max(1, min(days, 3650)) * 86400
    res = store.query_audit(q.strip(), action, operator, since, min(max(limit, 1), 500), max(offset, 0))
    names = {i["instance_id"]: i["name"] for i in aws_service.list_instances()}
    for it in res["items"]:
        it["instance_name"] = names.get(it["instance_id"], "")
    return res


# ---------------- S3 共享盘 ----------------
class ShareReq(BaseModel):
    name: str
    bucket: str
    prefix: Optional[str] = ""
    drive: str
    mode: str = "rw"
    scope: str = "selected"
    cache_gb: int = 20
    kms_key: Optional[str] = ""
    create_bucket: bool = False
    instance_ids: List[str] = []


class SharePatch(BaseModel):
    name: Optional[str] = None
    drive: Optional[str] = None
    mode: Optional[str] = None
    scope: Optional[str] = None
    cache_gb: Optional[int] = None


class ShareTargetsReq(BaseModel):
    add: List[str] = []
    remove: List[str] = []


def _affected(share, extra_ids=()):
    """该共享盘涉及的服务器（全部范围 = 全部纳管服务器）。"""
    all_ids = [i["instance_id"] for i in aws_service.list_instances()]
    ids = all_ids if share["scope"] == "all" else list(share.get("target_ids", []))
    return [i for i in dict.fromkeys([*ids, *extra_ids]) if i in all_ids]


def _resync(ids, user, title):
    """同步共享盘。正忙的服务器不跳过：登记为待同步，当前任务结束后自动补做。"""
    if not ids:
        return None
    busy = store.running_jobs_for(ids)
    for i in busy:
        jobs.PENDING_SHARE_SYNC.add(i)
    ids = [i for i in ids if i not in busy]
    if not ids:
        return None
    time.sleep(8)  # 等待 IAM 策略变更生效
    return jobs.start_share_sync(ids, user["username"], title)


def _share_out(s, insts_by_id):
    rows = []
    for inst in insts_by_id.values():
        for r in inst.get("shares", []):
            if r["id"] == s["id"]:
                rows.append({"instance_id": inst["instance_id"], "name": inst["name"], "state": inst["state"], **{k: r[k] for k in ("status", "pending", "last_error")}})
    return {**{k: s[k] for k in ("id", "name", "bucket", "prefix", "region", "drive", "mode", "scope", "cache_gb", "kms_key", "created_at", "updated_at", "updated_by")},
            "target_ids": s["target_ids"], "servers": rows,
            "mounted": sum(r["status"] == "ok" for r in rows), "problems": sum(r["status"] in ("missing", "failed", "outdated") for r in rows),
            "policy_count": len(json.loads(s.get("policy_arn") or "[]")), "path": f"s3://{s['bucket']}/{s['prefix']}".rstrip("/") + "/",
            "console_url": f"https://s3.console.aws.amazon.com/s3/buckets/{s['bucket']}?region={s['region']}&prefix={s['prefix'] + '/' if s['prefix'] else ''}"}


@app.get("/api/shares")
def list_shares(_=Depends(VIEWER)):
    by_id = {i["instance_id"]: i for i in _enriched()}
    import share_service
    return {"shares": [_share_out(s, by_id) for s in store.list_shares()],
            "drives": share_service.DRIVES, "role": config.INSTANCE_ROLE_NAME, "profile": config.LAUNCH_PROFILE}


@app.get("/api/shares/buckets")
def list_buckets(_=Depends(ADMIN)):
    import share_service
    try:
        return {"buckets": share_service.list_buckets()}
    except Exception as e:  # noqa: BLE001
        _fail("读取存储桶失败", e)


@app.post("/api/shares")
def create_share(req: ShareReq, user=Depends(ADMIN)):
    import share_service
    f = {"name": req.name.strip(), "bucket": req.bucket.strip().lower(), "prefix": share_service.clean_prefix(req.prefix),
         "drive": req.drive.upper().rstrip(":"), "mode": req.mode, "scope": req.scope, "cache_gb": req.cache_gb,
         "kms_key": (req.kms_key or "").strip() or None}
    try:
        share_service.validate(f, store.list_shares())
        if req.scope == "selected" and not req.instance_ids:
            raise ValueError("请选择要挂载的服务器，或将适用范围设为「全部服务器」")
        if req.create_bucket:
            share_service.create_bucket(f["bucket"], config.HOME_REGION)
            f["region"] = config.HOME_REGION
        else:
            f["region"] = share_service.bucket_region(f["bucket"])
        sid = store.create_share(user["username"], **f)
        if req.scope == "selected":
            store.add_share_targets(sid, req.instance_ids, user["username"])
        s = next(x for x in store.list_shares() if x["id"] == sid)
        try:
            arns = share_service.sync_iam(s, s["target_ids"])
        except Exception:
            store.delete_share(sid)
            raise
        store.update_share(sid, user["username"], policy_arn=json.dumps(arns))
    except Exception as e:  # noqa: BLE001
        _fail("创建共享盘失败", e, 400)
    s = next(x for x in store.list_shares() if x["id"] == sid)
    _audit("-", "share", user, f"创建共享盘「{f['name']}」 {f['drive']}: → s3://{f['bucket']}/{f['prefix']}（{'读写' if f['mode'] == 'rw' else '只读'}，"
           f"{'全部服务器' if f['scope'] == 'all' else str(len(s['target_ids'])) + ' 台'}）" + ("，新建存储桶" if req.create_bucket else ""))
    jid = _resync(_affected(s), user, f"挂载共享盘「{f['name']}」")
    return {"ok": True, "id": sid, "job_id": jid}


@app.put("/api/shares/{sid}")
def update_share(sid: int, req: SharePatch, user=Depends(ADMIN)):
    import share_service
    old = next((x for x in store.list_shares() if x["id"] == sid), None)
    if not old:
        raise HTTPException(status_code=404, detail="共享盘不存在")
    f = {k: v for k, v in req.dict().items() if v is not None}
    if "drive" in f:
        f["drive"] = f["drive"].upper().rstrip(":")
    new = {**old, **f}
    try:
        share_service.validate(new, [x for x in store.list_shares() if x["id"] != sid])
        if new["scope"] == "selected" and not new["target_ids"]:
            raise ValueError("「指定服务器」范围下至少需要一台服务器")
        arns = share_service.sync_iam(new, new["target_ids"])
        store.update_share(sid, user["username"], **f, policy_arn=json.dumps(arns))
    except Exception as e:  # noqa: BLE001
        _fail("修改失败", e, 400)
    zh = {"name": "名称", "drive": "盘符", "mode": "访问方式", "scope": "适用范围", "cache_gb": "缓存"}
    _audit("-", "share", user, f"修改共享盘「{new['name']}」：" + "，".join(f"{zh[k]} {old[k]}→{v}" for k, v in f.items() if old[k] != v))
    jid = _resync(_affected(new, _affected(old)), user, f"更新共享盘「{new['name']}」")
    return {"ok": True, "job_id": jid}


@app.post("/api/shares/{sid}/targets")
def share_targets(sid: int, req: ShareTargetsReq, user=Depends(ADMIN)):
    import share_service
    s = next((x for x in store.list_shares() if x["id"] == sid), None)
    if not s:
        raise HTTPException(status_code=404, detail="共享盘不存在")
    if s["scope"] == "all":
        raise HTTPException(status_code=400, detail="该共享盘对全部服务器生效，无需单独添加")
    new_ids = sorted((set(s["target_ids"]) | set(req.add)) - set(req.remove))
    if not new_ids:
        raise HTTPException(status_code=400, detail="至少保留一台服务器；如要停用，请删除共享盘")
    try:
        arns = share_service.sync_iam(s, new_ids)
        store.add_share_targets(sid, req.add, user["username"])
        store.remove_share_targets(sid, req.remove)
        store.update_share(sid, user["username"], policy_arn=json.dumps(arns))
    except Exception as e:  # noqa: BLE001
        _fail("修改授权失败", e, 400)
    names = {i["instance_id"]: i["name"] for i in aws_service.list_instances()}
    if req.add:
        _audit("-", "share", user, f"共享盘「{s['name']}」授权给：" + "、".join(names.get(i, i) for i in req.add))
    if req.remove:
        _audit("-", "share", user, f"共享盘「{s['name']}」取消授权：" + "、".join(names.get(i, i) for i in req.remove))
    jid = _resync([*req.add, *req.remove], user, f"共享盘「{s['name']}」授权变更")
    return {"ok": True, "job_id": jid}


@app.delete("/api/shares/{sid}")
def delete_share(sid: int, user=Depends(ADMIN)):
    s = next((x for x in store.list_shares() if x["id"] == sid), None)
    if not s:
        raise HTTPException(status_code=404, detail="共享盘不存在")
    affected = _affected(s)
    busy = store.running_jobs_for(affected)
    if busy:
        raise HTTPException(status_code=409, detail="相关服务器有未完成的任务，请稍后再删除")
    store.delete_share(sid)
    try:
        jid = jobs.start_share_delete(s, affected, user["username"])
    except Exception as e:  # noqa: BLE001
        _fail("删除失败", e, 400)
    _audit("-", "share", user, f"删除共享盘「{s['name']}」（S3 数据保留在 s3://{s['bucket']}/{s['prefix']}）")
    return {"ok": True, "job_id": jid}


@app.post("/api/jobs/share-sync")
def job_share_sync(req: BatchReq, user=Depends(OPERATOR)):
    try:
        return {"job_id": jobs.start_share_sync(req.instance_ids, user["username"])}
    except Exception as e:  # noqa: BLE001
        _fail("创建任务失败", e)


# ---------------- 前端 ----------------
@app.get("/")
def index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/health")
def health():
    return {"ok": True}


# ---------------- 初始化设置（管理员） ----------------
class SetupPlan(BaseModel):
    region: str
    network: Dict
    security_group: Dict
    access: Dict
    allowed_types: List[str]
    default_fallback: Optional[Dict] = None
    scheduler_tz: Optional[str] = None
    inspect_interval_min: Optional[int] = None
    idle_hours: Optional[float] = None
    volume_gb: Optional[int] = None
    deploy: bool = True
    home_region: Optional[str] = None


class RegionReq(BaseModel):
    region: str


class KeyReq(BaseModel):
    region: str
    name: str


@app.get("/api/setup/status")
def setup_status(_=Depends(ADMIN)):
    import setup_service
    try:
        regions = setup_service.check_all()
        home = config.HOME_REGION
        return {"identity": setup_service.identity(), "global": setup_service.global_settings(), "home_region": home,
                "regions": [{"region": r, **regions[r]} for r in config.REGIONS],
                # 兼容：主区域
                "plan": regions[home]["plan"], "checks": regions[home]["checks"]}
    except Exception as e:  # noqa: BLE001
        _fail("读取设置失败", e)


@app.get("/api/setup/regions")
def setup_regions(_=Depends(ADMIN)):
    import setup_service
    return {"regions": setup_service.regions()}


@app.get("/api/setup/network")
def setup_network(region: str, vpc_id: str = "", _=Depends(ADMIN)):
    import setup_service
    try:
        return setup_service.network(region, vpc_id or None)
    except Exception as e:  # noqa: BLE001
        _fail("读取网络失败", e, 400)


@app.get("/api/setup/access")
def setup_access(region: str, _=Depends(ADMIN)):
    import setup_service
    try:
        return setup_service.access(region)
    except Exception as e:  # noqa: BLE001
        _fail("读取角色与密钥失败", e, 400)


@app.post("/api/setup/key")
def setup_key(req: KeyReq, user=Depends(ADMIN)):
    import setup_service, re as _re
    if not _re.fullmatch(r"[A-Za-z0-9._-]{1,128}", req.name):
        raise HTTPException(status_code=400, detail="密钥名称只能包含字母、数字和 . _ -")
    try:
        pem = setup_service.create_key(req.region, req.name)
    except Exception as e:  # noqa: BLE001
        _fail("创建密钥对失败", e, 400)
    _audit("-", "setup", user, f"在 {req.region} 新建密钥对 {req.name}")
    return {"name": req.name, "private_key": pem}


@app.post("/api/setup/check")
def setup_check(req: SetupPlan, _=Depends(ADMIN)):
    """预检：只对选择「已有资源」的部分做检查；新建的部分在执行时创建。"""
    import setup_service
    errs = setup_service.validate(req.dict())
    plan = {"region": req.region, "vpc_id": req.network.get("vpc_id", ""), "subnet_ids": req.network.get("subnet_ids", []),
            "security_group_id": req.security_group.get("id", ""), "instance_profile": req.access.get("profile", ""),
            "instance_role": req.access.get("role", ""), "key_name": req.access.get("key_name", "")}
    checks = []
    try:
        checks = setup_service.check(plan)
    except Exception as e:  # noqa: BLE001
        errs.append(f"检查失败：{e}")
    skip = set()
    if req.network.get("mode") == "create":
        skip |= {"subnets"}
    if req.security_group.get("mode") == "create":
        skip |= {"sg"}
    if req.access.get("profile_mode") == "create":
        skip |= {"profile"}
    if req.deploy:
        skip |= {"scheduler", "group", "history", "power"}
    skip |= {"license"}  # 执行时自动为所有管理区域授权
    for x in checks:
        if x["key"] in skip:
            x.update(status="pending", detail="将在执行时创建或更新")
        if x["key"] == "profile" and x["status"] == "error" and "不一致" in x["detail"]:
            x.update(status="ok")  # 预检时角色名取自所选配置文件
    return {"errors": errs, "checks": checks}


@app.post("/api/setup/apply")
def setup_apply(req: SetupPlan, user=Depends(ADMIN)):
    import setup_service
    errs = setup_service.validate(req.dict())
    if errs:
        raise HTTPException(status_code=400, detail="；".join(errs))
    if any(t["status"] == "running" for t in setup_service.TASKS.values()):
        raise HTTPException(status_code=409, detail="已有初始化任务在执行")
    if store.running_jobs_for([i["instance_id"] for i in aws_service.list_instances()]):
        raise HTTPException(status_code=409, detail="有批量任务正在执行，请等待完成后再修改设置（平台需要重启）")
    tid = setup_service.apply(req.dict(), user["username"])
    _audit("-", "setup", user, f"{'更新' if req.region in config.REGIONS else '新增管理'}区域 {req.region}，网络{'新建' if req.network.get('mode') == 'create' else '已有 ' + req.network.get('vpc_id', '')}，"
           f"安全组{'新建' if req.security_group.get('mode') == 'create' else '已有 ' + req.security_group.get('id', '')}")
    return {"task_id": tid}


@app.get("/api/setup/tasks/{tid}")
def setup_task(tid: str, _=Depends(ADMIN)):
    import setup_service
    t = setup_service.TASKS.get(tid)
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在（平台可能已重启，请刷新设置页查看结果）")
    return t


@app.post("/api/setup/regions/remove")
def setup_remove_region(req: RegionReq, user=Depends(ADMIN)):
    import setup_service
    n = sum(1 for i in aws_service.list_instances() if i.get("region") == req.region)
    if store.running_jobs_for([i["instance_id"] for i in aws_service.list_instances()]):
        raise HTTPException(status_code=409, detail="有批量任务正在执行，请等待完成后再修改设置（平台需要重启）")
    try:
        home = setup_service.remove_region(req.region, user["username"])
    except Exception as e:  # noqa: BLE001
        _fail("移除区域失败", e, 400)
    _audit("-", "setup", user, f"移除管理区域 {req.region}（该区域 {n} 台服务器不再显示，AWS 资源未删除）；主区域 {home}")
    return {"ok": True, "home_region": home, "restart": True}


@app.post("/api/setup/regions/home")
def setup_home_region(req: RegionReq, user=Depends(ADMIN)):
    import setup_service
    try:
        setup_service.set_home(req.region, user["username"])
    except Exception as e:  # noqa: BLE001
        _fail("设置主区域失败", e, 400)
    _audit("-", "setup", user, f"主区域改为 {req.region}")
    return {"ok": True, "restart": True}


@app.get("/api/prices")
def get_prices(refresh: bool = False, region: str = "", _=Depends(VIEWER)):
    """各管理区域（或指定区域，用于新增区域向导）候选机型的按需单价（美元/小时，Windows）。"""
    import pricing_service
    regs = [region] if region else None
    try:
        if refresh:
            for r in regs or config.REGIONS:
                pricing_service.refresh(r, list(dict.fromkeys(config.ALLOWED_INSTANCE_TYPES + config.CANDIDATE_TYPES)))
        return pricing_service.all_regions(wait=bool(region), regions=regs)
    except Exception as e:  # noqa: BLE001
        _fail("读取价格失败", e)
