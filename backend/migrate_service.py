"""跨可用区迁移：服务器所在可用区长期缺货时，把它整机搬到有容量的可用区。

EBS 磁盘绑定可用区，停止的实例无法直接换区，因此流程为：
  1. 实测目标可用区容量（容量预留后立即取消），没容量就不动手
  2. 对原服务器制作镜像（含全部磁盘），保留为「迁移备份」
  3. 在目标可用区按原配置创建新服务器：同机型（或指定机型）、安全组、实例角色、密钥、全部标签
  4. 等新服务器 SSM 上线并确认 DCV 服务运行
  5. 平台内数据改指新服务器：权限模板绑定、自定义权限、备注、共享盘授权（含 IAM 策略）、定时任务、弹性 IP
  6. 删除原服务器（验证未通过时保留原服务器，只是不再纳管）

系统盘内容（Windows、DCV 配置、用户文件、主机名）原样保留；实例 ID、私网/公网 IP 会变化。
"""
import json
import logging
import time

import aws_service
import capacity_service
import config
import store
from db import _conn, _lock

log = logging.getLogger("dcv.migrate")
ec2 = aws_service.ec2

# 这些标签属于原服务器的一次性状态，不复制到新服务器
_DROP_TAGS = {"dcv:pending-template", "from-snapshot", aws_service.FROM_TAG, "dcv:migrated-to"}
MIGRATED_FROM = "dcv:migrated-from"


class MigrateError(Exception):
    pass


def plan_zones(inst, target_zone, instance_type):
    """返回按优先级排列的候选可用区（不含当前可用区）。"""
    subs = capacity_service.launch_subnets()
    if target_zone and target_zone != "auto":
        if target_zone == inst["az"]:
            raise MigrateError("目标可用区与当前相同")
        if target_zone not in subs:
            raise MigrateError(f"{target_zone} 没有可用于创建服务器的公有子网")
        return [target_zone]
    ranked = [az for az, st in capacity_service.best_zones(instance_type) if st != "unavailable"]
    zones = [az for az in ranked if az != inst["az"] and az in subs]
    if not zones:
        raise MigrateError(f"除 {inst['az']} 外没有提供 {instance_type} 的可用区")
    return zones


def _wait(fn, timeout, interval, what):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    raise MigrateError(f"等待{what}超时（{timeout // 60} 分钟）")


def _image_state(ami):
    imgs = ec2.describe_images(ImageIds=[ami]).get("Images", [])
    st = imgs[0]["State"] if imgs else "missing"
    if st in ("failed", "invalid", "error", "deregistered", "missing"):
        raise MigrateError(f"迁移镜像制作失败（{st}）")
    return st == "available"


def create_backup_image(d, name):
    iid = d["InstanceId"]
    tags = [{"Key": "Name", "Value": f"迁移备份 · {name}"[:128]},
            {"Key": config.SNAPSHOT_TAG_KEY, "Value": config.SNAPSHOT_TAG_VALUE},
            {"Key": "source-instance", "Value": iid}, {"Key": "source-name", "Value": name},
            {"Key": "dcv:migration-backup", "Value": iid}]
    return ec2.create_image(
        InstanceId=iid, Name=aws_service.ami_safe_name("migrate", iid), NoReboot=True,
        Description=f"DCV migration backup of {iid}",
        TagSpecifications=[{"ResourceType": "image", "Tags": tags}, {"ResourceType": "snapshot", "Tags": tags}],
    )["ImageId"]


def launch_clone(d, ami, zones, instance_type):
    """在候选可用区依次尝试创建；返回 (新实例 ID, 可用区)。容量不足换下一个可用区。"""
    subs = capacity_service.launch_subnets()
    tags = [t for t in d.get("Tags", []) if not t["Key"].startswith("aws:") and t["Key"] not in _DROP_TAGS]
    if instance_type != d["InstanceType"]:
        tags = [t for t in tags if t["Key"] != "dcv:original-type"] + [{"Key": "dcv:original-type", "Value": d["InstanceType"]}]
    tags.append({"Key": MIGRATED_FROM, "Value": d["InstanceId"]})
    md = d.get("MetadataOptions", {})
    kw = dict(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
        NetworkInterfaces=[{"DeviceIndex": 0, "AssociatePublicIpAddress": True,
                            "Groups": [g["GroupId"] for g in d.get("SecurityGroups", [])] or [config.region_cfg(aws_service.current_region())["security_group_id"]]}],
        MetadataOptions={k: md[k] for k in ("HttpTokens", "HttpEndpoint", "HttpPutResponseHopLimit") if k in md},
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}, {"ResourceType": "volume", "Tags": [t for t in tags if t["Key"] == "Name"]}],
    )
    if d.get("IamInstanceProfile"):
        kw["IamInstanceProfile"] = {"Arn": d["IamInstanceProfile"]["Arn"]}
    if d.get("KeyName"):
        kw["KeyName"] = d["KeyName"]
    last = None
    for az in zones:
        kw["NetworkInterfaces"][0]["SubnetId"] = subs[az]
        try:
            i = ec2.run_instances(**kw)["Instances"][0]
            return i["InstanceId"], az
        except Exception as e:  # noqa: BLE001
            last = e
            if not aws_service.is_capacity_error(e):
                raise
            log.warning("迁移 %s：%s 无 %s 容量，尝试下一个可用区", d["InstanceId"], az, instance_type)
    raise MigrateError(f"{'、'.join(zones)} 均暂无 {instance_type} 容量") from last


def verify(new_id):
    """等 SSM 上线并确认 DCV 服务运行。返回 (是否通过, 说明)。"""
    try:
        _wait(lambda: aws_service.is_ssm_online(new_id), 900, 15, "新服务器 SSM 上线")
    except MigrateError as e:
        return False, str(e)
    try:
        out = aws_service.run_powershell(new_id, ["(Get-Service dcvserver).Status"], timeout=120)
        txt = (out.get("stdout") if isinstance(out, dict) else str(out)) or ""
        if "Running" not in txt:
            time.sleep(30)
            out = aws_service.run_powershell(new_id, ["(Get-Service dcvserver).Status"], timeout=120)
            txt = (out.get("stdout") if isinstance(out, dict) else str(out)) or ""
        return ("Running" in txt), ("DCV 服务运行中" if "Running" in txt else f"DCV 服务状态异常：{txt.strip()[:100]}")
    except Exception as e:  # noqa: BLE001
        return False, f"检查 DCV 服务失败：{e}"


def remap_platform(old, new, operator):
    """平台数据改指新服务器；返回调整说明列表。"""
    notes = []
    with _lock, _conn() as con:
        for table in ("instance_template", "permissions", "instance_meta"):
            con.execute(f"DELETE FROM {table} WHERE instance_id=?", (new,))
            n = con.execute(f"UPDATE {table} SET instance_id=? WHERE instance_id=?", (new, old)).rowcount
            if n and table == "instance_template":
                notes.append("权限模板绑定")
        con.execute("UPDATE OR IGNORE share_targets SET instance_id=? WHERE instance_id=?", (new, old))
        con.execute("DELETE FROM share_targets WHERE instance_id=?", (old,))
        con.execute("DELETE FROM inspections WHERE instance_id=?", (old,))
    # 共享盘：「指定服务器」范围的 IAM 策略按实例 ID 限定，需要重新生成
    import share_service
    for s in store.list_shares():
        if s["scope"] == "selected" and new in s["target_ids"]:
            arns = share_service.sync_iam(s, s["target_ids"])
            store.update_share(s["id"], operator, policy_arn=json.dumps(arns))
            notes.append(f"共享盘「{s['name']}」授权")
    # 定时任务：替换实例 ID
    import eb_scheduler
    for sc in eb_scheduler.list_all():
        if old in sc["instance_ids"]:
            ids = [new if x == old else x for x in sc["instance_ids"]]
            eb_scheduler.update(sc["name"], instance_ids=list(dict.fromkeys(ids)))
            notes.append(f"定时任务 {sc['name']}")
    # 弹性 IP：从原服务器移到新服务器
    for a in ec2.describe_addresses(Filters=[{"Name": "instance-id", "Values": [old]}]).get("Addresses", []):
        ec2.associate_address(AllocationId=a["AllocationId"], InstanceId=new, AllowReassociation=True)
        notes.append(f"弹性 IP {a['PublicIp']}")
    return notes


def retire_old(old, new, terminate):
    if terminate:
        ec2.terminate_instances(InstanceIds=[old])
        return "原服务器已删除"
    # 保留但不再纳管，避免平台里出现两台同名服务器
    ec2.create_tags(Resources=[old], Tags=[{"Key": config.DCV_TAG_KEY, "Value": "migrated"},
                                           {"Key": "dcv:migrated-to", "Value": new}])
    return "原服务器已保留（已停止，不再纳管，可在 AWS 控制台删除）"


def migrate_one(inst, target_zone="auto", instance_type=None, delete_old=True, keep_stopped=False,
                operator="", progress=lambda m: None):
    """迁移一台已停止的服务器；返回结果说明。失败时原服务器保持不变。"""
    iid = inst["instance_id"]
    d = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    if d["State"]["Name"] != "stopped":
        raise MigrateError("请先关机再迁移")
    itype = instance_type or d["InstanceType"]
    if itype not in config.ALLOWED_INSTANCE_TYPES:
        raise MigrateError(f"不支持的机型：{itype}")
    zones = plan_zones(inst, target_zone, itype)

    progress(f"实测 {'、'.join(zones)} 的 {itype} 容量…")
    good = [az for az in zones if capacity_service.probe(az, itype).get("ok")]
    capacity_service.cleanup_probes()
    if not good:
        raise MigrateError(f"{'、'.join(zones)} 此刻均无 {itype} 容量，原服务器未做任何改动")

    progress("制作迁移镜像（含全部磁盘）…")
    ami = create_backup_image(d, inst.get("name") or iid)
    try:
        _wait(lambda: _image_state(ami), 3600, 20, "迁移镜像制作")
        progress(f"在 {good[0]} 创建新服务器…")
        new_id, az = launch_clone(d, ami, good, itype)
    except Exception:
        try:
            aws_service.delete_image(ami)
        except Exception:  # noqa: BLE001
            log.exception("清理迁移镜像失败 %s", ami)
        raise
    aws_service.invalidate_cache()
    progress(f"新服务器 {new_id}（{az}）启动中，等待 SSM 与 DCV 就绪…")
    ec2.get_waiter("instance_running").wait(InstanceIds=[new_id])
    ok, vmsg = verify(new_id)

    notes = remap_platform(iid, new_id, operator)
    retire = retire_old(iid, new_id, terminate=(delete_old and ok))
    if keep_stopped:
        ec2.stop_instances(InstanceIds=[new_id])
    aws_service.invalidate_cache()
    return {
        "ok": ok, "new_id": new_id, "az": az, "type": itype, "backup_image": ami,
        "message": (f"已迁移到 {az}（新实例 {new_id}，{itype}）；{vmsg}；"
                    + (f"已同步：{'、'.join(notes)}；" if notes else "")
                    + retire + f"；迁移备份镜像 {ami} 保留在「快照与镜像」中，确认无误后可删除"
                    + ("；已按要求关机" if keep_stopped else "")),
    }
