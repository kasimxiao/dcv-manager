"""删除服务器（终止 EC2 实例），并清理平台中对它的引用。

流程（每台）：
  1. 检查：终止保护、是否有用户正在连接（由调用方决定是否允许）
  2. 可选：制作「删除前备份」快照并等待完成（快照保留在「快照与镜像」中）
  3. 终止实例（DeleteOnTermination 的磁盘随之删除；其余数据盘保留并在结果中列出）
  4. 平台清理：权限模板绑定、自定义权限、备注、巡检记录、共享盘授权（含 IAM 策略重建）、
     定时任务中的该实例（任务只剩它时删除整个定时任务）、弹性 IP 解除关联（地址保留在账号中）
"""
import json
import logging
import time

import aws_service
import config
import store
from db import _conn, _lock

log = logging.getLogger("dcv.terminate")
ec2 = aws_service.ec2


class TerminateError(Exception):
    pass


def precheck(iid):
    """返回 (实例描述, 问题列表)。"""
    d = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    problems = []
    if d["State"]["Name"] in ("shutting-down", "terminated"):
        problems.append("服务器已在删除中或已删除")
    prot = ec2.describe_instance_attribute(InstanceId=iid, Attribute="disableApiTermination")["DisableApiTermination"]["Value"]
    if prot:
        problems.append("已开启终止保护，请先在 EC2 控制台关闭")
    return d, problems


def backup(d, name, wait_timeout=3600):
    """制作删除前备份快照（含全部磁盘），等待可用后返回 AMI ID。"""
    iid = d["InstanceId"]
    tags = [{"Key": "Name", "Value": f"删除前备份 · {name}"[:128]},
            {"Key": config.SNAPSHOT_TAG_KEY, "Value": config.SNAPSHOT_TAG_VALUE},
            {"Key": "source-instance", "Value": iid}, {"Key": "source-name", "Value": name},
            {"Key": "dcv:terminate-backup", "Value": iid}]
    ami = ec2.create_image(InstanceId=iid, Name=aws_service.ami_safe_name("final-backup", iid), NoReboot=True,
                           Description=f"DCV final backup of {iid}",
                           TagSpecifications=[{"ResourceType": "image", "Tags": tags},
                                              {"ResourceType": "snapshot", "Tags": tags}])["ImageId"]
    t0 = time.time()
    while time.time() - t0 < wait_timeout:
        st = (ec2.describe_images(ImageIds=[ami]).get("Images") or [{"State": "pending"}])[0]["State"]
        if st == "available":
            return ami
        if st in ("failed", "invalid", "error", "deregistered"):
            raise TerminateError(f"备份快照制作失败（{st}），服务器未删除")
        time.sleep(20)
    raise TerminateError("备份快照制作超时，服务器未删除（快照仍在制作中，可稍后在「快照与镜像」中查看）")


def purge_platform(iid, operator):
    """清理平台数据中对该实例的引用；返回说明列表。"""
    notes = []
    affected = [x["id"] for x in store.list_shares() if x["scope"] == "selected" and iid in x["target_ids"]]
    with _lock, _conn() as con:
        n = con.execute("DELETE FROM instance_template WHERE instance_id=?", (iid,)).rowcount
        if n:
            notes.append("权限模板绑定")
        for table in ("permissions", "instance_meta", "inspections", "share_targets"):
            con.execute(f"DELETE FROM {table} WHERE instance_id=?", (iid,))
    import share_service
    for s in store.list_shares():
        if s["id"] in affected:
            # 「指定服务器」共享盘的 IAM 策略按实例 ID 授权，去掉该实例后重建
            try:
                arns = share_service.sync_iam(s, s["target_ids"])
                store.update_share(s["id"], operator, policy_arn=json.dumps(arns))
                notes.append(f"已从共享盘「{s['name']}」授权中移除")
            except Exception:  # noqa: BLE001
                log.exception("重建共享盘策略失败 %s", s["id"])
                notes.append(f"共享盘「{s['name']}」授权更新失败，请在共享存储页重新保存")
    import eb_scheduler
    for sc in eb_scheduler.list_all():
        if iid in sc["instance_ids"]:
            rest = [x for x in sc["instance_ids"] if x != iid]
            if rest:
                eb_scheduler.update(sc["name"], instance_ids=rest, region=sc["region"])
                notes.append(f"已从定时任务 {sc['name']} 移除")
            else:
                eb_scheduler.delete(sc["name"], region=sc["region"])
                notes.append(f"定时任务 {sc['name']} 只包含该服务器，已删除")
    for a in ec2.describe_addresses(Filters=[{"Name": "instance-id", "Values": [iid]}]).get("Addresses", []):
        ec2.disassociate_address(AssociationId=a["AssociationId"])
        notes.append(f"弹性 IP {a['PublicIp']} 已解除关联（仍保留在账号中，不用时请释放）")
    return notes


def terminate_one(inst, do_backup, operator, progress=lambda m: None):
    iid, name = inst["instance_id"], inst.get("name") or inst["instance_id"]
    d, problems = precheck(iid)
    if problems:
        raise TerminateError("；".join(problems))
    kept = [b["Ebs"]["VolumeId"] for b in d.get("BlockDeviceMappings", [])
            if b.get("Ebs") and not b["Ebs"].get("DeleteOnTermination", True)]
    ami = None
    if do_backup:
        progress("制作删除前备份快照…")
        ami = backup(d, name)
    progress("删除服务器…")
    ec2.terminate_instances(InstanceIds=[iid])
    notes = purge_platform(iid, operator)
    aws_service.invalidate_cache()
    msg = "已删除" + (f"；备份快照 {ami} 保留在「快照与镜像」中" if ami else "")
    if kept:
        msg += f"；以下数据盘未随实例删除（仍在计费）：{'、'.join(kept)}"
    if notes:
        msg += "；" + "；".join(notes)
    return {"backup_image": ami, "kept_volumes": kept, "message": msg}
