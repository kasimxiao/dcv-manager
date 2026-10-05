"""DCV 托管开机函数（AWS Lambda，由 EventBridge 调用，不依赖平台进程）。

两种触发：
1. EventBridge Scheduler 定时开机：{"action": "start", "InstanceIds": [...]}
   原机型容量不足（或该可用区不提供）时，按实例标签 dcv:fallback-types（无标签时用默认顺序）改机型重试；
   成功后打标签 dcv:fallback-from=<原机型>；全部失败则改回原机型并抛错，触发 Lambda 异步重试。
2. EventBridge 规则 EC2 状态变为 stopped：带 dcv:fallback-from 的实例自动改回原机型。

只操作带纳管标签（默认 dcv=true）的实例；机型限定在 ALLOWED_TYPES 内。
"""
import json
import logging
import os
import concurrent.futures as cf

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)
ec2 = boto3.client("ec2")

TAG_KEY = os.environ.get("DCV_TAG_KEY", "dcv")
TAG_VALUE = os.environ.get("DCV_TAG_VALUE", "true")
ALLOWED = {t for t in os.environ.get("ALLOWED_TYPES", "").split(",") if t}
# 没有 dcv:fallback-types 标签时按当前机型取默认顺序；标签为 none 表示不自动换机型
DEFAULT_FALLBACK = json.loads(os.environ.get("DEFAULT_FALLBACK", "{}"))
FB_TAG, FROM_TAG, ORIG_TAG = "dcv:fallback-types", "dcv:fallback-from", "dcv:original-type"
# 换机型能解决的错误：容量不足、该可用区不提供此机型
SWITCHABLE = ("InsufficientInstanceCapacity", "Unsupported")


def _code(e):
    return e.response.get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""


def _describe(ids):
    out = []
    for i in range(0, len(ids), 100):
        for r in ec2.describe_instances(InstanceIds=ids[i:i + 100])["Reservations"]:
            out += r["Instances"]
    return out


def _tags(inst):
    return {t["Key"]: t["Value"] for t in inst.get("Tags", [])}


def chain_for(tags, current):
    raw = tags.get(FB_TAG)
    items = DEFAULT_FALLBACK.get(current, []) if raw is None else ([] if raw.strip() == "none" else raw.split(","))
    seen, out = {current}, []
    for t in items:
        t = t.strip()
        if t and t not in seen and (not ALLOWED or t in ALLOWED):
            seen.add(t)
            out.append(t)
    return out


def _set_type(iid, t):
    ec2.modify_instance_attribute(InstanceId=iid, InstanceType={"Value": t})


def start_one(inst):
    iid, cur, tags = inst["InstanceId"], inst["InstanceType"], _tags(inst)
    state = inst["State"]["Name"]
    if tags.get(TAG_KEY) != TAG_VALUE:
        return {"id": iid, "status": "skipped", "msg": "未纳管"}
    if state in ("running", "pending"):
        return {"id": iid, "status": "skipped", "msg": "已在运行"}
    if state != "stopped":
        return {"id": iid, "status": "failed", "msg": f"当前状态 {state}，无法开机"}
    try:
        ec2.start_instances(InstanceIds=[iid])
        return {"id": iid, "status": "ok", "type": cur}
    except ClientError as e:
        if _code(e) not in SWITCHABLE:
            return {"id": iid, "status": "failed", "msg": f"{_code(e)}: {e}"}
        first_err = _code(e)
    tried = [cur]
    for t in chain_for(tags, cur):
        tried.append(t)
        try:
            _set_type(iid, t)
            ec2.start_instances(InstanceIds=[iid])
        except ClientError as e:
            if _code(e) in SWITCHABLE:
                continue
            log.error("%s 改为 %s 失败：%s", iid, t, e)
            break
        new_tags = [{"Key": FROM_TAG, "Value": tags.get(FROM_TAG) or cur}]
        if ORIG_TAG not in tags:
            new_tags.append({"Key": ORIG_TAG, "Value": cur})
        ec2.create_tags(Resources=[iid], Tags=new_tags)
        log.info("%s：%s %s，已改为 %s 开机", iid, cur, first_err, t)
        return {"id": iid, "status": "ok", "type": t, "fallback_from": cur}
    if len(tried) > 1:
        try:
            _set_type(iid, cur)
        except ClientError:
            log.exception("%s 改回 %s 失败", iid, cur)
    return {"id": iid, "status": "failed", "msg": f"{inst['Placement']['AvailabilityZone']} 暂无 {'、'.join(tried)} 容量"}


def revert_one(iid):
    inst = _describe([iid])[0]
    tags = _tags(inst)
    target = tags.get(FROM_TAG)
    if tags.get(TAG_KEY) != TAG_VALUE or not target or inst["State"]["Name"] != "stopped":
        return {"id": iid, "status": "skipped"}
    if inst["InstanceType"] != target:
        _set_type(iid, target)
    drop = [{"Key": FROM_TAG}] + ([{"Key": ORIG_TAG}] if tags.get(ORIG_TAG) == target else [])
    ec2.delete_tags(Resources=[iid], Tags=drop)
    log.info("%s 已改回原机型 %s", iid, target)
    return {"id": iid, "status": "reverted", "type": target}


def handler(event, context):
    log.info("事件：%s", json.dumps(event, ensure_ascii=False)[:2000])
    if event.get("detail-type") == "EC2 Instance State-change Notification":
        d = event.get("detail", {})
        return revert_one(d["instance-id"]) if d.get("state") == "stopped" else {"status": "ignored"}
    action = event.get("action", "start")
    ids = list(dict.fromkeys(event.get("InstanceIds") or []))
    if action != "start" or not ids:
        raise ValueError("仅支持 {'action': 'start', 'InstanceIds': [...]}")
    insts = _describe(ids)
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(start_one, insts))
    log.info("结果：%s", json.dumps(results, ensure_ascii=False))
    failed = [r for r in results if r["status"] == "failed"]
    if failed:
        # 抛错让 Lambda 异步调用自动重试（已开机的会被跳过）
        raise RuntimeError(f"{len(failed)}/{len(results)} 台开机失败：" + json.dumps(failed, ensure_ascii=False))
    return {"results": results}
