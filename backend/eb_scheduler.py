"""基于 AWS EventBridge Scheduler 的定时开关机（托管调度，独立于本后端进程），支持多区域。

- 调度是区域级资源，只能操作本区域的实例：一个定时任务对应一个区域。
  创建时若所选服务器分布在多个区域，自动按区域拆成多个调度（备注与时间相同）。
- 一个调度可批量作用于多台实例（EC2 API 接受 InstanceIds 数组）。
- 备注(note)存于 Description；动作由目标 ARN 反推；实例列表存于 Target.Input。
- 开机目标为本区域的托管开机函数（已部署时），容量不足自动换备选机型。
"""
import json
import re
import time
import uuid
import concurrent.futures as cf

import aws_service
import config
from config import SCHEDULER_TZ, SCHEDULER_GROUP, SCHEDULER_ROLE_ARN

ACTION_ARN = {
    "start": "arn:aws:scheduler:::aws-sdk:ec2:startInstances",
    "stop": "arn:aws:scheduler:::aws-sdk:ec2:stopInstances",
    "reboot": "arn:aws:scheduler:::aws-sdk:ec2:rebootInstances",
}
ARN_ACTION = {v: k for k, v in ACTION_ARN.items()}


def _sch(region):
    return aws_service.client("scheduler", region)


# {区域: {"arn", "checked"}}
_fn = {}


def power_function_arn(region=None):
    """该区域托管开机函数的 ARN；未部署时返回 None，开机定时任务直接调用 EC2。"""
    from config import POWER_FUNCTION_NAME
    region = region or config.HOME_REGION
    c = _fn.setdefault(region, {"arn": None, "checked": 0.0})
    if c["arn"] or time.time() - c["checked"] < 300:
        return c["arn"]
    c["checked"] = time.time()
    try:
        c["arn"] = aws_service.client("lambda", region).get_function(
            FunctionName=POWER_FUNCTION_NAME)["Configuration"]["FunctionArn"]
    except Exception:  # noqa: BLE001
        c["arn"] = None
    return c["arn"]


def reset_function_cache(region=None):
    if region:
        _fn.pop(region, None)
    else:
        _fn.clear()


def _role_arn():
    return SCHEDULER_ROLE_ARN or f"arn:aws:iam::{aws_service.account_id()}:role/dcv-scheduler-exec-role"


def _target(action, instance_ids, region=None):
    fn = power_function_arn(region) if action == "start" else None
    if fn:
        return {"Arn": fn, "RoleArn": _role_arn(),
                "Input": json.dumps({"action": "start", "InstanceIds": list(instance_ids)})}
    return {"Arn": ACTION_ARN[action], "RoleArn": _role_arn(), "Input": json.dumps({"InstanceIds": list(instance_ids)})}


def _wrap_cron(expr: str) -> str:
    """接受 6 段 AWS cron 内表达式或完整 cron(...)/rate(...)，统一为完整形式。"""
    expr = expr.strip()
    if expr.startswith("cron(") or expr.startswith("rate(") or expr.startswith("at("):
        return expr
    return f"cron({expr})"


def _unwrap_cron(expr: str) -> str:
    m = re.match(r"^cron\((.*)\)$", expr.strip())
    return m.group(1) if m else expr


_group_ok = set()


def _ensure_group(region):
    if region in _group_ok:
        return
    s = _sch(region)
    try:
        s.get_schedule_group(Name=SCHEDULER_GROUP)
    except s.exceptions.ResourceNotFoundException:
        s.create_schedule_group(Name=SCHEDULER_GROUP)
    _group_ok.add(region)


def _parse(full: dict, region=None) -> dict:
    target = full.get("Target", {})
    arn = target.get("Arn", "")
    action = ARN_ACTION.get(arn, "?")
    instance_ids = []
    try:
        inp = json.loads(target.get("Input", "{}"))
        instance_ids = inp.get("InstanceIds", [])
        if arn.startswith("arn:aws:lambda:"):
            action = inp.get("action", "start")
    except Exception:
        pass
    return {
        "name": full.get("Name"),
        "region": region or config.HOME_REGION,
        "note": full.get("Description", "") or "",
        "action": action,
        "instance_ids": instance_ids,
        "cron": _unwrap_cron(full.get("ScheduleExpression", "")),
        "expression": full.get("ScheduleExpression", ""),
        "timezone": full.get("ScheduleExpressionTimezone", SCHEDULER_TZ),
        "enabled": full.get("State", "ENABLED") == "ENABLED",
        "arn": full.get("Arn"),
        # 开机由托管函数执行：容量不足时按各服务器的备选机型自动换机型
        "managed_start": arn.startswith("arn:aws:lambda:"),
    }


def _put(region, op, name, action, instance_ids, cron, timezone, note, enabled):
    getattr(_sch(region), op)(
        Name=name,
        GroupName=SCHEDULER_GROUP,
        ScheduleExpression=_wrap_cron(cron),
        ScheduleExpressionTimezone=timezone or SCHEDULER_TZ,
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED" if enabled else "DISABLED",
        Description=note or "",
        Target=_target(action, instance_ids, region),
    )


def create_many(action: str, instance_ids, cron: str, timezone: str = None, note: str = "", enabled: bool = True) -> list:
    """按区域拆分创建，返回创建的定时任务列表（每个区域一个）。"""
    if action not in ACTION_ARN:
        raise ValueError("action 必须为 start/stop/reboot")
    if not instance_ids:
        raise ValueError("至少选择一台实例")
    out = []
    for region, ids in aws_service.group_by_region(list(dict.fromkeys(instance_ids))).items():
        _ensure_group(region)
        name = f"dcv-{action}-{uuid.uuid4().hex[:8]}"
        _put(region, "create_schedule", name, action, ids, cron, timezone, note, enabled)
        out.append(get(name, region))
    return out


def create(action: str, instance_ids, cron: str, timezone: str = None, note: str = "", enabled: bool = True) -> dict:
    """兼容旧接口：返回第一个创建的定时任务。"""
    return create_many(action, instance_ids, cron, timezone, note, enabled)[0]


def get(name: str, region=None) -> dict:
    region = region or find_region(name)
    full = _sch(region).get_schedule(Name=name, GroupName=SCHEDULER_GROUP)
    return _parse(full, region)


def _list_region(region):
    s = _sch(region)
    try:
        s.get_schedule_group(Name=SCHEDULER_GROUP)
    except s.exceptions.ResourceNotFoundException:
        return []
    names = []
    for page in s.get_paginator("list_schedules").paginate(GroupName=SCHEDULER_GROUP):
        names += [x["Name"] for x in page.get("Schedules", [])]

    def one(n):
        try:
            return get(n, region)
        except Exception:  # noqa: BLE001
            return None
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        return [x for x in ex.map(one, names) if x]


_where = {}  # 定时任务名 → 区域


def list_all() -> list:
    with cf.ThreadPoolExecutor(max_workers=max(1, len(config.REGIONS))) as ex:
        parts = list(ex.map(_list_region, config.REGIONS))
    out = [x for p in parts for x in p]
    for x in out:
        _where[x["name"]] = x["region"]
    out.sort(key=lambda x: (x["region"] != config.HOME_REGION, x["region"], x["name"]))
    return out


def find_region(name):
    if name not in _where:
        list_all()
    if name not in _where:
        raise ValueError(f"定时任务 {name} 不存在")
    return _where[name]


def update(name: str, action=None, instance_ids=None, cron=None, timezone=None, note=None, enabled=None, region=None) -> dict:
    region = region or find_region(name)
    cur = get(name, region)
    action = action or cur["action"]
    instance_ids = instance_ids if instance_ids is not None else cur["instance_ids"]
    other = [i for i in instance_ids if aws_service.region_of(i) != region]
    if other:
        raise ValueError(f"该定时任务属于 {region}，只能包含本区域的服务器；其他区域的服务器请另建定时任务")
    _put(region, "update_schedule", name, action, instance_ids, cron or cur["cron"], timezone or cur["timezone"],
         note if note is not None else cur["note"], cur["enabled"] if enabled is None else enabled)
    return get(name, region)


def delete(name: str, region=None):
    region = region or find_region(name)
    _sch(region).delete_schedule(Name=name, GroupName=SCHEDULER_GROUP)
    _where.pop(name, None)
