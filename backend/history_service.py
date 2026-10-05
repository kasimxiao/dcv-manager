"""实例运行历史：合并三类数据源，计算运行时段与累计时长。

1. 状态变更日志（EventBridge → CloudWatch Logs，由 AWS 托管采集，保留 365 天）
2. CloudTrail 操作记录（开机/关机/重启/创建/快照，可回溯 90 天，含操作来源）
3. 平台本地审计（记录是哪个平台用户发起的操作）
"""
import json
import datetime as dt

import aws_service
import db
from config import STATE_LOG_GROUP

logs = aws_service._RegionProxy("logs")  # 按服务器所在区域路由
trail = aws_service._RegionProxy("cloudtrail")

UTC = dt.timezone.utc
MAX_DAYS = 90  # CloudTrail 查询上限

TRAIL_ACTIONS = {
    "RunInstances": "创建实例",
    "StartInstances": "开机",
    "StopInstances": "关机",
    "RebootInstances": "重启",
    "TerminateInstances": "终止",
    "CreateImage": "创建快照",
}
STATE_ZH = {
    "pending": "启动中", "running": "运行中", "stopping": "停止中",
    "stopped": "已停止", "shutting-down": "关闭中", "terminated": "已终止",
}
# CloudTrail 动作 ↔ 平台审计动作
_TRAIL_TO_AUDIT = {"StartInstances": "start", "StopInstances": "stop", "RebootInstances": "reboot",
                   "CreateImage": "snapshot"}
AUDIT_ZH = {"start": "开机", "stop": "关机", "reboot": "重启", "permissions": "修改 DCV 权限",
            "snapshot": "创建快照", "launch": "从快照创建实例", "reset_password": "重置 DCV 登录密码",
            "tags": "修改分组/使用人", "rename": "重命名", "share": "共享盘", "change_type": "更改机型", "migrate": "迁移可用区", "host_agent": "主机组件", "terminate": "删除服务器"}


def _state_events(instance_id, start):
    out = []
    try:
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(
            logGroupName=STATE_LOG_GROUP,
            filterPattern=f'"{instance_id}"',
            startTime=int(start.timestamp() * 1000),
            PaginationConfig={"MaxItems": 5000},
        ):
            for e in page.get("events", []):
                try:
                    m = json.loads(e["message"])
                except ValueError:
                    continue
                d = m.get("detail", {})
                if d.get("instance-id") != instance_id:
                    continue
                t = dt.datetime.fromisoformat(m["time"].replace("Z", "+00:00"))
                out.append({"time": t, "state": d.get("state", "")})
    except logs.exceptions.ResourceNotFoundException:
        pass
    return out


def _source_of(detail):
    arn = detail.get("userIdentity", {}).get("arn", "")
    if "dcv-scheduler-exec-role" in arn or "dcv-power-fn-role" in arn:
        return "定时任务"
    ui = detail.get("userIdentity", {})
    return ui.get("userName") or arn.rsplit("/", 1)[-1] or "未知"


def _trail_events(instance_id, start):
    out, token = [], None
    for _ in range(10):
        kw = {
            "LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": instance_id}],
            "StartTime": start,
            "MaxResults": 50,
        }
        if token:
            kw["NextToken"] = token
        resp = trail.lookup_events(**kw)
        for ev in resp.get("Events", []):
            name = ev.get("EventName")
            if name not in TRAIL_ACTIONS:
                continue
            try:
                detail = json.loads(ev.get("CloudTrailEvent", "{}"))
            except ValueError:
                detail = {}
            out.append({
                "time": ev["EventTime"].astimezone(UTC),
                "action": name,
                "source": _source_of(detail),
                "error": detail.get("errorCode"),
            })
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _iso(t):
    return t.astimezone(UTC).isoformat() if t else None


@aws_service.in_instance_region
def get_history(instance_id, days=30):
    days = max(1, min(int(days), MAX_DAYS))
    now = dt.datetime.now(UTC)
    start = now - dt.timedelta(days=days)

    inst = aws_service.get_instance(instance_id) or {}
    cur_state = inst.get("state", "")

    states = _state_events(instance_id, start)
    trails = _trail_events(instance_id, start)
    audits = db.list_audit(instance_id, start.timestamp())

    # ---- 1. 计算运行时段：合并状态日志与 CloudTrail 成功操作 ----
    points = []
    for s in states:
        if s["state"] == "running":
            points.append((s["time"], "up"))
        elif s["state"] in ("stopped", "terminated"):
            points.append((s["time"], "down"))
    for t in trails:
        if t["error"]:
            continue
        if t["action"] in ("RunInstances", "StartInstances"):
            points.append((t["time"], "up"))
        elif t["action"] in ("StopInstances", "TerminateInstances"):
            points.append((t["time"], "down"))
    # 当前运行中：EC2 的 LaunchTime 就是最近一次开机时间，作为可靠的起点
    if cur_state == "running" and inst.get("running_since"):
        lt = dt.datetime.fromisoformat(inst["running_since"])
        if lt >= start:
            points.append((lt, "up"))
    points.sort(key=lambda p: p[0])

    sessions, cur = [], None
    for t, kind in points:
        if kind == "up" and cur is None:
            cur = t
        elif kind == "down" and cur is not None:
            sessions.append({"start": cur, "end": t, "ongoing": False})
            cur = None
    if cur is not None:
        running_now = cur_state in ("running", "pending")
        sessions.append({"start": cur, "end": now if running_now else None, "ongoing": running_now})
    # 若窗口开始前就已在运行（窗口内第一个点是 down），补一个从窗口起点开始的时段
    if points and points[0][1] == "down":
        sessions.insert(0, {"start": start, "end": points[0][0], "ongoing": False, "clipped": True})

    total = 0
    for s in sessions:
        if s["end"]:
            s["seconds"] = int((s["end"] - s["start"]).total_seconds())
            total += s["seconds"]
        else:
            s["seconds"] = None
    sessions.reverse()  # 最新在前

    # ---- 2. 事件时间线：状态变更 + 操作记录（关联平台用户）+ 平台独有操作 ----
    timeline = []
    for s in states:
        timeline.append({"time": s["time"], "type": "state", "title": STATE_ZH.get(s["state"], s["state"]),
                         "state": s["state"], "source": "AWS"})
    used = set()
    for t in trails:
        source = t["source"]
        a = _TRAIL_TO_AUDIT.get(t["action"])
        if a:  # 与平台审计匹配（同动作、时间差 2 分钟内）→ 标注平台操作人
            for au in audits:
                if au["id"] in used or au["action"] != a:
                    continue
                if abs(au["ts"] - t["time"].timestamp()) <= 120:
                    source = f"管理平台 · {au['operator']}"
                    used.add(au["id"])
                    break
        timeline.append({"time": t["time"], "type": "op", "title": TRAIL_ACTIONS[t["action"]],
                         "source": source, "error": t["error"]})
    for au in audits:
        if au["id"] in used:
            continue
        # 电源类操作 CloudTrail 有延迟（约 5-15 分钟）；这里也展示，保证最新操作可见
        timeline.append({"time": dt.datetime.fromtimestamp(au["ts"], UTC), "type": "platform",
                         "title": AUDIT_ZH.get(au["action"], au["action"]),
                         "source": f"管理平台 · {au['operator']}", "detail": au.get("detail") or ""})
    timeline.sort(key=lambda x: x["time"], reverse=True)

    return {
        "instance_id": instance_id,
        "name": inst.get("name", ""),
        "days": days,
        "current_state": cur_state,
        "total_seconds": total,
        "session_count": len(sessions),
        "sessions": [{"start": _iso(s["start"]), "end": _iso(s["end"]), "seconds": s["seconds"],
                      "ongoing": s["ongoing"], "clipped": s.get("clipped", False)} for s in sessions],
        "timeline": [dict(e, time=_iso(e["time"])) for e in timeline],
        "state_log_count": len(states),
    }
