"""多可用区 GPU 容量检测。

AWS 没有直接查询按需剩余容量的接口，这里综合四类信号，按「可用区 × 机型」给出结论：
1. 供应：该机型是否在该可用区销售（describe_instance_type_offerings）
2. 实测失败：最近 CloudTrail 中开机/创建的 InsufficientInstanceCapacity 记录（真实失败，权重最高）
3. 探测：创建 1 台按需容量预留并立即取消（最可靠的「此刻能否开出」；按秒计费，成本约几分钱）
4. Spot 放置分数（1–10，仅作参考，与按需容量相关但不等同）
另检查 G 系列按需 vCPU 配额的剩余量。
"""
import datetime as dt
import json
import logging
import threading
import time
import concurrent.futures as cf

import aws_service
import config
from config import ALLOWED_INSTANCE_TYPES

log = logging.getLogger("dcv.capacity")
ec2 = aws_service.ec2
_sess = aws_service._session
UTC = dt.timezone.utc

PROBE_TAG = "dcv:capacity-probe"
G_QUOTA_CODE = "L-DB2E81BA"          # Running On-Demand G and VT instances（vCPU）
FAIL_WINDOW_MIN = 60                # 最近多久内的开机失败计入判断
_cache = {}                         # {区域: {"ts", "data"}}
_probe_lock = threading.Lock()
_last_probe = {}                    # {(az, type): {"ok": bool, "at": ts, "error": str}}
_subnet_cache = {}                  # {区域: {"ts", "map"}}


# ---------------- 基础信息 ----------------

def zones():
    r = ec2.describe_availability_zones(Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}])
    return sorted(z["ZoneName"] for z in r["AvailabilityZones"] if z["State"] == "available")


def offerings(types):
    r = ec2.describe_instance_type_offerings(LocationType="availability-zone",
                                              Filters=[{"Name": "instance-type", "Values": list(types)}])
    return {(o["Location"], o["InstanceType"]) for o in r["InstanceTypeOfferings"]}


def launch_subnets(region=None):
    """每个可用区可用于创建服务器的子网（{可用区: 子网}）。

    在「系统设置」中为该区域选定了子网时只用这些子网（按设置顺序，每个可用区取第一个）；
    否则自动发现：与默认子网同 VPC、路由到互联网网关的公有子网。
    """
    region = region or aws_service.current_region()
    c = _subnet_cache.get(region)
    if c and time.time() - c["ts"] < 300:
        return c["map"]
    with aws_service.use_region(region):
        out = _discover_subnets(config.region_cfg(region), explicit=bool((config.REGION_SETTINGS.get(region) or {}).get("subnet_ids")))
    _subnet_cache[region] = {"ts": time.time(), "map": out}
    return out


def _discover_subnets(rcfg, explicit):
    chosen = list(rcfg["subnet_ids"])
    if not chosen:
        return {}
    if explicit:
        got = {x["SubnetId"]: x for x in ec2.describe_subnets(SubnetIds=chosen)["Subnets"]}
        out = {}
        for sid in chosen:
            if sid in got and got[sid]["AvailabilityZone"] not in out:
                out[got[sid]["AvailabilityZone"]] = sid
        return out
    base_id = chosen[0]
    base = ec2.describe_subnets(SubnetIds=[base_id])["Subnets"][0]
    vpc = base["VpcId"]
    subs = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["Subnets"]
    rts = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]
    main_igw = False
    public = set()
    for rt in rts:
        has_igw = any(r.get("GatewayId", "").startswith("igw-") and r.get("DestinationCidrBlock") == "0.0.0.0/0" for r in rt["Routes"])
        for a in rt.get("Associations", []):
            if a.get("Main"):
                main_igw = has_igw
            elif a.get("SubnetId") and has_igw:
                public.add(a["SubnetId"])
    explicit_assoc = {a.get("SubnetId") for rt in rts for a in rt.get("Associations", []) if a.get("SubnetId")}
    out = {}
    for x in sorted(subs, key=lambda x: (x["SubnetId"] != base_id, -x["AvailableIpAddressCount"])):
        is_pub = x["SubnetId"] in public or (x["SubnetId"] not in explicit_assoc and main_igw)
        if is_pub and x["AvailabilityZone"] not in out:
            out[x["AvailabilityZone"]] = x["SubnetId"]
    return out


def g_quota():
    sq = aws_service.client("service-quotas")
    try:
        limit = sq.get_service_quota(ServiceCode="ec2", QuotaCode=G_QUOTA_CODE)["Quota"]["Value"]
    except Exception:  # noqa: BLE001
        limit = sq.get_aws_default_service_quota(ServiceCode="ec2", QuotaCode=G_QUOTA_CODE)["Quota"]["Value"]
    used = 0
    pg = ec2.get_paginator("describe_instances")
    for page in pg.paginate(Filters=[{"Name": "instance-state-name", "Values": ["pending", "running"]}]):
        for res in page["Reservations"]:
            for i in res["Instances"]:
                fam = i["InstanceType"].split(".")[0]
                if fam.startswith(("g", "vt")):
                    used += i.get("CpuOptions", {}).get("CoreCount", 0) * i.get("CpuOptions", {}).get("ThreadsPerCore", 1)
    return {"limit": int(limit), "used": int(used), "free": int(limit - used)}


# ---------------- 信号：真实开机失败 ----------------

def recent_failures(minutes=FAIL_WINDOW_MIN):
    """{(az, type): [{time, source, api}]}：最近开机/创建因容量不足失败的记录。"""
    ct = aws_service.client("cloudtrail")
    start = dt.datetime.now(UTC) - dt.timedelta(minutes=minutes)
    events = []
    for name in ("StartInstances", "RunInstances"):
        token = None
        for _ in range(5):
            kw = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": name}], "StartTime": start, "MaxResults": 50}
            if token:
                kw["NextToken"] = token
            r = ct.lookup_events(**kw)
            events += r["Events"]
            token = r.get("NextToken")
            if not token:
                break
    need_ids, fails = set(), []
    for e in events:
        d = json.loads(e["CloudTrailEvent"])
        if d.get("errorCode") not in ("Server.InsufficientInstanceCapacity", "InsufficientInstanceCapacity"):
            continue
        rp = d.get("requestParameters") or {}
        ids = [x["instanceId"] for x in (rp.get("instancesSet") or {}).get("items", []) if "instanceId" in x]
        arn = d["userIdentity"].get("arn", "")
        src = "定时任务" if ("dcv-scheduler-exec-role" in arn or "dcv-power-fn-role" in arn) else (d["userIdentity"].get("userName") or arn.rsplit("/", 1)[-1])
        f = {"time": e["EventTime"].astimezone(UTC).isoformat(), "source": src, "api": d["eventName"], "ids": ids,
             "type": rp.get("instanceType"), "az": ((rp.get("placement") or {}).get("availabilityZone")),
             "subnet": ((rp.get("networkInterfaceSet") or {}).get("items") or [{}])[0].get("subnetId")}
        need_ids |= set(ids)
        fails.append(f)
    # StartInstances 请求里没有机型/可用区，查询实例补全
    info = {}
    if need_ids:
        for res in ec2.describe_instances(InstanceIds=list(need_ids))["Reservations"]:
            for i in res["Instances"]:
                info[i["InstanceId"]] = (i["Placement"]["AvailabilityZone"], i["InstanceType"])
    subaz = {}
    for f in fails:
        if f["subnet"] and not f["az"]:
            if f["subnet"] not in subaz:
                try:
                    subaz[f["subnet"]] = ec2.describe_subnets(SubnetIds=[f["subnet"]])["Subnets"][0]["AvailabilityZone"]
                except Exception:  # noqa: BLE001
                    subaz[f["subnet"]] = None
            f["az"] = subaz[f["subnet"]]
    out = {}
    for f in fails:
        pairs = [info[i] for i in f["ids"] if i in info] if f["ids"] else [(f["az"], f["type"])]
        for az, it in set(pairs):
            if az and it:
                out.setdefault((az, it), []).append({"time": f["time"], "source": f["source"], "api": f["api"]})
    for v in out.values():
        v.sort(key=lambda x: x["time"], reverse=True)
    return out


def instance_failures(minutes=FAIL_WINDOW_MIN):
    """{instance_id: 最近一次容量不足失败时间}，汇总所有管理区域，用于服务器列表告警。"""
    out = {}
    with cf.ThreadPoolExecutor(max_workers=max(1, len(config.REGIONS))) as ex:
        for part in ex.map(lambda r: _safe(aws_service.run_in_region, r, _instance_failures_region, minutes), config.REGIONS):
            out.update(part or {})
    return out


def _safe(fn, *a):
    try:
        return fn(*a)
    except Exception:  # noqa: BLE001
        log.exception("读取开机失败记录失败")
        return {}


def _instance_failures_region(minutes):
    ct = aws_service.client("cloudtrail")
    start = dt.datetime.now(UTC) - dt.timedelta(minutes=minutes)
    out = {}
    token = None
    for _ in range(5):
        kw = {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "StartInstances"}], "StartTime": start, "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        r = ct.lookup_events(**kw)
        for e in r["Events"]:
            d = json.loads(e["CloudTrailEvent"])
            if "InsufficientInstanceCapacity" not in (d.get("errorCode") or ""):
                continue
            for x in ((d.get("requestParameters") or {}).get("instancesSet") or {}).get("items", []):
                iid = x.get("instanceId")
                ts = e["EventTime"].timestamp()
                if iid and ts > out.get(iid, 0):
                    out[iid] = ts
        token = r.get("NextToken")
        if not token:
            break
    return out


# ---------------- 信号：Spot 放置分数 ----------------

def spot_scores(types, region=None):
    """{(az, type): score}；按机型逐个查询（多机型合并查询得到的是组合分数）。"""
    region = region or aws_service.current_region()
    ce = aws_service.client("ec2", region)
    azmap = {z["ZoneId"]: z["ZoneName"] for z in ce.describe_availability_zones()["AvailabilityZones"]}
    out = {}

    def one(t):
        try:
            r = ce.get_spot_placement_scores(InstanceTypes=[t], TargetCapacity=1, SingleAvailabilityZone=True, RegionNames=[region])
            return t, {azmap.get(s.get("AvailabilityZoneId")): s["Score"] for s in r["SpotPlacementScores"]}
        except Exception as e:  # noqa: BLE001
            log.warning("Spot 放置分数查询失败 %s: %s", t, e)
            return t, {}
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        for t, m in ex.map(one, types):
            for az, sc in m.items():
                out[(az, t)] = sc
    return out


# ---------------- 信号：容量预留探测 ----------------

def probe(az, instance_type, count=1):
    """创建按需容量预留并立即取消，判断此刻能否开出 count 台。

    返回 {"ok": bool, "error": str, "seconds": float}。预留按秒计费，存在时间通常不到 3 秒。
    """
    t0 = time.time()
    res = {"az": az, "type": instance_type, "count": count, "at": t0}
    ec2 = aws_service.client("ec2", config.region_of_az(az))
    with _probe_lock:
        cid = None
        try:
            cr = ec2.create_capacity_reservation(
                InstanceType=instance_type, InstancePlatform="Windows", AvailabilityZone=az, InstanceCount=int(count),
                InstanceMatchCriteria="targeted", EndDateType="unlimited",
                TagSpecifications=[{"ResourceType": "capacity-reservation", "Tags": [{"Key": PROBE_TAG, "Value": "true"}]}])
            cid = cr["CapacityReservation"]["CapacityReservationId"]
            res.update(ok=True, error="")
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            msg = {"InsufficientInstanceCapacity": "容量不足",
                   "ReservationCapacityExceeded": "容量预留配额不足，无法探测",
                   "InstanceLimitExceeded": "配额不足"}.get(code, f"{code or type(e).__name__}：{str(e)[:150]}")
            res.update(ok=False, error=msg, code=code)
        finally:
            if cid:
                for _ in range(3):
                    try:
                        ec2.cancel_capacity_reservation(CapacityReservationId=cid)
                        break
                    except Exception:  # noqa: BLE001
                        time.sleep(1)
    res["seconds"] = round(time.time() - t0, 1)
    _last_probe[(az, instance_type)] = res
    return res


def cleanup_probes(regions=None):
    """取消可能因进程中断而残留的探测预留（启动时及每次探测后调用）。"""
    n = 0
    for reg in regions or config.REGIONS:
        try:
            n += _cleanup_region(aws_service.client("ec2", reg))
        except Exception:  # noqa: BLE001
            log.exception("清理 %s 探测预留失败", reg)
    return n


def _cleanup_region(ec2):
    r = ec2.describe_capacity_reservations(Filters=[{"Name": f"tag:{PROBE_TAG}", "Values": ["true"]},
                                                     {"Name": "state", "Values": ["active", "pending"]}])
    n = 0
    for c in r["CapacityReservations"]:
        try:
            ec2.cancel_capacity_reservation(CapacityReservationId=c["CapacityReservationId"])
            n += 1
        except Exception:  # noqa: BLE001
            log.exception("取消残留探测预留失败")
    if n:
        log.warning("已取消 %d 个残留的容量探测预留", n)
    return n


def probe_matrix(pairs, count=1):
    """并发探测多个 (az, type)。"""
    out = []
    for az, it in pairs:  # 串行：避免同时持有多个预留，也避免触发 API 限速
        out.append(probe(az, it, count))
    cleanup_probes(sorted({config.region_of_az(az) for az, _ in pairs}))
    return out


# ---------------- 汇总 ----------------

def _verdict(offered, fails, probe_res, score):
    """返回 (status, reason)。status: available / likely / limited / unavailable / unknown / not_offered"""
    if not offered:
        return "not_offered", "该可用区不提供此机型"
    now = time.time()
    fresh_probe = probe_res and now - probe_res["at"] < 900
    last_fail = dt.datetime.fromisoformat(fails[0]["time"]).timestamp() if fails else None
    if fresh_probe and (not last_fail or probe_res["at"] > last_fail):
        if probe_res["ok"]:
            return "available", f"{int((now - probe_res['at']) / 60)} 分钟前实测可开出 {probe_res['count']} 台"
        if probe_res.get("code") == "InsufficientInstanceCapacity":
            return "unavailable", f"{int((now - probe_res['at']) / 60)} 分钟前实测容量不足"
        return "unknown", probe_res["error"]
    if last_fail and now - last_fail < 1800:
        return "unavailable", f"最近 {int((now - last_fail) / 60)} 分钟内开机失败 {len(fails)} 次（容量不足）"
    if last_fail:
        return "limited", f"{int((now - last_fail) / 60)} 分钟前出现过容量不足"
    if score is not None:
        if score >= 7:
            return "likely", f"Spot 放置分数 {score}/10，容量较充足（参考值）"
        if score <= 3:
            return "limited", f"Spot 放置分数 {score}/10，容量紧张（参考值）"
        return "likely", f"Spot 放置分数 {score}/10（参考值）"
    return "unknown", "暂无数据，可点击「实测」"


def overview(types=None, use_cache=True, region=None):
    region = region or config.HOME_REGION
    types = [t for t in (types or ALLOWED_INSTANCE_TYPES)]
    c = _cache.get(region)
    if use_cache and c and time.time() - c["ts"] < 60:
        return c["data"]
    R = aws_service.run_in_region
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        f_az = ex.submit(R, region, zones)
        f_off = ex.submit(R, region, offerings, types)
        f_fail = ex.submit(R, region, recent_failures)
        f_spot = ex.submit(spot_scores, types, region)
        f_q = ex.submit(R, region, g_quota)
        f_sub = ex.submit(launch_subnets, region)
        azs, off, fails, spot, subs = f_az.result(), f_off.result(), f_fail.result(), f_spot.result(), f_sub.result()
        try:
            quota = f_q.result()
        except Exception as e:  # noqa: BLE001
            quota = {"error": str(e)}
    insts = [i for i in aws_service.list_instances() if i.get("region") == region]
    specs = {t: aws_service._type_specs(t) for t in types}
    cells = []
    for az in azs:
        for t in types:
            status, reason = _verdict((az, t) in off, fails.get((az, t), []), _last_probe.get((az, t)), spot.get((az, t)))
            cells.append({"az": az, "type": t, "status": status, "reason": reason, "offered": (az, t) in off,
                          "spot_score": spot.get((az, t)), "failures": fails.get((az, t), [])[:5],
                          "probe": _last_probe.get((az, t)),
                          "servers": sum(1 for i in insts if i["az"] == az and i["instance_type"] == t),
                          "running": sum(1 for i in insts if i["az"] == az and i["instance_type"] == t and i["state"] == "running")})
    data = {"generated_at": time.time(), "region": region, "regions": config.REGIONS,
            "zones": [{"az": az, "subnet": subs.get(az), "servers": sum(1 for i in insts if i["az"] == az)} for az in azs],
            "types": [{"type": t, "cpu": specs[t].get("cpu"), "memory_mib": specs[t].get("memory_mib"), "gpu_memory_mib": specs[t].get("gpu_memory_mib")} for t in types],
            "cells": cells, "quota": quota}
    _cache[region] = {"ts": time.time(), "data": data}
    return data


def invalidate(region=None):
    if region:
        _cache.pop(region, None)
    else:
        _cache.clear()


def best_zones(instance_type, region=None):
    """按容量状态给可用区排序，供创建服务器时的「自动选择」使用；只返回有公有子网的可用区。"""
    region = region or aws_service.current_region()
    d = overview(region=region)
    subs = launch_subnets(region)
    rank = {"available": 0, "likely": 1, "unknown": 2, "limited": 3, "unavailable": 4}
    cells = [c for c in d["cells"] if c["type"] == instance_type and c["offered"] and c["az"] in subs]
    cells.sort(key=lambda c: (rank.get(c["status"], 9), c["servers"]))
    return [(c["az"], c["status"]) for c in cells]


def alternatives(instance):
    """已有服务器开不出时的建议：同可用区的其他机型（关机后可直接改）。系统盘绑定可用区，换可用区需快照重建。"""
    d = overview(region=instance.get("region") or config.HOME_REGION)
    az = instance["az"]
    rank = {"available": 0, "likely": 1, "unknown": 2, "limited": 3, "unavailable": 4}
    same = [c for c in d["cells"] if c["az"] == az and c["type"] != instance["instance_type"] and c["offered"]]
    same.sort(key=lambda c: rank.get(c["status"], 9))
    other = [c for c in d["cells"] if c["az"] != az and c["type"] == instance["instance_type"] and c["offered"]]
    other.sort(key=lambda c: rank.get(c["status"], 9))
    return {"change_type": same, "other_zones": other}
