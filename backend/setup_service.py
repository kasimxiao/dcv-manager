"""初始化设置：在控制台选择或新建平台所需的 AWS 资源，并部署托管组件。

资源清单（区域级 = 每个区域一套；全局 = IAM）：
  网络（区域级）   VPC、公有子网（每个可用区）、互联网网关、路由表、安全组（DCV 8443 TCP/UDP）
  主机（全局+区域）实例角色与实例配置文件（SSM 托管）、密钥对
  托管组件（区域级）定时任务执行角色（全局）与调度组、运行历史规则与日志组、托管开机函数与关机改回规则

所有创建操作幂等：已存在则复用；不会删除或修改用户已有的资源（安全组只在新建时写入规则）。
"""
import io
import json
import os
import threading
import time
import uuid
import zipfile
import ipaddress
import concurrent.futures as cf

import boto3

import config

TAG = [{"Key": "dcv:managed-by", "Value": "dcv-manager"}]
STATE_RULE, STATE_LOG_GROUP = "dcv-instance-state-change", config.STATE_LOG_GROUP
REVERT_RULE, FN_ROLE, SCHED_ROLE = "dcv-fallback-revert", "dcv-power-fn-role", "dcv-scheduler-exec-role"
LOGS_POLICY = "dcv-eventbridge-to-logs"
FN_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lambda", "dcv_power", "handler.py")
GPU_FAMILIES = ["g6f", "g4dn", "g5", "g6", "g6e"]

_sessions = {}


def sess(region):
    if region not in _sessions:
        _sessions[region] = boto3.session.Session(region_name=region)
    return _sessions[region]


def c(region, svc):
    return sess(region).client(svc)


def _name(tags):
    return next((t["Value"] for t in tags or [] if t["Key"] == "Name"), "")


# ---------------- 发现 ----------------

def identity():
    i = c(config.AWS_REGION, "sts").get_caller_identity()
    return {"account": i["Account"], "arn": i["Arn"]}


def regions():
    """已启用的区域，以及各区域提供哪些 GPU 机型（判断能否部署 g6f）。"""
    names = sorted(r["RegionName"] for r in c(config.AWS_REGION, "ec2").describe_regions()["Regions"])
    # 必须包含全部候选机型，否则未查询的机型会被误判为「本区域不提供」
    types = list(dict.fromkeys(config.CANDIDATE_TYPES + config.ALLOWED_INSTANCE_TYPES))

    def one(r):
        try:
            o = c(r, "ec2").describe_instance_type_offerings(
                LocationType="availability-zone", Filters=[{"Name": "instance-type", "Values": types}])["InstanceTypeOfferings"]
            by = {}
            for x in o:
                by.setdefault(x["InstanceType"], set()).add(x["Location"])
            return {"region": r, "types": {t: sorted(z) for t, z in by.items()}, "current": r == config.HOME_REGION, "managed": r in config.REGIONS}
        except Exception as e:  # noqa: BLE001
            return {"region": r, "types": {}, "error": str(e)[:120], "current": r == config.HOME_REGION, "managed": r in config.REGIONS}
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        out = list(ex.map(one, names))
    out.sort(key=lambda x: (not x["current"], not x["managed"], not any(t.startswith("g6f") for t in x["types"]), x["region"]))
    return out


def _public_subnets(ec2, vpc_id):
    rts = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    main_igw, public, explicit = False, set(), set()
    for rt in rts:
        igw = any(r.get("GatewayId", "").startswith("igw-") and r.get("DestinationCidrBlock") == "0.0.0.0/0" for r in rt["Routes"])
        for a in rt.get("Associations", []):
            if a.get("Main"):
                main_igw = igw
            elif a.get("SubnetId"):
                explicit.add(a["SubnetId"])
                if igw:
                    public.add(a["SubnetId"])
    return public, explicit, main_igw


def network(region, vpc_id=None):
    """VPC 列表；指定 VPC 时附带子网（是否公有、可用区是否提供 GPU 机型）与安全组。"""
    ec2 = c(region, "ec2")
    vpcs = [{"id": v["VpcId"], "name": _name(v.get("Tags")), "cidr": v["CidrBlock"], "default": v.get("IsDefault", False),
             "managed": any(t["Key"] == "dcv:managed-by" for t in v.get("Tags", []))}
            for v in ec2.describe_vpcs()["Vpcs"]]
    out = {"region": region, "vpcs": sorted(vpcs, key=lambda v: (not v["default"], v["name"] or v["id"])), "sg_template": sg_template()}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"] if z["State"] == "available")
    offers = {}
    for o in ec2.describe_instance_type_offerings(LocationType="availability-zone",
                                                  Filters=[{"Name": "instance-type", "Values": config.ALLOWED_INSTANCE_TYPES}])["InstanceTypeOfferings"]:
        offers.setdefault(o["Location"], []).append(o["InstanceType"])
    out["zones"] = [{"az": z, "types": sorted(offers.get(z, []))} for z in zones]
    if vpc_id:
        public, explicit, main_igw = _public_subnets(ec2, vpc_id)
        subs = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        out["subnets"] = sorted([{
            "id": s["SubnetId"], "name": _name(s.get("Tags")), "az": s["AvailabilityZone"], "cidr": s["CidrBlock"],
            "free_ips": s["AvailableIpAddressCount"], "auto_public_ip": s.get("MapPublicIpOnLaunch", False),
            "public": s["SubnetId"] in public or (s["SubnetId"] not in explicit and main_igw),
            "types": sorted(offers.get(s["AvailabilityZone"], [])),
        } for s in subs], key=lambda x: (x["az"], x["cidr"]))
        out["security_groups"] = [_sg_summary(g) for g in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]]
    return out


def _sg_summary(g):
    port = config.DCV_PORT
    tcp, udp = [], []
    for p in g.get("IpPermissions", []):
        proto = p.get("IpProtocol")
        lo, hi = p.get("FromPort", 0), p.get("ToPort", 65535)
        if proto == "-1" or (lo <= port <= hi):
            src = [r["CidrIp"] for r in p.get("IpRanges", [])] + [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])] \
                + [x.get("GroupId", "") for x in p.get("UserIdGroupPairs", [])] + [x.get("PrefixListId", "") for x in p.get("PrefixListIds", [])]
            if proto in ("tcp", "-1"):
                tcp += src
            if proto in ("udp", "-1"):
                udp += src
    https_out = False
    for p in g.get("IpPermissionsEgress", []):
        proto, lo, hi = p.get("IpProtocol"), p.get("FromPort", 0), p.get("ToPort", 65535)
        to_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])) or bool(p.get("PrefixListIds"))
        if to_world and (proto == "-1" or (proto == "tcp" and lo <= 443 <= hi)):
            https_out = True
    rdp = [r["CidrIp"] for p in g.get("IpPermissions", []) if p.get("IpProtocol") in ("tcp", "-1")
           and p.get("FromPort", 0) <= 3389 <= p.get("ToPort", 65535) for r in p.get("IpRanges", [])]
    return {"id": g["GroupId"], "name": g["GroupName"], "description": g.get("Description", ""),
            "https_out": https_out, "rdp": sorted(set(rdp)),
            "dcv_tcp": sorted(set(tcp)), "dcv_udp": sorted(set(udp)),
            "open_world": "0.0.0.0/0" in tcp or "::/0" in tcp}


def access(region):
    """实例配置文件（附带角色是否有 SSM 托管权限）与密钥对。"""
    iam = c(region, "iam")
    profiles = []
    for page in iam.get_paginator("list_instance_profiles").paginate():
        for p in page["InstanceProfiles"]:
            roles = [r["RoleName"] for r in p.get("Roles", [])]
            profiles.append({"name": p["InstanceProfileName"], "role": roles[0] if roles else "",
                             "manageable": bool(roles) and roles[0].startswith("dcv-")})

    def ssm_ok(p):
        if not p["role"]:
            return {**p, "ssm": False}
        try:
            att = [x["PolicyName"] for x in iam.list_attached_role_policies(RoleName=p["role"])["AttachedPolicies"]]
        except Exception:  # noqa: BLE001
            att = []
        return {**p, "ssm": "AmazonSSMManagedInstanceCore" in att, "policies": att}
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        profiles = list(ex.map(ssm_ok, profiles))
    profiles.sort(key=lambda p: (not p["ssm"], p["name"]))
    keys = [{"name": k["KeyName"], "type": k.get("KeyType", "")} for k in c(region, "ec2").describe_key_pairs()["KeyPairs"]]
    return {"profiles": profiles, "keys": sorted(keys, key=lambda k: k["name"])}


# ---------------- 校验 ----------------

def global_settings():
    return {"home_region": config.HOME_REGION, "instance_profile": config.LAUNCH_PROFILE, "instance_role": config.INSTANCE_ROLE_NAME,
            "allowed_types": config.ALLOWED_INSTANCE_TYPES, "default_fallback": config.DEFAULT_FALLBACK,
            "scheduler_tz": config.SCHEDULER_TZ, "inspect_interval_min": config.INSPECT_INTERVAL_MIN,
            "idle_hours": config.IDLE_HOURS, "volume_gb": config.LAUNCH_VOLUME_GB,
            "saved": bool(config.SETTINGS), "saved_at": config.SETTINGS.get("saved_at"), "saved_by": config.SETTINGS.get("saved_by")}


def current_plan(region=None):
    """某个区域当前生效的配置（区域级网络 + 全局设置），用于向导默认值与状态检查。"""
    import capacity_service
    region = region or config.HOME_REGION
    rc = config.region_cfg(region)
    subs = list((config.REGION_SETTINGS.get(region) or {}).get("subnet_ids") or [])
    if not subs:
        try:
            subs = list(capacity_service.launch_subnets(region).values())
        except Exception:  # noqa: BLE001
            subs = list(rc["subnet_ids"])
    vpc = rc["vpc_id"]
    if not vpc and subs:
        try:
            vpc = c(region, "ec2").describe_subnets(SubnetIds=subs[:1])["Subnets"][0]["VpcId"]
        except Exception:  # noqa: BLE001
            vpc = ""
    return {**global_settings(), "region": region, "vpc_id": vpc, "subnet_ids": subs,
            "security_group_id": rc["security_group_id"], "key_name": rc["key_name"]}


def check_all():
    """所有管理区域的检查结果：{区域: {plan, checks}}（并行）。"""
    def one(r):
        try:
            p = current_plan(r)
            return r, {"plan": p, "checks": check(p)}
        except Exception as e:  # noqa: BLE001
            return r, {"plan": {"region": r}, "checks": [{"key": "region", "title": "区域", "status": "error", "detail": f"检查失败：{e}"}]}
    with cf.ThreadPoolExecutor(max_workers=max(1, len(config.REGIONS))) as ex:
        return dict(ex.map(one, config.REGIONS))


def check(plan=None):
    """逐项检查配置是否可用。返回 [{key, title, status: ok/warn/error, detail}]。"""
    p = plan or current_plan()
    r = p["region"]
    ec2, iam = c(r, "ec2"), c(r, "iam")
    out = []

    def add(key, title, status, detail):
        out.append({"key": key, "title": title, "status": status, "detail": detail})

    # 网络
    try:
        subs = ec2.describe_subnets(SubnetIds=p["subnet_ids"])["Subnets"] if p["subnet_ids"] else []
        public, explicit, main_igw = _public_subnets(ec2, p["vpc_id"]) if p["vpc_id"] else (set(), set(), False)
        bad_vpc = [s["SubnetId"] for s in subs if s["VpcId"] != p["vpc_id"]]
        priv = [s["SubnetId"] for s in subs if not (s["SubnetId"] in public or (s["SubnetId"] not in explicit and main_igw))]
        noip = [s["SubnetId"] for s in subs if not s.get("MapPublicIpOnLaunch")]
        azs = sorted({s["AvailabilityZone"] for s in subs})
        offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone", Filters=[{"Name": "instance-type", "Values": config.ALLOWED_INSTANCE_TYPES}])["InstanceTypeOfferings"]}
        if not subs:
            add("subnets", "子网", "error", "未设置，请在初始化向导中选择或新建 VPC 与子网")
        elif bad_vpc or priv:
            add("subnets", "子网", "error", ("不属于所选 VPC：" + "、".join(bad_vpc) + "；" if bad_vpc else "")
                + ("没有到互联网网关的路由（服务器需要公网访问 SSM 和用户连接）：" + "、".join(priv) if priv else ""))
        else:
            gpu_az = [a for a in azs if a in offered]
            st = "ok" if len(gpu_az) >= 2 else "warn"
            add("subnets", "子网", st, f"{len(subs)} 个公有子网，覆盖 {len(azs)} 个可用区（{'、'.join(azs)}）"
                + ("" if len(gpu_az) >= 2 else "；建议至少两个提供 GPU 机型的可用区，单可用区缺货时才能分散或迁移")
                + (f"；{'、'.join(noip)} 未开启自动分配公网 IP（平台创建时会显式分配，不影响）" if noip else ""))
    except Exception as e:  # noqa: BLE001
        add("subnets", "子网", "error", f"读取失败：{e}")
    # 安全组
    try:
        if not p.get("security_group_id"):
            raise LookupError("未设置")
        g = _sg_summary(ec2.describe_security_groups(GroupIds=[p["security_group_id"]])["SecurityGroups"][0])
        if not g["dcv_tcp"]:
            add("sg", "安全组", "error", f"{g['name']} 未放行 DCV 端口 {config.DCV_PORT}/TCP，用户无法连接")
        elif not g["https_out"]:
            add("sg", "安全组", "error", f"{g['name']} 出站未放行 443/TCP，服务器无法连接 SSM、S3 共享盘与 DCV 授权")
        else:
            add("sg", "安全组", "warn" if (g["open_world"] or "0.0.0.0/0" in g["rdp"]) else "ok",
                f"{g['name']}：{config.DCV_PORT}/TCP 来源 {', '.join(g['dcv_tcp'])}" + (f"；UDP（QUIC）来源 {', '.join(g['dcv_udp'])}" if g["dcv_udp"] else "；未放行 UDP，DCV 将只用 TCP")
                + ("；对全互联网开放，建议限制为公司出口 IP" if g["open_world"] else "")
                + (f"；RDP 3389 对 {', '.join(g['rdp'])} 开放" + ("（对全互联网开放，存在风险）" if "0.0.0.0/0" in g["rdp"] else "") if g["rdp"] else ""))
    except LookupError:
        add("sg", "安全组", "error", "未设置，请在初始化向导中选择或新建")
    except Exception as e:  # noqa: BLE001
        add("sg", "安全组", "error", f"读取失败：{e}")
    # 实例角色
    try:
        if not p.get("instance_profile"):
            raise LookupError("未设置")
        prof = iam.get_instance_profile(InstanceProfileName=p["instance_profile"])["InstanceProfile"]
        roles = [x["RoleName"] for x in prof["Roles"]]
        att = [x["PolicyName"] for x in iam.list_attached_role_policies(RoleName=roles[0])["AttachedPolicies"]] if roles else []
        if not roles:
            add("profile", "实例角色", "error", f"实例配置文件 {p['instance_profile']} 没有关联角色")
        elif "AmazonSSMManagedInstanceCore" not in att:
            add("profile", "实例角色", "warn", f"角色 {roles[0]} 未附加 AmazonSSMManagedInstanceCore，平台可能无法远程管理主机")
        elif not roles[0].startswith(MANAGED_ROLE_PREFIX):
            add("profile", "实例角色", "error", f"角色 {roles[0]} 不以 {MANAGED_ROLE_PREFIX} 开头：平台的最小权限只能传递和修改 {MANAGED_ROLE_PREFIX}* 角色，"
                "创建服务器、共享盘授权、DCV 授权都会失败。请在向导中新建实例角色，或改用 dcv- 开头的角色")
        else:
            st = "ok" if roles[0] == p["instance_role"] else "error"
            add("profile", "实例角色", st, f"{p['instance_profile']} → 角色 {roles[0]}（已有 SSM 托管权限）"
                + ("" if st == "ok" else f"；与设置中的角色 {p['instance_role']} 不一致，共享盘授权会附加到错误的角色"))
    except LookupError:
        add("profile", "实例角色", "error", "未设置，请在初始化向导中选择或新建")
    except Exception as e:  # noqa: BLE001
        add("profile", "实例角色", "error", f"读取失败：{e}")
    # DCV 授权（EC2 上免费，但实例角色必须能读取所在区域的授权桶，否则显示 unlicensed）
    try:
        if p.get("instance_role"):
            ok = dcv_license_ok(p["instance_role"], r)
            add("license", "DCV 授权", "ok" if ok else "error",
                f"实例角色可读取 dcv-license.{r}" if ok else f"实例角色 {p['instance_role']} 无法读取 dcv-license.{r}，该区域服务器的 DCV 会显示未授权；在本向导执行一次即可自动修复")
    except Exception as e:  # noqa: BLE001
        add("license", "DCV 授权", "warn", f"无法检查：{str(e)[:80]}")
    # 密钥对
    try:
        if not p.get("key_name"):
            raise LookupError("未设置")
        ec2.describe_key_pairs(KeyNames=[p["key_name"]])
        add("key", "密钥对", "ok", f"{p['key_name']}（用于解密 Windows 管理员密码，日常运维通过 SSM，无需开放 RDP）")
    except LookupError:
        add("key", "密钥对", "error", "未设置，请在初始化向导中选择或新建")
    except Exception as e:  # noqa: BLE001
        add("key", "密钥对", "error", f"{p['key_name']} 不存在于 {r}：{str(e)[:80]}")
    # 托管组件
    try:
        role = iam.get_role(RoleName=SCHED_ROLE)["Role"]
        ok = "scheduler.amazonaws.com" in json.dumps(role["AssumeRolePolicyDocument"])
        add("scheduler", "定时任务执行角色", "ok" if ok else "error", SCHED_ROLE + ("" if ok else " 信任关系不是 EventBridge Scheduler"))
    except Exception:  # noqa: BLE001
        add("scheduler", "定时任务执行角色", "error", f"{SCHED_ROLE} 不存在")
    try:
        c(r, "scheduler").get_schedule_group(Name=config.SCHEDULER_GROUP)
        add("group", "定时任务调度组", "ok", config.SCHEDULER_GROUP)
    except Exception:  # noqa: BLE001
        add("group", "定时任务调度组", "warn", f"{config.SCHEDULER_GROUP} 不存在（首次创建定时任务时会自动创建）")
    try:
        tg = c(r, "events").list_targets_by_rule(Rule=STATE_RULE)["Targets"]
        ok = any(STATE_LOG_GROUP in t["Arn"] for t in tg)
        add("history", "运行历史记录", "ok" if ok else "error", f"规则 {STATE_RULE} → 日志组 {STATE_LOG_GROUP}" if ok else f"规则 {STATE_RULE} 未指向日志组")
    except Exception:  # noqa: BLE001
        add("history", "运行历史记录", "error", f"规则 {STATE_RULE} 不存在，运行历史只能从 CloudTrail 推算")
    try:
        fn = c(r, "lambda").get_function(FunctionName=config.POWER_FUNCTION_NAME)["Configuration"]
        tg = c(r, "events").list_targets_by_rule(Rule=REVERT_RULE)["Targets"]
        ok = any(t["Arn"] == fn["FunctionArn"] for t in tg)
        add("power", "托管开机函数", "ok" if ok else "warn", f"{config.POWER_FUNCTION_NAME}（容量不足自动换备选机型）" + ("；关机改回规则正常" if ok else "；缺少关机改回规则"))
    except Exception:  # noqa: BLE001
        add("power", "托管开机函数", "error", "未部署：定时开机容量不足时不会自动换机型")
    # 配额
    try:
        q = c(r, "service-quotas")
        try:
            lim = q.get_service_quota(ServiceCode="ec2", QuotaCode="L-DB2E81BA")["Quota"]["Value"]
        except Exception:  # noqa: BLE001
            lim = q.get_aws_default_service_quota(ServiceCode="ec2", QuotaCode="L-DB2E81BA")["Quota"]["Value"]
        n = int(lim // 4)
        add("quota", "G 系列 vCPU 配额", "ok" if n >= 20 else "warn",
            f"{int(lim)} vCPU，约可同时运行 {n} 台 g6f.xlarge" + ("" if n >= 20 else "；规模 20–100 台需在 Service Quotas 申请提额"))
    except Exception as e:  # noqa: BLE001
        add("quota", "G 系列 vCPU 配额", "warn", f"无法读取：{str(e)[:80]}")
    return out


# ---------------- 创建 ----------------

def create_vpc(region, cidr, azs, name="dcv-vpc", log=print):
    """新建 VPC：每个所选可用区一个公有子网（/20 或按 CIDR 均分）、互联网网关、路由表。返回 (vpc_id, [subnet_id])。"""
    net = ipaddress.ip_network(cidr)
    if net.prefixlen > 24:
        raise ValueError("VPC 网段至少 /24")
    if not azs:
        raise ValueError("请至少选择一个可用区")
    ec2 = c(region, "ec2")

    def spec(rt, n):
        return [{"ResourceType": rt, "Tags": TAG + [{"Key": "Name", "Value": n}]}]
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=spec("vpc", name))["Vpc"]["VpcId"]
    log(f"已创建 VPC {vpc}（{cidr}）")
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc])
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})
    igw = ec2.create_internet_gateway(TagSpecifications=spec("internet-gateway", f"{name}-igw"))["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rt = ec2.create_route_table(VpcId=vpc, TagSpecifications=spec("route-table", f"{name}-public"))["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    log(f"已创建互联网网关 {igw} 与公有路由表 {rt}")
    new_prefix = max(net.prefixlen + 4, 20) if net.prefixlen <= 16 else net.prefixlen + 2
    blocks = list(net.subnets(new_prefix=min(new_prefix, 28)))
    if len(blocks) < len(azs):
        raise ValueError("VPC 网段太小，无法为每个可用区划分子网")
    subs = []
    for az, blk in zip(azs, blocks):
        sid = ec2.create_subnet(VpcId=vpc, CidrBlock=str(blk), AvailabilityZone=az,
                                TagSpecifications=spec("subnet", f"{name}-public-{az[-2:]}"))["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=rt, SubnetId=sid)
        subs.append(sid)
        log(f"已创建公有子网 {sid}（{az}，{blk}）")
    return vpc, subs


# 新建安全组的规则模板：按平台功能所需最小放行
SG_EGRESS_MINIMAL = [
    {"proto": "tcp", "port": 443, "cidrs": ["0.0.0.0/0"],
     "purpose": "SSM 远程管理、AWS API、S3 共享盘、DCV 授权、驱动与组件下载、Windows 更新"},
    {"proto": "tcp", "port": 80, "cidrs": ["0.0.0.0/0"], "purpose": "Windows 更新、证书吊销检查（CRL / OCSP）"},
    {"proto": "tcp", "port": 1688, "cidrs": ["169.254.169.250/32", "169.254.169.251/32"], "purpose": "Windows 激活（AWS KMS 服务器）"},
    {"proto": "udp", "port": 123, "cidrs": ["169.254.169.123/32"], "purpose": "时间同步（Amazon Time Sync）"},
]


def sg_template():
    """供向导展示的规则模板。"""
    return {"ingress": [{"proto": "tcp", "port": config.DCV_PORT, "purpose": "DCV 连接（TCP）"},
                        {"proto": "udp", "port": config.DCV_PORT, "purpose": "DCV 连接（QUIC / UDP，画面更流畅）"},
                        {"proto": "tcp", "port": 3389, "purpose": "RDP 远程桌面（可选，仅维护时使用）", "optional": True}],
            "egress_minimal": SG_EGRESS_MINIMAL}


def _cidr_list(items):
    return [str(ipaddress.ip_network(x.strip(), strict=False)) for x in items or [] if x.strip()]


def _ranges(cidrs, desc):
    return ({"IpRanges": [{"CidrIp": x, "Description": desc} for x in cidrs if ":" not in x],
             "Ipv6Ranges": [{"CidrIpv6": x, "Description": desc} for x in cidrs if ":" in x]})


def create_sg(region, vpc_id, cidrs, name="dcv-servers", log=print, egress="minimal", rdp_cidrs=None):
    """新建安全组，按平台功能所需配置：

    入站：DCV 端口 TCP + UDP（来源为填写的网段）；可选 RDP 3389（仅维护，来源单独填写）。
    出站：minimal = 只放行 HTTPS/HTTP、Windows 激活、时间同步（见 SG_EGRESS_MINIMAL）；all = 放行全部出站。
    """
    ec2 = c(region, "ec2")
    cidrs = _cidr_list(cidrs)
    if not cidrs:
        raise ValueError("请至少填写一个允许连接 DCV 的来源网段")
    rdp = _cidr_list(rdp_cidrs)
    if any(x in ("0.0.0.0/0", "::/0") for x in rdp):
        raise ValueError("RDP 不能对全互联网开放，请填写公司出口 IP 等具体网段")
    gname = f"{name}-{uuid.uuid4().hex[:6]}"
    gid = ec2.create_security_group(GroupName=gname, VpcId=vpc_id,
                                    Description="DCV servers (managed by dcv-manager)",
                                    TagSpecifications=[{"ResourceType": "security-group", "Tags": TAG + [{"Key": "Name", "Value": name}]}])["GroupId"]
    ingress = [{"IpProtocol": proto, "FromPort": config.DCV_PORT, "ToPort": config.DCV_PORT, **_ranges(cidrs, f"DCV {proto.upper()}")}
               for proto in ("tcp", "udp")]
    if rdp:
        ingress.append({"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, **_ranges(rdp, "RDP maintenance")})
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=ingress)
    if egress == "minimal":
        ec2.authorize_security_group_egress(GroupId=gid, IpPermissions=[
            {"IpProtocol": r["proto"], "FromPort": r["port"], "ToPort": r["port"],
             **_ranges(r["cidrs"], {443: "HTTPS: SSM, AWS APIs, S3, DCV license, downloads",
                                     80: "HTTP: Windows Update, CRL/OCSP", 1688: "Windows activation (AWS KMS)",
                                     123: "Amazon Time Sync"}[r["port"]])}
            for r in SG_EGRESS_MINIMAL])
        # 去掉默认的「放行全部出站」规则
        ec2.revoke_security_group_egress(GroupId=gid, IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    log(f"已创建安全组 {gname}（{gid}）：入站 {config.DCV_PORT}/TCP+UDP 来源 {', '.join(cidrs)}"
        + (f"；RDP 3389 来源 {', '.join(rdp)}" if rdp else "；不开放 RDP")
        + ("；出站只放行 443、80、Windows 激活与时间同步" if egress == "minimal" else "；出站全部放行"))
    return gid


def ensure_instance_role(name="dcv-instance-role", log=print):
    """实例角色 + 同名实例配置文件，附加 AmazonSSMManagedInstanceCore。返回 (profile, role)。"""
    iam = c(config.AWS_REGION, "iam")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    try:
        iam.get_role(RoleName=name)
        log(f"复用已有角色 {name}")
    except iam.exceptions.NoSuchEntityException:
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Description="DCV servers (SSM managed)", Tags=TAG)
        log(f"已创建实例角色 {name}")
    iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
    try:
        prof = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]
    except iam.exceptions.NoSuchEntityException:
        prof = iam.create_instance_profile(InstanceProfileName=name, Tags=TAG)["InstanceProfile"]
        log(f"已创建实例配置文件 {name}")
    if name not in [r["RoleName"] for r in prof.get("Roles", [])]:
        iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
        time.sleep(10)  # 新实例配置文件需要几秒才能被 EC2 使用
    return name, name


def create_key(region, name):
    """新建密钥对，返回私钥（只返回这一次，平台不保存）。"""
    k = c(region, "ec2").create_key_pair(KeyName=name, KeyType="rsa", KeyFormat="pem",
                                         TagSpecifications=[{"ResourceType": "key-pair", "Tags": TAG}])
    return k["KeyMaterial"]


def ensure_scheduler(region, log=print):
    iam = c(region, "iam")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    try:
        iam.get_role(RoleName=SCHED_ROLE)
    except iam.exceptions.NoSuchEntityException:
        iam.create_role(RoleName=SCHED_ROLE, AssumeRolePolicyDocument=json.dumps(trust), Description="DCV schedules", Tags=TAG)
        log(f"已创建定时任务执行角色 {SCHED_ROLE}")
    managed = {f"aws:ResourceTag/{config.DCV_TAG_KEY}": config.DCV_TAG_VALUE}
    iam.put_role_policy(RoleName=SCHED_ROLE, PolicyName="dcv-ec2-power", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances"],
                                                 "Resource": "arn:aws:ec2:*:*:instance/*", "Condition": {"StringEquals": managed}}]}))
    # 旧版本使用的宽权限内联策略（Resource *）如存在则保留，避免影响已有调度
    sch = c(region, "scheduler")
    try:
        sch.get_schedule_group(Name=config.SCHEDULER_GROUP)
    except sch.exceptions.ResourceNotFoundException:
        sch.create_schedule_group(Name=config.SCHEDULER_GROUP)
        log(f"已在 {region} 创建调度组 {config.SCHEDULER_GROUP}")


def ensure_history(region, log=print):
    logs, events = c(region, "logs"), c(region, "events")
    acct = c(region, "sts").get_caller_identity()["Account"]
    try:
        logs.create_log_group(logGroupName=STATE_LOG_GROUP)
        logs.put_retention_policy(logGroupName=STATE_LOG_GROUP, retentionInDays=400)
        log(f"已创建日志组 {STATE_LOG_GROUP}（保留 400 天）")
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    arn = f"arn:aws:logs:{region}:{acct}:log-group:{STATE_LOG_GROUP}"
    pols = {p["policyName"] for p in logs.describe_resource_policies().get("resourcePolicies", [])}
    if LOGS_POLICY not in pols:
        logs.put_resource_policy(policyName=LOGS_POLICY, policyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": ["events.amazonaws.com", "delivery.logs.amazonaws.com"]},
                                                     "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": f"arn:aws:logs:{region}:{acct}:log-group:/aws/events/*:*"}]}))
    events.put_rule(Name=STATE_RULE, State="ENABLED", Description="DCV：EC2 状态变化写入日志（运行历史）",
                    EventPattern=json.dumps({"source": ["aws.ec2"], "detail-type": ["EC2 Instance State-change Notification"]}))
    events.put_targets(Rule=STATE_RULE, Targets=[{"Id": "dcv-state-log", "Arn": arn}])
    log(f"运行历史：规则 {STATE_RULE} → {STATE_LOG_GROUP}")


def _package():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(FN_SRC, "handler.py")
    return buf.getvalue()


def ensure_power_function(region, allowed_types=None, default_fallback=None, log=print):
    """托管开机函数 + 关机改回规则 + 授权调度角色调用。"""
    iam, lam, events = c(region, "iam"), c(region, "lambda"), c(region, "events")
    acct = c(region, "sts").get_caller_identity()["Account"]
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    try:
        role_arn = iam.get_role(RoleName=FN_ROLE)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        role_arn = iam.create_role(RoleName=FN_ROLE, AssumeRolePolicyDocument=json.dumps(trust), Description="DCV managed start with fallback", Tags=TAG)["Role"]["Arn"]
        log(f"已创建函数角色 {FN_ROLE}")
    iam.attach_role_policy(RoleName=FN_ROLE, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    managed = {f"aws:ResourceTag/{config.DCV_TAG_KEY}": config.DCV_TAG_VALUE}
    iam.put_role_policy(RoleName=FN_ROLE, PolicyName="dcv-power", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
            {"Effect": "Allow", "Action": ["ec2:StartInstances", "ec2:ModifyInstanceAttribute", "ec2:CreateTags", "ec2:DeleteTags"],
             "Resource": "arn:aws:ec2:*:*:instance/*", "Condition": {"StringEquals": managed}}]}))
    env = {"Variables": {"DCV_TAG_KEY": config.DCV_TAG_KEY, "DCV_TAG_VALUE": config.DCV_TAG_VALUE,
                         "ALLOWED_TYPES": ",".join(allowed_types or config.ALLOWED_INSTANCE_TYPES),
                         "DEFAULT_FALLBACK": json.dumps(default_fallback or config.DEFAULT_FALLBACK)}}
    fn = config.POWER_FUNCTION_NAME
    try:
        lam.get_function(FunctionName=fn)
        lam.update_function_code(FunctionName=fn, ZipFile=_package())
        lam.get_waiter("function_updated_v2").wait(FunctionName=fn)
        lam.update_function_configuration(FunctionName=fn, Role=role_arn, Environment=env, Timeout=300, MemorySize=256)
        log(f"已更新托管开机函数 {fn}")
    except lam.exceptions.ResourceNotFoundException:
        for n in range(12):
            try:
                lam.create_function(FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="handler.handler", Code={"ZipFile": _package()},
                                    Timeout=300, MemorySize=256, Environment=env, Tags={"dcv:managed-by": "dcv-manager"},
                                    Description="DCV 定时开机：容量不足自动换备选机型；关机后改回")
                break
            except lam.exceptions.InvalidParameterValueException:
                if n == 11:
                    raise
                time.sleep(5)  # 新角色需要几秒才能被 Lambda 使用
        log(f"已在 {region} 创建托管开机函数 {fn}")
    lam.get_waiter("function_active_v2").wait(FunctionName=fn)
    lam.get_waiter("function_updated_v2").wait(FunctionName=fn)
    lam.put_function_event_invoke_config(FunctionName=fn, MaximumRetryAttempts=2, MaximumEventAgeInSeconds=3600)
    fn_arn = lam.get_function(FunctionName=fn)["Configuration"]["FunctionArn"]
    rule_arn = events.put_rule(Name=REVERT_RULE, State="ENABLED", Description="DCV：实例停止后改回原机型",
                               EventPattern=json.dumps({"source": ["aws.ec2"], "detail-type": ["EC2 Instance State-change Notification"],
                                                        "detail": {"state": ["stopped"]}}))["RuleArn"]
    events.put_targets(Rule=REVERT_RULE, Targets=[{"Id": "dcv-power", "Arn": fn_arn}])
    try:
        lam.add_permission(FunctionName=fn, StatementId="events-revert", Action="lambda:InvokeFunction",
                           Principal="events.amazonaws.com", SourceArn=rule_arn)
    except lam.exceptions.ResourceConflictException:
        pass
    iam.put_role_policy(RoleName=SCHED_ROLE, PolicyName="dcv-invoke-power", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction",
                                                 "Resource": f"arn:aws:lambda:*:{acct}:function:{fn}"}]}))
    log("关机改回规则与调度授权已配置")
    return fn_arn


DCV_LICENSE_POLICY = "dcv-license-access"


def ensure_dcv_license(role, regions, log=print):
    """EC2 上的 DCV 免费授权需要读取所在区域的 dcv-license.<区域> 存储桶；为所有管理区域授权（内联策略，幂等）。"""
    iam = c(config.HOME_REGION, "iam")
    regions = sorted(set(regions))
    iam.put_role_policy(RoleName=role, PolicyName=DCV_LICENSE_POLICY, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Sid": "DcvLicense", "Effect": "Allow", "Action": "s3:GetObject",
                                                 "Resource": [f"arn:aws:s3:::dcv-license.{r}/*" for r in regions]}]}))
    log(f"实例角色 {role} 已授权 DCV 授权存储桶：{'、'.join(regions)}")


def dcv_license_ok(role, region):
    """角色的内联/托管策略中是否包含该区域的 DCV 授权桶（文本匹配，足以发现遗漏）。"""
    iam = c(config.HOME_REGION, "iam")
    need = f"dcv-license.{region}"
    for name in iam.list_role_policies(RoleName=role)["PolicyNames"]:
        if need in json.dumps(iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]):
            return True
    for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
        pol = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]
        doc = iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
        txt = json.dumps(doc)
        if need in txt or "dcv-license.*" in txt or '"Resource": "*"' in txt and "s3:GetObject" in txt:
            return True
    return False


# ---------------- 执行向导 ----------------

TASKS = {}
# 平台角色的最小权限只允许管理以此开头的 IAM 角色、实例配置文件、函数与规则（见 deploy/platform.yaml）
MANAGED_ROLE_PREFIX = "dcv-"


def validate(req):
    """检查向导提交的计划，返回错误列表。"""
    errs = []
    net, sg, acc = req.get("network", {}), req.get("security_group", {}), req.get("access", {})
    if net.get("mode") == "create":
        try:
            ipaddress.ip_network(net.get("cidr", ""))
        except ValueError:
            errs.append("VPC 网段格式不正确")
        if not net.get("azs"):
            errs.append("新建 VPC 需选择可用区")
    elif not net.get("vpc_id") or not net.get("subnet_ids"):
        errs.append("请选择 VPC 和至少一个子网")
    if sg.get("mode") == "create":
        try:
            [ipaddress.ip_network(x.strip(), strict=False) for x in sg.get("cidrs", []) if x.strip()]
        except ValueError:
            errs.append("DCV 来源网段格式不正确")
        if not [x for x in sg.get("cidrs", []) if x.strip()]:
            errs.append("请填写允许连接 DCV 的来源网段")
        try:
            rdp = _cidr_list(sg.get("rdp_cidrs"))
            if any(x in ("0.0.0.0/0", "::/0") for x in rdp):
                errs.append("RDP 不能对全互联网开放")
        except ValueError:
            errs.append("RDP 来源网段格式不正确")
        if sg.get("egress", "minimal") not in ("minimal", "all"):
            errs.append("出站规则选项不正确")
    elif not sg.get("id"):
        errs.append("请选择安全组")
    if acc.get("profile_mode") != "create" and not acc.get("profile"):
        errs.append("请选择实例配置文件")
    if acc.get("profile_mode") == "create" and not (acc.get("role_name") or "dcv-instance-role").startswith(MANAGED_ROLE_PREFIX):
        errs.append(f"实例角色名称必须以 {MANAGED_ROLE_PREFIX} 开头（平台的最小权限只能管理这类角色）")
    if not acc.get("key_name"):
        errs.append("请选择或新建密钥对")
    if not req.get("allowed_types"):
        errs.append("请至少允许一种机型")
    return errs


def save_settings(values, operator, drop=()):
    """合并保存；drop 中的顶层键（旧版单区域字段）一并移除。"""
    data = {**config.load_settings(), **values, "saved_at": time.time(), "saved_by": operator}
    for k in drop:
        data.pop(k, None)
    tmp = config.SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, config.SETTINGS_PATH)
    return data


def apply(req, operator):
    """后台执行：按计划创建/复用资源 → 部署托管组件 → 保存设置。返回任务 ID。"""
    tid = uuid.uuid4().hex[:8]
    task = TASKS[tid] = {"id": tid, "status": "running", "log": [], "started": time.time(), "operator": operator}

    def log(m):
        task["log"].append({"t": time.time(), "msg": m})

    def run():
        try:
            region = req["region"]
            net, sg, acc = req["network"], req["security_group"], req["access"]
            if net.get("mode") == "create":
                vpc, subs = create_vpc(region, net["cidr"], net["azs"], net.get("name") or "dcv-vpc", log)
            else:
                vpc, subs = net["vpc_id"], net["subnet_ids"]
                log(f"使用已有 VPC {vpc}，子网 {'、'.join(subs)}")
            if sg.get("mode") == "create":
                sgid = create_sg(region, vpc, sg["cidrs"], sg.get("name") or "dcv-servers", log,
                                 egress=sg.get("egress", "minimal"), rdp_cidrs=sg.get("rdp_cidrs"))
            else:
                sgid = sg["id"]
                log(f"使用已有安全组 {sgid}")
            if acc.get("profile_mode") == "create":
                profile, role = ensure_instance_role(acc.get("role_name") or "dcv-instance-role", log)
            else:
                profile = acc["profile"]
                roles = c(region, "iam").get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"]
                role = roles[0]["RoleName"] if roles else ""
                log(f"使用已有实例配置文件 {profile}（角色 {role}）")
            if role:
                ensure_dcv_license(role, set(config.REGIONS) | {region}, log)
            if req.get("deploy", True):
                ensure_scheduler(region, log)
                ensure_history(region, log)
                ensure_power_function(region, req["allowed_types"], req.get("default_fallback"), log)
                import eb_scheduler
                eb_scheduler.reset_function_cache(region)
                if region in config.REGIONS:
                    for sc in eb_scheduler._list_region(region):
                        if sc["action"] == "start" and not sc.get("managed_start"):
                            eb_scheduler.update(sc["name"], region=region)
                            log(f"开机定时任务 {sc['name']} 已改为调用托管开机函数")
            rvals = {"vpc_id": vpc, "subnet_ids": subs, "security_group_id": sgid, "key_name": acc["key_name"]}
            gvals = {"instance_profile": profile, "instance_role": role,
                     "allowed_types": req["allowed_types"], "default_fallback": req.get("default_fallback") or config.DEFAULT_FALLBACK}
            for k in ("scheduler_tz", "inspect_interval_min", "idle_hours", "volume_gb"):
                if req.get(k) not in (None, ""):
                    gvals[k] = req[k]
            log("检查配置…")
            res = check({**rvals, **gvals, "region": region})
            for x in res:
                log(f"{'✓' if x['status'] == 'ok' else ('!' if x['status'] == 'warn' else '✗')} {x['title']}：{x['detail']}")
            if any(x["status"] == "error" and x["key"] in ("subnets", "sg", "profile", "key") for x in res):
                raise RuntimeError("关键配置未通过检查，设置未保存")
            cur = config.load_settings()
            regs = config._regions_from(cur) if cur else {r: config.region_cfg(r) for r in config.REGIONS}
            new_region = region not in regs
            regs[region] = rvals
            home = req.get("home_region") or cur.get("region") or config.HOME_REGION
            if home not in regs:
                home = region
            values = {**gvals, "regions": regs, "region": home}
            save_settings(values, operator, drop=config._REGION_KEYS)
            log(("已新增管理区域 " if new_region else "已更新区域 ") + region + f"；主区域 {home}；共 {len(regs)} 个区域")
            log("设置已保存，平台即将重启以生效")
            task.update(status="success", values=values, restart=True)
            schedule_restart()
        except Exception as e:  # noqa: BLE001
            log(f"失败：{e}")
            task.update(status="failed", error=str(e))
        finally:
            task["finished"] = time.time()

    threading.Thread(target=run, daemon=True).start()
    return tid


def schedule_restart(delay=2.0):
    """以相同参数重新执行当前进程，加载新设置（前端会自动重连）。"""
    import sys

    def go():
        time.sleep(delay)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Thread(target=go, daemon=True).start()


def remove_region(region, operator):
    """从平台移除一个管理区域（只修改平台设置，不删除该区域的任何 AWS 资源）。"""
    cur = config.load_settings()
    regs = config._regions_from(cur) if cur else {r: config.region_cfg(r) for r in config.REGIONS}
    if region not in regs:
        raise ValueError(f"{region} 不是平台管理的区域")
    if len(regs) == 1:
        raise ValueError("至少保留一个区域")
    regs.pop(region)
    home = cur.get("region") or config.HOME_REGION
    if home == region or home not in regs:
        home = next(iter(regs))
    save_settings({"regions": regs, "region": home}, operator, drop=config._REGION_KEYS)
    schedule_restart()
    return home


def set_home(region, operator):
    if region not in config.REGIONS:
        raise ValueError(f"{region} 不是平台管理的区域")
    cur = config.load_settings()
    regs = config._regions_from(cur) if cur else {r: config.region_cfg(r) for r in config.REGIONS}
    save_settings({"regions": regs, "region": region}, operator, drop=config._REGION_KEYS)
    schedule_restart()
