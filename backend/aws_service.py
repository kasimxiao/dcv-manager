"""AWS 服务层：EC2 电源管理/发现 + SSM 远程命令执行（多区域）。

多区域路由：模块级的 ec2 / ssm 是代理对象，每次调用按「当前区域」取对应区域的客户端。
当前区域由 use_region(...) 上下文（线程内有效）决定，未设置时为主区域。
针对单台服务器的函数会自动切到该服务器所在区域，调用方无需关心区域。
"""
import contextlib
import threading
import time
import concurrent.futures as cf
import boto3

import config
from config import AWS_REGION, DCV_TAG_KEY, DCV_TAG_VALUE, DCV_PORT, SSM_TIMEOUT

_session = boto3.session.Session(region_name=AWS_REGION)
_clients = {}
_clients_lock = threading.Lock()
_ctx = threading.local()


def client(svc, region=None):
    region = region or current_region()
    key = (svc, region)
    if key not in _clients:
        with _clients_lock:
            if key not in _clients:
                _clients[key] = _session.client(svc, region_name=region)
    return _clients[key]


def current_region():
    st = getattr(_ctx, "stack", None)
    return st[-1] if st else config.HOME_REGION


@contextlib.contextmanager
def use_region(region):
    """在该上下文（当前线程）内，ec2/ssm 等代理调用都发往 region。"""
    st = getattr(_ctx, "stack", None)
    if st is None:
        st = _ctx.stack = []
    st.append(region or config.HOME_REGION)
    try:
        yield
    finally:
        st.pop()


class _RegionProxy:
    def __init__(self, svc):
        self._svc = svc

    def __getattr__(self, name):
        return getattr(client(self._svc), name)


ec2 = _RegionProxy("ec2")
ssm = _RegionProxy("ssm")
sts = _session.client("sts")

# 实例 ID → 区域（由 list_instances 维护；未知时查询各区域）
_region_map = {}


def region_of(instance_id):
    r = _region_map.get(instance_id)
    if r:
        return r
    list_instances(use_cache=False)
    if instance_id in _region_map:
        return _region_map[instance_id]
    # 未纳管的实例（例如迁移中的新实例）：逐区域查找
    for reg in config.REGIONS:
        try:
            if client("ec2", reg).describe_instances(InstanceIds=[instance_id])["Reservations"]:
                _region_map[instance_id] = reg
                return reg
        except Exception:  # noqa: BLE001
            continue
    return config.HOME_REGION


def in_instance_region(fn):
    """装饰器：第一个参数为实例 ID 的函数，在该实例所在区域执行。"""
    import functools

    @functools.wraps(fn)
    def wrap(instance_id, *a, **kw):
        with use_region(region_of(instance_id)):
            return fn(instance_id, *a, **kw)
    return wrap


def group_by_region(instance_ids):
    out = {}
    for i in instance_ids:
        out.setdefault(region_of(i), []).append(i)
    return out


def run_in_region(region, fn, *a, **kw):
    with use_region(region):
        return fn(*a, **kw)

_account_id = None


def account_id():
    global _account_id
    if _account_id is None:
        _account_id = sts.get_caller_identity()["Account"]
    return _account_id

# 常见 GPU 实例族 → GPU 说明
_GPU_HINTS = {
    "g6f": "NVIDIA L4 (分数卡)",
    "g6": "NVIDIA L4",
    "gr6": "NVIDIA L4",
    "g5": "NVIDIA A10G",
    "g5g": "NVIDIA T4G",
    "g4dn": "NVIDIA T4",
    "g4ad": "AMD Radeon Pro V520",
    "g3": "NVIDIA M60",
    "p5": "NVIDIA H100",
    "p4d": "NVIDIA A100",
    "p3": "NVIDIA V100",
}


def _gpu_for_type(itype: str) -> str:
    fam = itype.split(".")[0]
    return _GPU_HINTS.get(fam, "")


# 实例规格缓存：{instance_type: {cpu, memory_mib, gpu_count, gpu_memory_mib, gpu_name}}
_type_cache = {}


def _type_specs(itype: str) -> dict:
    if itype in _type_cache:
        return _type_cache[itype]
    specs = {"cpu": None, "memory_mib": None, "gpu_count": 0, "gpu_memory_mib": None, "gpu_name": ""}
    try:
        resp = ec2.describe_instance_types(InstanceTypes=[itype])
        it = resp["InstanceTypes"][0]
        specs["cpu"] = it.get("VCpuInfo", {}).get("DefaultVCpus")
        specs["memory_mib"] = it.get("MemoryInfo", {}).get("SizeInMiB")
        gpu = it.get("GpuInfo")
        if gpu:
            specs["gpu_memory_mib"] = gpu.get("TotalGpuMemoryInMiB")
            gpus = gpu.get("Gpus", [])
            if gpus:
                g0 = gpus[0]
                specs["gpu_count"] = g0.get("Count") or g0.get("LogicalGpuCount") or 1
                specs["gpu_name"] = f"{g0.get('Manufacturer','')} {g0.get('Name','')}".strip()
    except Exception:
        pass
    _type_cache[itype] = specs
    return specs


def _name_from_tags(tags):
    for t in tags or []:
        if t["Key"] == "Name":
            return t["Value"]
    return ""


# 管理用标签：分组、使用人、部门、备注。直接存于 EC2 标签，AWS 控制台与成本分摊报表也能使用。
# portal_user：分配给哪个平台账号（桌面用户角色）自助开关机；只能由管理员修改，迁移时随标签带到新服务器。
MGMT_TAGS = {"group": "dcv:group", "assignee": "dcv:assignee", "department": "dcv:department", "note": "dcv:note",
             "pending_template": "dcv:pending-template", "portal_user": "dcv:user"}

# 实例列表短缓存：100 台规模下前端多处同时读取，避免频繁调用 EC2/SSM API
_list_cache = {"ts": 0.0, "items": None}
_LIST_TTL = 5.0


def ssm_ping_map(instance_ids):
    """批量查询 SSM 在线状态：{instance_id: 'Online'|'ConnectionLost'|...}"""
    out = {}
    ids = list(instance_ids)
    for i in range(0, len(ids), 40):  # 过滤条件每次最多 40 个值
        chunk = ids[i:i + 40]
        paginator = ssm.get_paginator("describe_instance_information")
        for page in paginator.paginate(Filters=[{"Key": "InstanceIds", "Values": chunk}]):
            for info in page.get("InstanceInformationList", []):
                out[info["InstanceId"]] = info.get("PingStatus", "")
    return out


def list_instances(use_cache=True):
    """按标签发现 DCV 主机（分页，支持数百台）并返回结构化信息。"""
    now = time.time()
    if use_cache and _list_cache["items"] is not None and now - _list_cache["ts"] < _LIST_TTL:
        return [dict(x) for x in _list_cache["items"]]
    with cf.ThreadPoolExecutor(max_workers=max(1, len(config.REGIONS))) as ex:
        parts = list(ex.map(_list_region_safe, config.REGIONS))
    items, errors = [], {}
    for reg, (got, err) in zip(config.REGIONS, parts):
        items += got
        if err:
            errors[reg] = err
    for i in items:
        _region_map[i["instance_id"]] = i["region"]
    items.sort(key=lambda x: (x["group"] or "~", x["name"] or x["instance_id"]))
    _list_cache.update(ts=now, items=items, errors=errors)
    return [dict(x) for x in items]


def list_errors():
    """最近一次汇总时读取失败的区域：{区域: 错误}。"""
    return dict(_list_cache.get("errors") or {})


def _list_region_safe(region):
    try:
        with use_region(region):
            return _list_region(region), None
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger("dcv.aws").warning("读取 %s 服务器失败：%s", region, e)
        # 读取失败时保留该区域上次的结果，避免服务器在列表中「消失」
        old = [dict(x) for x in (_list_cache.get("items") or []) if x.get("region") == region]
        return old, str(e)[:200]


def _list_region(region):
    items = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[{"Name": f"tag:{DCV_TAG_KEY}", "Values": [DCV_TAG_VALUE]}]):
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                state = inst["State"]["Name"]
                if state == "terminated":
                    continue
                itype = inst.get("InstanceType", "")
                pub_ip = inst.get("PublicIpAddress")
                specs = _type_specs(itype)
                launch = inst.get("LaunchTime")
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                items.append(
                    {
                        "instance_id": inst["InstanceId"],
                        "region": region,
                        "name": tags.get("Name", ""),
                        "state": state,
                        "instance_type": itype,
                        "gpu": specs.get("gpu_name") or _gpu_for_type(itype),
                        "cpu": specs.get("cpu"),
                        "memory_mib": specs.get("memory_mib"),
                        "gpu_count": specs.get("gpu_count"),
                        "gpu_memory_mib": specs.get("gpu_memory_mib"),
                        "az": inst.get("Placement", {}).get("AvailabilityZone", ""),
                        "public_ip": pub_ip,
                        "private_ip": inst.get("PrivateIpAddress"),
                        "platform": inst.get("PlatformDetails", inst.get("Platform", "")),
                        "launch_time": launch.isoformat() if launch else None,
                        # 运行中时以最近一次启动时间(LaunchTime)作为运行起点
                        "running_since": launch.isoformat() if (launch and state == "running") else None,
                        "dcv_url": f"https://{pub_ip}:{DCV_PORT}/" if pub_ip else None,
                        **{k: tags.get(v, "") for k, v in MGMT_TAGS.items()},
                        "from_snapshot": tags.get("from-snapshot", ""),
                        "iam_profile": inst.get("IamInstanceProfile", {}).get("Arn", "").rsplit("/", 1)[-1],
                        "original_type": tags.get("dcv:original-type", ""),
                        # 因容量不足由备选机型临时开机：关机后自动改回该机型
                        "fallback_from": tags.get(FROM_TAG, ""),
                        "fallback_types": fallback_chain(tags, tags.get(FROM_TAG) or itype),
                        "fallback_custom": FB_TAG in tags,
                    }
                )
    try:
        pings = ssm_ping_map([i["instance_id"] for i in items if i["state"] == "running"])
    except Exception:  # noqa: BLE001
        pings = {}
    for i in items:
        i["ssm"] = pings.get(i["instance_id"], "") if i["state"] == "running" else ""
    return items


def invalidate_cache():
    _list_cache["items"] = None


def set_mgmt_tags(instance_ids, values: dict):
    for reg, ids in group_by_region(instance_ids).items():
        with use_region(reg):
            _set_mgmt_tags(ids, values)
    invalidate_cache()


def _set_mgmt_tags(instance_ids, values: dict):
    """批量设置管理标签。values 的键为 group/assignee/department/note；空字符串表示清除。"""
    to_set, to_del = [], []
    for k, v in values.items():
        if k not in MGMT_TAGS or v is None:
            continue
        v = str(v).strip()[:255]
        (to_set.append({"Key": MGMT_TAGS[k], "Value": v}) if v else to_del.append({"Key": MGMT_TAGS[k]}))
    ids = list(instance_ids)
    for i in range(0, len(ids), 500):
        if to_set:
            ec2.create_tags(Resources=ids[i:i + 500], Tags=to_set)
        if to_del:
            ec2.delete_tags(Resources=ids[i:i + 500], Tags=to_del)
    invalidate_cache()


@in_instance_region
def rename_instance(instance_id, name):
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "Name", "Value": name.strip()[:255]}])
    invalidate_cache()


def get_instance(instance_id):
    for i in list_instances():
        if i["instance_id"] == instance_id:
            return i
    return None


@in_instance_region
def power_action(instance_id, action):
    """action: start / stop / reboot"""
    if action == "start":
        ec2.start_instances(InstanceIds=[instance_id])
    elif action == "stop":
        ec2.stop_instances(InstanceIds=[instance_id])
    elif action == "reboot":
        ec2.reboot_instances(InstanceIds=[instance_id])
    else:
        raise ValueError(f"unknown action: {action}")
    invalidate_cache()
    return True


# ---------------- SSM ----------------

@in_instance_region
def run_powershell(instance_id, commands, timeout=SSM_TIMEOUT):
    """在 Windows 实例上执行 PowerShell 命令并等待结果。

    返回 dict: {status, stdout, stderr}
    """
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={"commands": commands},
    )
    cmd_id = resp["Command"]["CommandId"]
    deadline = time.time() + timeout
    time.sleep(1.5)
    while True:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            if time.time() > deadline:
                return {"status": "Timedout", "stdout": "", "stderr": "invocation not found", "command_id": cmd_id}
            time.sleep(1.5)
            continue
        status = inv["Status"]
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            return {
                "status": status,
                "stdout": inv.get("StandardOutputContent", ""),
                "stderr": inv.get("StandardErrorContent", ""),
                "command_id": cmd_id,
            }
        if time.time() > deadline:
            return {"status": "Timedout", "stdout": inv.get("StandardOutputContent", ""), "stderr": "poll timeout",
                    "command_id": cmd_id}
        time.sleep(2)


@in_instance_region
def is_ssm_online(instance_id):
    try:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        lst = resp.get("InstanceInformationList", [])
        return bool(lst) and lst[0].get("PingStatus") == "Online"
    except Exception:
        return False


# ---------------- 快照 (AMI) ----------------
from config import (  # noqa: E402
    SNAPSHOT_TAG_KEY, SNAPSHOT_TAG_VALUE,
    LAUNCH_PROFILE, LAUNCH_VOLUME_GB, ALLOWED_INSTANCE_TYPES,
)


def ami_safe_name(name, instance_id):
    """AMI 名称只允许 3–128 位字母数字与 ()./-_，且账号内唯一；中文等字符替换，并追加时间戳避免重名。"""
    import re as _re
    base = _re.sub(r"[^A-Za-z0-9()./_-]+", "-", name).strip("-")[:80] or "dcv-snapshot"
    return f"{base}-{instance_id[-8:]}-{time.strftime('%Y%m%d-%H%M%S')}"


@in_instance_region
def create_image(instance_id, name, description=""):
    """从实例创建 AMI（快照）。用户输入的名称（可含中文）存为 Name 标签用于显示；AMI 名称自动生成合规版本。"""
    name = name.strip()[:128]
    if not name:
        raise ValueError("快照名称不能为空")
    src = get_instance(instance_id) or {}
    tags = [
        {"Key": "Name", "Value": name},
        {"Key": SNAPSHOT_TAG_KEY, "Value": SNAPSHOT_TAG_VALUE},
        {"Key": "source-instance", "Value": instance_id},
        {"Key": "source-name", "Value": src.get("name", "")},
    ]
    resp = ec2.create_image(
        InstanceId=instance_id,
        Name=ami_safe_name(name, instance_id),
        # 描述同样只允许 ASCII；中文说明保存在标签里
        Description=(description if description.isascii() else "")[:255] or f"DCV snapshot of {instance_id}",
        NoReboot=True,
        TagSpecifications=[
            {"ResourceType": "image", "Tags": tags + ([{"Key": "dcv:description", "Value": description[:255]}] if description else [])},
            {"ResourceType": "snapshot", "Tags": tags},
        ],
    )
    return resp["ImageId"]


def list_images():
    """列出各管理区域中平台创建的快照(AMI)，带 region 字段。"""
    with cf.ThreadPoolExecutor(max_workers=max(1, len(config.REGIONS))) as ex:
        parts = list(ex.map(lambda r: run_in_region(r, _list_images_region, r), config.REGIONS))
    items = [x for part in parts for x in part]
    items.sort(key=lambda x: x["created"], reverse=True)
    return items


def image_region(image_id):
    for x in list_images():
        if x["image_id"] == image_id:
            return x["region"]
    return config.HOME_REGION


def _list_images_region(region):
    try:
        resp = ec2.describe_images(
            Owners=["self"],
            Filters=[{"Name": f"tag:{SNAPSHOT_TAG_KEY}", "Values": [SNAPSHOT_TAG_VALUE]}],
        )
    except Exception:  # noqa: BLE001
        return []
    items = []
    for img in resp.get("Images", []):
        size = 0
        for bdm in img.get("BlockDeviceMappings", []):
            ebs = bdm.get("Ebs")
            if ebs and ebs.get("VolumeSize"):
                size += ebs["VolumeSize"]
        tagmap = {t["Key"]: t["Value"] for t in img.get("Tags", [])}
        items.append({
            "image_id": img["ImageId"],
            "name": tagmap.get("Name") or img.get("Name", ""),
            "ami_name": img.get("Name", ""),
            "state": img.get("State", ""),  # pending / available / failed
            "created": img.get("CreationDate", ""),
            "description": tagmap.get("dcv:description") or img.get("Description", ""),
            "size_gb": size,
            "source_instance": tagmap.get("source-instance", ""),
            "source_name": tagmap.get("source-name", ""),
            "region": region,
            "copied_from": tagmap.get("dcv:copied-from", ""),
        })
    return items


def delete_image(image_id, region=None):
    """注销 AMI 并删除其关联的 EBS 快照。"""
    with use_region(region or image_region(image_id)):
        return _delete_image(image_id)


def copy_image(image_id, src_region, dst_region, name=None):
    """把快照复制到另一个区域（AWS 后台复制，约 10–40 分钟）；新快照沿用名称与标签。"""
    if dst_region not in config.REGIONS:
        raise ValueError(f"{dst_region} 不是平台管理的区域")
    if dst_region == src_region:
        raise ValueError("目标区域与源区域相同")
    src = client("ec2", src_region).describe_images(ImageIds=[image_id])["Images"][0]
    tags = {t["Key"]: t["Value"] for t in src.get("Tags", [])}
    disp = name or tags.get("Name") or src["Name"]
    r = client("ec2", dst_region).copy_image(SourceImageId=image_id, SourceRegion=src_region,
                                             Name=ami_safe_name(src["Name"][:60] + "-" + dst_region, image_id.replace("ami-", "i-")),
                                             Description=(src.get("Description") or "")[:255], CopyImageTags=False)
    new = r["ImageId"]
    keep = {k: v for k, v in tags.items() if not k.startswith("aws:")}
    keep.update({"Name": disp, SNAPSHOT_TAG_KEY: SNAPSHOT_TAG_VALUE, "dcv:copied-from": f"{src_region}/{image_id}"})
    for _ in range(10):  # 复制刚提交时 AMI 可能还查不到
        try:
            client("ec2", dst_region).create_tags(Resources=[new], Tags=[{"Key": k, "Value": v} for k, v in keep.items()])
            break
        except Exception:  # noqa: BLE001
            time.sleep(2)
    return new


def _delete_image(image_id):
    desc = ec2.describe_images(ImageIds=[image_id]).get("Images", [])
    snap_ids = []
    if desc:
        for bdm in desc[0].get("BlockDeviceMappings", []):
            ebs = bdm.get("Ebs")
            if ebs and ebs.get("SnapshotId"):
                snap_ids.append(ebs["SnapshotId"])
    ec2.deregister_image(ImageId=image_id)
    for sid in snap_ids:
        try:
            ec2.delete_snapshot(SnapshotId=sid)
        except Exception:
            pass
    return True


FB_TAG, FROM_TAG = "dcv:fallback-types", "dcv:fallback-from"


def fallback_chain(tags, current):
    """开机容量不足时依次尝试的机型：服务器标签优先（none 表示关闭），否则按当前机型取默认顺序。与托管开机函数逻辑一致。"""
    from config import DEFAULT_FALLBACK, ALLOWED_INSTANCE_TYPES as _A
    raw = tags.get(FB_TAG)
    items = DEFAULT_FALLBACK.get(current, []) if raw is None else ([] if raw.strip() == "none" else raw.split(","))
    out = []
    for t in items:
        t = t.strip()
        if t and t != current and t in _A and t not in out:
            out.append(t)
    return out


@in_instance_region
def mark_fallback(instance_id, from_type):
    """记录「因容量不足临时换机型」，关机后由托管函数自动改回 from_type。"""
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": FROM_TAG, "Value": from_type}])


def set_fallback_types(instance_ids, types):
    """types=None 恢复默认顺序；[] 关闭自动换机型；否则按给定顺序。"""
    if len(group_by_region(instance_ids)) > 1:
        for reg, ids in group_by_region(instance_ids).items():
            with use_region(reg):
                set_fallback_types(ids, types)
        return
    with use_region(region_of(list(instance_ids)[0])):
        _set_fallback_types(instance_ids, types)


def _set_fallback_types(instance_ids, types):
    from config import ALLOWED_INSTANCE_TYPES as _A
    if types is None:
        ec2.delete_tags(Resources=list(instance_ids), Tags=[{"Key": FB_TAG}])
    else:
        bad = [t for t in types if t not in _A]
        if bad:
            raise ValueError(f"不支持的机型: {', '.join(bad)}")
        ec2.create_tags(Resources=list(instance_ids), Tags=[{"Key": FB_TAG, "Value": ",".join(dict.fromkeys(types)) or "none"}])
    invalidate_cache()


@in_instance_region
def change_instance_type(instance_id, new_type, remember_original=True):
    """修改已停止实例的机型（实例 ID、磁盘、IP 分配方式、配置不变）。首次修改时记录原机型，便于改回。"""
    if new_type not in ALLOWED_INSTANCE_TYPES:
        raise ValueError(f"不支持的机型: {new_type}")
    d = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    if d["State"]["Name"] != "stopped":
        raise ValueError("只能修改已停止服务器的机型，请先关机")
    old = d["InstanceType"]
    if old == new_type:
        return old
    ec2.modify_instance_attribute(InstanceId=instance_id, InstanceType={"Value": new_type})
    tags = {t["Key"]: t["Value"] for t in d.get("Tags", [])}
    if FROM_TAG in tags:  # 人工改机型后不再自动改回
        ec2.delete_tags(Resources=[instance_id], Tags=[{"Key": FROM_TAG}])
    if remember_original and "dcv:original-type" not in tags:
        ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "dcv:original-type", "Value": old}])
    elif tags.get("dcv:original-type") == new_type:
        ec2.delete_tags(Resources=[instance_id], Tags=[{"Key": "dcv:original-type"}])
    invalidate_cache()
    return old


def is_capacity_error(e):
    code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
    return "InsufficientInstanceCapacity" in code


def launch_from_image(image_id, instance_type, name, mgmt: dict = None, count: int = 1, subnets=None, region=None):
    """在快照所在区域创建服务器（快照是区域级资源）。"""
    region = region or image_region(image_id)
    with use_region(region):
        return _launch_from_image(image_id, instance_type, name, mgmt, count, subnets, config.region_cfg(region))


def _root_block_device(image_id):
    """按镜像的根卷返回 BlockDeviceMappings：磁盘不得小于镜像快照，否则 AWS 直接拒绝创建。"""
    img = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    root = img.get("RootDeviceName") or "/dev/sda1"
    snap_gb = 0
    for bdm in img.get("BlockDeviceMappings", []):
        if bdm.get("DeviceName") == root and bdm.get("Ebs"):
            snap_gb = int(bdm["Ebs"].get("VolumeSize") or 0)
            break
    size = max(int(LAUNCH_VOLUME_GB), snap_gb)
    return [{"DeviceName": root,
             "Ebs": {"VolumeSize": size, "VolumeType": "gp3", "DeleteOnTermination": True}}], size, snap_gb


def _launch_from_image(image_id, instance_type, name, mgmt, count, subnets, rcfg):
    """从快照(AMI)启动新实例（可批量），自动纳管（打 dcv 标签），可附带分组/使用人等管理标签。

    批量创建时名称自动追加序号：name-01、name-02 …；返回实例 ID 列表。
    """
    if instance_type not in ALLOWED_INSTANCE_TYPES:
        raise ValueError(f"不支持的机型: {instance_type}")
    count = int(count)
    if count < 1:
        raise ValueError("数量至少为 1")
    extra = [{"Key": MGMT_TAGS[k], "Value": str(v).strip()[:255]}
             for k, v in (mgmt or {}).items() if k in MGMT_TAGS and v and str(v).strip()]
    # subnets: 按顺序排列的候选子网。每台依次尝试，某个可用区容量不足时自动换下一个；
    # spread=True 时（由调用方传入轮换后的列表）实现多可用区均衡分布。
    if not rcfg["subnet_ids"] or not rcfg["security_group_id"]:
        raise ValueError("该区域尚未完成网络设置，请先在「系统设置」中配置")
    plan = subnets or [[rcfg["subnet_ids"][0]]] * count
    bdm, vol_gb, snap_gb = _root_block_device(image_id)
    if vol_gb > int(LAUNCH_VOLUME_GB):
        import logging
        logging.getLogger("dcv.aws").info("镜像 %s 的系统盘 %s GB 大于设置的 %s GB，按镜像大小创建",
                                          image_id, snap_gb, LAUNCH_VOLUME_GB)
    ids, placed, errors = [], [], []
    for n in range(count):
        cand = plan[n] if n < len(plan) else plan[-1]
        last = None
        for sub in cand:
            try:
                resp = ec2.run_instances(
                    ImageId=image_id, InstanceType=instance_type, MinCount=1, MaxCount=1,
                    IamInstanceProfile={"Name": LAUNCH_PROFILE}, **({"KeyName": rcfg["key_name"]} if rcfg["key_name"] else {}),
                    BlockDeviceMappings=bdm,
                    NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": sub, "AssociatePublicIpAddress": True, "Groups": [rcfg["security_group_id"]]}],
                    TagSpecifications=[{"ResourceType": "instance", "Tags": [
                        {"Key": "Name", "Value": f"{name}-{n + 1:02d}" if count > 1 else name},
                        {"Key": DCV_TAG_KEY, "Value": DCV_TAG_VALUE},
                        {"Key": "from-snapshot", "Value": image_id}, *extra]}],
                )
                i = resp["Instances"][0]
                ids.append(i["InstanceId"])
                placed.append(i["Placement"]["AvailabilityZone"])
                last = None
                break
            except Exception as e:  # noqa: BLE001
                last = e
                if not is_capacity_error(e):
                    break
        if last is not None:
            errors.append(last)
            if not is_capacity_error(last):
                break  # 非容量问题（参数、配额等）后续也会失败，停止
    invalidate_cache()
    if not ids and errors:
        raise errors[-1]
    return ids, placed, [str(e)[:200] for e in errors]


def allowed_types_with_specs():
    out = []
    for t in ALLOWED_INSTANCE_TYPES:
        s = _type_specs(t)
        out.append({"type": t, "cpu": s.get("cpu"), "memory_mib": s.get("memory_mib"),
                    "gpu_memory_mib": s.get("gpu_memory_mib")})
    return out
