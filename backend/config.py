"""全局配置。

优先级：控制台「系统设置」保存的 settings.json > 环境变量 > 默认值。
settings.json 只保存资源标识（区域、VPC、子网、安全组、角色等），不保存任何密钥。
修改后平台自动重启生效。
"""
import os
import json
import secrets

SETTINGS_PATH = os.getenv("DCV_SETTINGS_PATH", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "settings.json"))


def load_settings():
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


SETTINGS = load_settings()


def _get(key, env, default):
    if key in SETTINGS and SETTINGS[key] not in (None, "", []):
        return SETTINGS[key]
    return os.getenv(env, default) if env else default


# AWS 区域
AWS_REGION = _get("region", "AWS_REGION", "eu-central-1")
os.environ["AWS_REGION"] = AWS_REGION
os.environ["AWS_DEFAULT_REGION"] = AWS_REGION

# 纳管标签：给 EC2 实例打上该标签即被识别为 DCV 主机
DCV_TAG_KEY = os.getenv("DCV_TAG_KEY", "dcv")
DCV_TAG_VALUE = os.getenv("DCV_TAG_VALUE", "true")

# DCV 默认参数
DCV_PORT = int(os.getenv("DCV_PORT", "8443"))
# 默认会话属主（当无法从实例探测到时使用）
DCV_DEFAULT_OWNER = os.getenv("DCV_DEFAULT_OWNER", "dcvuser")
# DCV Server 可执行文件路径（Windows）
DCV_EXE = os.getenv("DCV_EXE", r"C:\Program Files\NICE\DCV\Server\bin\dcv.exe")
# 权限文件在实例上的存放路径
DCV_PERM_PATH = os.getenv("DCV_PERM_PATH", r"C:\dcv\console.perm")

# 管理界面登录口令（务必通过环境变量覆盖默认值）
ADMIN_PASSWORD = os.getenv("DCV_ADMIN_PASSWORD", "changeme")

# 数据库路径
DB_PATH = os.getenv("DCV_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data.db"))

# 会话签名密钥（进程级随机；重启后需重新登录）
SESSION_SECRET = os.getenv("DCV_SESSION_SECRET", secrets.token_hex(32))

# 定时任务默认时区
SCHEDULER_TZ = _get("scheduler_tz", "DCV_SCHEDULER_TZ", "Asia/Shanghai")

# EventBridge Scheduler 调度组与执行角色
SCHEDULER_GROUP = os.getenv("DCV_SCHEDULER_GROUP", "dcv-manager")
# 执行角色 ARN；留空则在运行时根据账号自动拼接 dcv-scheduler-exec-role
SCHEDULER_ROLE_ARN = os.getenv("DCV_SCHEDULER_ROLE_ARN", "")

# SSM 命令轮询超时（秒）
SSM_TIMEOUT = int(os.getenv("DCV_SSM_TIMEOUT", "60"))

# ---------------- 快照(AMI)与从快照启动实例 ----------------
# 平台创建的 AMI 会打上该标签，用于在"快照"列表中筛选
SNAPSHOT_TAG_KEY = os.getenv("DCV_SNAPSHOT_TAG_KEY", "dcv-snapshot")
SNAPSHOT_TAG_VALUE = os.getenv("DCV_SNAPSHOT_TAG_VALUE", "true")

# 从快照启动实例时的默认网络/角色/密钥（按环境覆盖）
# ---------------- 多区域 ----------------
# settings.json 的 regions：{区域: {vpc_id, subnet_ids, security_group_id, key_name}}，按区域保存网络与密钥；
# 实例角色、机型、备选机型、时区等为全局设置。旧版单区域设置（顶层 vpc_id/subnet_ids…）自动视为主区域的配置。
_REGION_KEYS = ("vpc_id", "subnet_ids", "security_group_id", "key_name")


def _regions_from(settings):
    regs = {r: dict(v) for r, v in (settings.get("regions") or {}).items()}
    if not regs:
        legacy = {k: settings[k] for k in _REGION_KEYS if settings.get(k)}
        regs[AWS_REGION] = legacy
    return regs


REGION_SETTINGS = _regions_from(SETTINGS)
# 主区域：平台默认区域（新建共享盘存储桶、未指定区域的接口）；必须在已管理区域中
HOME_REGION = AWS_REGION if AWS_REGION in REGION_SETTINGS else next(iter(REGION_SETTINGS))
REGIONS = [HOME_REGION] + sorted(r for r in REGION_SETTINGS if r != HOME_REGION)
# 没有任何默认资源：全新部署时为空，需在「系统设置」中初始化（也可用环境变量预置）
_ENV_DEFAULTS = {"subnet_ids": [x for x in (os.getenv("DCV_LAUNCH_SUBNETS") or os.getenv("DCV_LAUNCH_SUBNET", "")).split(",") if x],
                 "security_group_id": os.getenv("DCV_LAUNCH_SG", ""),
                 "key_name": os.getenv("DCV_LAUNCH_KEY", ""), "vpc_id": ""}


def region_cfg(region):
    """某个区域的网络与密钥配置；主区域未保存的项回退到环境变量（兼容旧部署）。"""
    r = dict(REGION_SETTINGS.get(region) or {})
    if region == HOME_REGION:
        for k, v in _ENV_DEFAULTS.items():
            if not r.get(k):
                r[k] = v
    for k in _REGION_KEYS:
        r.setdefault(k, [] if k == "subnet_ids" else "")
    return r


def region_of_az(az):
    """可用区名 → 区域名（eu-central-1a → eu-central-1）。"""
    return az[:-1] if az and az[-1].isalpha() else az


# 兼容：主区域的配置（旧代码路径与单区域部署）
_home = region_cfg(HOME_REGION)
LAUNCH_SUBNETS = list((REGION_SETTINGS.get(HOME_REGION) or {}).get("subnet_ids") or [])
LAUNCH_SUBNET = _home["subnet_ids"][0] if _home["subnet_ids"] else ""
VPC_ID = _home["vpc_id"]
LAUNCH_SG = _home["security_group_id"]
LAUNCH_PROFILE = _get("instance_profile", "DCV_LAUNCH_PROFILE", "")
LAUNCH_KEY = _home["key_name"]
LAUNCH_VOLUME_GB = int(_get("volume_gb", "DCV_LAUNCH_VOLUME_GB", "60"))

# 允许从快照启动的机型（前端下拉）
ALLOWED_INSTANCE_TYPES = SETTINGS.get("allowed_types") or os.getenv("DCV_ALLOWED_TYPES", "g6f.large,g6f.xlarge,g6f.2xlarge,g4dn.xlarge,g5.xlarge").split(",")

# 初始化向导中可勾选的候选 GPU 机型（实际允许的机型由 ALLOWED_INSTANCE_TYPES 决定）
CANDIDATE_TYPES = ["g6f.large", "g6f.xlarge", "g6f.2xlarge", "g6f.4xlarge",
                   "g4dn.xlarge", "g4dn.2xlarge", "g5.xlarge", "g5.2xlarge",
                   "g6.xlarge", "g6.2xlarge", "g6e.xlarge", "gr6.4xlarge"]

# 托管开机函数（provisioning/deploy_power_function.py 部署）：定时开机容量不足时自动换备选机型，关机后改回
POWER_FUNCTION_NAME = os.getenv("DCV_POWER_FUNCTION", "dcv-power")
# 未单独设置备选机型的服务器，按当前机型使用这里的默认顺序（JSON，可用环境变量覆盖）；
# 服务器标签 dcv:fallback-types 优先，值为 none 表示该服务器不自动换机型
import json as _json  # noqa: E402
DEFAULT_FALLBACK = SETTINGS.get("default_fallback") or _json.loads(os.getenv("DCV_DEFAULT_FALLBACK", _json.dumps({
    "g6f.large": ["g6f.xlarge", "g4dn.xlarge"],
    "g6f.xlarge": ["g4dn.xlarge", "g5.xlarge"],
    "g6f.2xlarge": [],  # 没有同等规格的备选（g5.xlarge/g4dn.xlarge 只有一半 CPU 和内存），默认不自动降级
})))

# ---------------- 运行历史 ----------------
# EventBridge 规则 dcv-instance-state-change 将 EC2 状态变更写入该日志组
STATE_LOG_GROUP = os.getenv("DCV_STATE_LOG_GROUP", "/aws/events/dcv-instance-state")

# ---------------- 巡检 ----------------
# 后台自动巡检间隔（分钟）；0 表示关闭
INSPECT_INTERVAL_MIN = int(_get("inspect_interval_min", "DCV_INSPECT_INTERVAL_MIN", "10"))
# 运行中但无人连接超过该时长（小时）标记为"闲置"，用于提醒关机节省费用
IDLE_HOURS = float(_get("idle_hours", "DCV_IDLE_HOURS", "2"))
# 单次批量从快照创建实例的上限
MAX_LAUNCH_COUNT = int(os.getenv("DCV_MAX_LAUNCH_COUNT", "20"))

# ---------------- 用户管理：AWS Cognito ----------------
# 配置了 POOL 与 CLIENT 即启用 Cognito 认证；否则回退到简单口令认证
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "")
# 用户池所在区域由用户池 ID 前缀决定（与服务器所在区域无关，切换区域不影响登录）
COGNITO_REGION = os.getenv("COGNITO_REGION") or (COGNITO_USER_POOL_ID.split("_")[0] if "_" in COGNITO_USER_POOL_ID else AWS_REGION)


def cognito_enabled() -> bool:
    return bool(COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID)

# ---------------- S3 共享盘 ----------------
# 服务器实例角色名（其实例配置文件由 LAUNCH_PROFILE 指定）；共享盘的 S3 权限策略附加到该角色
INSTANCE_ROLE_NAME = _get("instance_role", "DCV_INSTANCE_ROLE", "")
# 客户端组件（固定版本并校验 SHA256，从官方发布地址下载）
RCLONE_VERSION = "v1.75.1"
RCLONE_URL = f"https://github.com/rclone/rclone/releases/download/{RCLONE_VERSION}/rclone-{RCLONE_VERSION}-windows-amd64.zip"
RCLONE_SHA256 = "200eb602c126d82aa38b51e0f6b9ae837473ff99b51278d3f6f837574c494d6e"
WINFSP_URL = "https://github.com/winfsp/winfsp/releases/download/v2.1/winfsp-2.1.25156.msi"
WINFSP_SHA256 = "073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a"
# 主机上的安装与数据目录（仅 SYSTEM/管理员可写）
SHARE_ROOT = r"C:\ProgramData\dcv-share"
