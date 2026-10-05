"""DCV 权限服务：根据权限规格生成 permissions 文件，通过 SSM 下发到实例，
并重建 console 会话使其生效。

权限规格 spec: {feature_key: rule}，rule ∈ {allow, disallow, deny}
说明：规则应用于 %any%（所有连接用户，包括会话属主），
因此不使用 "%owner% allow builtin"，否则属主会绕过全部限制。
"""
import base64
import re

from config import DCV_EXE, DCV_PERM_PATH, DCV_DEFAULT_OWNER
from dcv_features import ALL_FEATURE_KEYS, DEFAULT_SPEC
import aws_service
import db


def build_perm_content(spec: dict) -> str:
    """将权限规格转换为 DCV permissions 文件文本。"""
    buckets = {"allow": [], "disallow": [], "deny": []}
    for key in ALL_FEATURE_KEYS:
        rule = spec.get(key, DEFAULT_SPEC.get(key, "allow"))
        if rule not in buckets:
            rule = "allow"
        buckets[rule].append(key)
    lines = ["[permissions]"]
    for rule in ("allow", "disallow", "deny"):
        feats = buckets[rule]
        if feats:
            lines.append(f"%any% {rule} " + " ".join(feats))
    return "\r\n".join(lines) + "\r\n"


@aws_service.in_instance_region
def _detect_owner(instance_id: str) -> str:
    """探测 console 会话当前属主，优先使用；否则用元数据或默认值。"""
    meta = db.get_meta(instance_id)
    if meta and meta.get("owner"):
        return meta["owner"]
    res = aws_service.run_powershell(
        instance_id,
        [f'& "{DCV_EXE}" list-sessions 2>&1'],
        timeout=30,
    )
    m = re.search(r"owner:(\S+)", res.get("stdout", ""))
    if m:
        owner = m.group(1)
        if owner and owner.upper() != "SYSTEM":
            return owner
    return DCV_DEFAULT_OWNER


@aws_service.in_instance_region
def apply_permissions(instance_id: str, spec: dict, owner: str = None) -> dict:
    """下发权限并重建 console 会话。返回执行结果。"""
    content = build_perm_content(spec)
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    if not owner:
        owner = _detect_owner(instance_id)

    perm_dir = DCV_PERM_PATH.rsplit("\\", 1)[0]
    # 注意：Windows 版 DCV 以 SYSTEM 运行，读取的是 HKEY_USERS\S-1-5-18 下的配置，
    # 而非 HKLM。这里同步写入开机自动会话的属主与权限文件，保证实例重启后会话仍按此配置创建。
    reg = r"Registry::HKEY_USERS\S-1-5-18\Software\GSettings\com\nicesoftware\dcv\session-management"
    commands = [
        f'$dcv = "{DCV_EXE}"',
        f'New-Item -Path "{perm_dir}" -ItemType Directory -Force | Out-Null',
        f'$b64 = "{b64}"',
        '$txt = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))',
        f'Set-Content -Path "{DCV_PERM_PATH}" -Value $txt -Encoding ASCII',
        f'New-Item -Path "{reg}\\automatic-console-session" -Force | Out-Null',
        f'Set-ItemProperty -Path "{reg}" -Name create-session -Value 1 -Type DWord',
        f'Set-ItemProperty -Path "{reg}\\automatic-console-session" -Name owner -Value "{owner}" -Type String',
        f'Set-ItemProperty -Path "{reg}\\automatic-console-session" -Name permissions-file -Value "{DCV_PERM_PATH}" -Type String',
        '& $dcv close-session console 2>&1',
        'Start-Sleep -Seconds 2',
        f'& $dcv create-session --type=console --owner {owner} --permissions-file "{DCV_PERM_PATH}" console 2>&1',
        'Start-Sleep -Seconds 2',
        'Write-Output "===SESSIONS==="',
        '& $dcv list-sessions 2>&1',
        'Write-Output "===PERMFILE==="',
        f'Get-Content "{DCV_PERM_PATH}"',
    ]
    res = aws_service.run_powershell(instance_id, commands)
    out = res.get("stdout", "")
    # 核对：主机上读回的权限文件必须与下发内容一致，且 console 会话已按属主重建
    host_perm = out.split("===PERMFILE===", 1)[1] if "===PERMFILE===" in out else ""
    norm = lambda s: [ln.strip() for ln in s.replace("\r", "").split("\n") if ln.strip()]
    file_ok = norm(host_perm) == norm(content)
    session_ok = f"owner:{owner} type:console" in out
    verified = res["status"] == "Success" and file_ok and session_ok
    # 保存规格与属主
    db.save_permission_spec(instance_id, spec)
    db.save_meta(instance_id, owner=owner)
    restricted = [k for k in ALL_FEATURE_KEYS if spec.get(k, DEFAULT_SPEC.get(k)) != "allow"]
    return {
        "ok": res["status"] == "Success",
        "verified": verified,
        "file_ok": file_ok,
        "session_ok": session_ok,
        "restricted": restricted,
        "status": res["status"],
        "output": out,
        "error": res["stderr"],
        "owner": owner,
        "perm_content": content,
    }


@aws_service.in_instance_region
def get_live_status(instance_id: str) -> dict:
    """读取实例上的 DCV 服务状态与会话列表。"""
    commands = [
        '$dcv = "%s"' % DCV_EXE,
        'Write-Output "===SERVICE==="',
        '(Get-Service dcvserver -ErrorAction SilentlyContinue).Status',
        'Write-Output "===SESSIONS==="',
        '& $dcv list-sessions 2>&1',
    ]
    res = aws_service.run_powershell(instance_id, commands, timeout=40)
    out = res.get("stdout", "")
    service = ""
    sessions = ""
    if "===SERVICE===" in out:
        try:
            service = out.split("===SERVICE===")[1].split("===SESSIONS===")[0].strip()
        except IndexError:
            pass
    if "===SESSIONS===" in out:
        sessions = out.split("===SESSIONS===")[1].strip()
    return {"status": res["status"], "service": service, "sessions": sessions, "raw": out}


# ---------------- 重置 Windows / DCV 登录密码 ----------------
import uuid  # noqa: E402


_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,20}$")


def validate_windows_password(pw: str, username: str):
    """按 Windows 默认复杂度策略预检，返回错误信息或 None。"""
    if len(pw) < 12 or len(pw) > 127:
        return "密码长度需为 12–127 位"
    cats = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if cats < 3:
        return "密码需包含大写字母、小写字母、数字、符号中的至少三类"
    low = pw.lower()
    # Windows 规则：不得包含账户名或全名中长度≥3 的片段
    for bad in {username.lower(), "dcv", "user", "remote", "access"}:
        if len(bad) >= 3 and bad in low:
            return f"密码不能包含「{bad}」（Windows 复杂度策略会拒绝）"
    return None


@aws_service.in_instance_region
def reset_password(instance_id: str, password: str, username: str = None) -> dict:
    """通过 SSM 重置实例上本地用户的密码。

    明文密码只经过 SSM Parameter Store（SecureString，KMS 加密）中转：
    实例用自身角色读取后立即删除，SSM 命令历史中只出现参数名。
    """
    username = username or _detect_owner(instance_id)
    if not _USERNAME_RE.match(username):
        raise ValueError("用户名不合法")
    err = validate_windows_password(password, username)
    if err:
        raise ValueError(err)

    ssm = aws_service.ssm
    pname = f"/dcv-manager/pwreset/{instance_id}/{uuid.uuid4().hex}"
    ssm.put_parameter(Name=pname, Value=password, Type="SecureString", Overwrite=True)
    try:
        commands = [
            '$ErrorActionPreference = "Stop"',
            'Import-Module AWSPowerShell -ErrorAction SilentlyContinue',
            f'$v = (Get-SSMParameter -Name "{pname}" -WithDecryption $true -Region {aws_service.current_region()}).Value',
            '$sp = ConvertTo-SecureString $v -AsPlainText -Force',
            f'Set-LocalUser -Name "{username}" -Password $sp',
            'Add-Type -AssemblyName System.DirectoryServices.AccountManagement',
            '$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext("Machine")',
            f'if ($pc.ValidateCredentials("{username}", $v)) {{ "RESET_OK" }} else {{ "VALIDATE_FAIL" }}',
            'Remove-Variable v, sp',
        ]
        res = aws_service.run_powershell(instance_id, commands, timeout=150)
        if res["status"] == "Timedout" and res.get("command_id"):
            # 命令仍在排队/执行：先取消，避免实例稍后执行时读到已删除的参数
            try:
                ssm.cancel_command(CommandId=res["command_id"], InstanceIds=[instance_id])
            except Exception:  # noqa: BLE001
                pass
    finally:
        try:
            ssm.delete_parameter(Name=pname)
        except Exception:  # noqa: BLE001
            pass

    ok = res["status"] == "Success" and "RESET_OK" in res["stdout"]
    error = ""
    if not ok:
        raw = (res.get("stderr") or "") + (res.get("stdout") or "")
        if res["status"] == "Timedout":
            error = "主机响应超时（可能刚开机仍在启动），请稍后重试"
        elif "complexity" in raw or "requirements" in raw:
            error = "密码不符合该主机的密码策略"
        elif "was not found" in raw:
            error = f"主机上不存在用户 {username}"
        else:
            error = raw.strip()[-300:] or res["status"]
    return {"ok": ok, "username": username, "error": error}
