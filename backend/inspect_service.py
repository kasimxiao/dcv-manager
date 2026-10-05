"""批量巡检与合规核对。

一次 SSM 命令最多下发给 50 台主机，收集：
DCV 服务/会话/连接数、权限文件、开机自动会话配置、GPU/CPU/内存/磁盘、属主是否为管理员等。
再与平台记录的"期望状态"（permissions 表中的规格 + 会话属主）比对得出合规结论。
"""
import json
import time
import datetime as dt
import concurrent.futures as cf

import aws_service
from config import DCV_EXE, DCV_PERM_PATH
from dcv_service import build_perm_content

_MARK = "###JSON###"

_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$dcv = '__DCV_EXE__'
$r = [ordered]@{}
$r.dcv_service = "$((Get-Service dcvserver).Status)"
try {
  $j = (& $dcv describe-session console --json 2>$null | Out-String) | ConvertFrom-Json
  $r.session_owner = $j.owner
  $r.connections = [int]$j.'num-of-connections'
  $r.session_created = $j.'creation-time'
  $r.last_disconnect = $j.'last-disconnection-time'
  $r.license = "$(($j.licenses | Select-Object -First 1).status)"
} catch { $r.session_owner = $null }
$pf = '__PERM__'
if (Test-Path $pf) { $r.perm_file = [IO.File]::ReadAllText($pf) } else { $r.perm_file = $null }
$reg = 'Registry::HKEY_USERS\S-1-5-18\Software\GSettings\com\nicesoftware\dcv\session-management\automatic-console-session'
$p = Get-ItemProperty $reg
$r.auto_owner = $p.owner
$r.auto_perm = $p.'permissions-file'
$g = & "$env:SystemRoot\System32\nvidia-smi.exe" --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>$null
if ($g) { $a = ("$($g | Select-Object -First 1)").Split(','); $r.gpu_util = [int]$a[0]; $r.gpu_mem_used = [int]$a[1]; $r.gpu_mem_total = [int]$a[2] }
$r.cpu = [int](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
$os = Get-CimInstance Win32_OperatingSystem
$r.mem_total_mb = [int]($os.TotalVisibleMemorySize / 1024)
$r.mem_free_mb = [int]($os.FreePhysicalMemory / 1024)
$r.boot_time = $os.LastBootUpTime.ToUniversalTime().ToString('o')
$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$r.disk_total_gb = [math]::Round($d.Size / 1GB, 1)
$r.disk_free_gb = [math]::Round($d.FreeSpace / 1GB, 1)
$admins = @((Get-LocalGroupMember -SID S-1-5-32-544).Name)
$r.owner_is_admin = [bool]($r.session_owner -and ($admins | Where-Object { $_ -like "*\$($r.session_owner)" }))
$ver = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -like '*DCV*Server*' } | Select-Object -First 1
$r.dcv_version = "$($ver.DisplayVersion)"
'__MARK__' + ($r | ConvertTo-Json -Compress -Depth 5)
"""


def _commands():
    import share_service
    s = _SCRIPT.replace("__DCV_EXE__", DCV_EXE).replace("__PERM__", DCV_PERM_PATH).replace("__MARK__", _MARK)
    lines = [ln for ln in s.strip().splitlines() if ln.strip()]
    # 共享盘状态在输出 JSON 之前采集
    import gpu_guard
    return lines[:-1] + share_service.status_snippet() + gpu_guard.status_snippet() + lines[-1:]


def _parse(stdout):
    if _MARK not in stdout:
        return None
    raw = stdout.split(_MARK, 1)[1].strip()
    try:
        return json.loads(raw)
    except ValueError:
        return None


def inspect_many(instance_ids, timeout=120, on_result=None):
    """批量巡检（多区域并行，每个区域单独下发）。返回 {instance_id: data | {"error": ...}}；每台完成时回调 on_result(iid, data)。"""
    groups = aws_service.group_by_region(list(instance_ids))
    results = {}
    with cf.ThreadPoolExecutor(max_workers=max(1, len(groups))) as ex:
        for part in ex.map(lambda kv: _inspect_region(kv[0], kv[1], timeout, on_result), groups.items()):
            results.update(part)
    return results


def _inspect_region(region, ids, timeout, on_result):
    ssm = aws_service.client("ssm", region)
    results = {}
    for i in range(0, len(ids), 50):
        chunk = ids[i:i + 50]
        cmd_id = ssm.send_command(
            InstanceIds=chunk, DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": _commands()}, TimeoutSeconds=60,
            Comment="dcv-manager inspection",
        )["Command"]["CommandId"]
        pending = set(chunk)
        deadline = time.time() + timeout
        time.sleep(3)
        while pending and time.time() < deadline:
            done = []
            paginator = ssm.get_paginator("list_command_invocations")
            for page in paginator.paginate(CommandId=cmd_id):
                for inv in page.get("CommandInvocations", []):
                    if inv["InstanceId"] in pending and inv["Status"] not in ("Pending", "InProgress", "Delayed"):
                        done.append((inv["InstanceId"], inv["Status"]))
            # 完成的逐台取完整输出（列表接口只返回前 2500 字符）
            def fetch(item):
                iid, status = item
                try:
                    out = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
                    data = _parse(out.get("StandardOutputContent", ""))
                except Exception as e:  # noqa: BLE001
                    return iid, {"error": f"读取结果失败: {e}"}
                return iid, data if data else {"error": f"巡检脚本未返回结果（{status}）"}
            with cf.ThreadPoolExecutor(max_workers=8) as ex:
                for iid, data in ex.map(fetch, done):
                    results[iid] = data
                    pending.discard(iid)
                    if on_result:
                        on_result(iid, data)
            if pending:
                time.sleep(3)
        for iid in pending:
            results[iid] = {"error": "巡检超时"}
            if on_result:
                on_result(iid, results[iid])
            try:
                ssm.cancel_command(CommandId=cmd_id, InstanceIds=[iid])
            except Exception:  # noqa: BLE001
                pass
    return results


def _norm(text):
    return [ln.strip() for ln in (text or "").replace("\r", "").split("\n") if ln.strip()]


def _ts(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def evaluate(inst, insp, spec, owner, binding):
    """合规与健康评估。

    compliance: compliant 合规 / drift 偏离 / unmanaged 未纳管权限 / unknown 无法判断
    health:     ok / warn / critical / unknown
    """
    reasons, alerts = [], []
    running = inst.get("state") == "running"

    if binding and binding.get("outdated"):
        reasons.append("模板已更新，需重新应用")

    if not running:
        compliance = "unknown"
    elif not insp or insp.get("error"):
        compliance = "unknown"
        if insp and insp.get("error"):
            alerts.append(("warn", f"巡检失败：{insp['error']}"))
    elif spec is None:
        compliance = "unmanaged"
    else:
        want = build_perm_content(spec)
        if _norm(insp.get("perm_file")) != _norm(want):
            reasons.append("主机权限文件与期望配置不一致")
        if owner and insp.get("session_owner") != owner:
            reasons.append(f"当前会话属主为 {insp.get('session_owner') or '无'}，期望 {owner}")
        if owner and insp.get("auto_owner") != owner:
            reasons.append("开机自动会话属主未配置，重启后用户可能无法连接")
        if (insp.get("auto_perm") or "").lower() != DCV_PERM_PATH.lower():
            reasons.append("开机自动会话未绑定权限文件，重启后权限失效")
        compliance = "drift" if reasons else "compliant"

    if running:
        if inst.get("ssm") and inst["ssm"] != "Online":
            alerts.append(("warn", "SSM 代理离线，无法远程管理"))
        if insp and not insp.get("error"):
            if insp.get("dcv_service") != "Running":
                alerts.append(("critical", f"DCV 服务未运行（{insp.get('dcv_service') or '未安装'}）"))
            so = insp.get("session_owner")
            if not so or so.upper() == "SYSTEM":
                alerts.append(("critical", "没有属于登录用户的会话，用户连接会提示 No sessions available"))
            if insp.get("disk_free_gb") is not None and insp["disk_free_gb"] < 5:
                alerts.append(("warn", f"系统盘剩余空间不足（{insp['disk_free_gb']} GB）"))
            if insp.get("owner_is_admin"):
                alerts.append(("warn", "会话用户是本地管理员，可自行绕过 DCV 权限"))
            if insp.get("license") and insp["license"] != "licensed":
                alerts.append(("warn", f"DCV 授权状态异常：{insp['license']}"))
            if insp.get("gpu_problem"):
                alerts.append(("critical", f"显卡驱动未就绪（{insp['gpu_problem']}），DCV 无 GPU 加速。换机型后首次开机常见，通常 5–10 分钟内自动就绪，开机显卡自检会在必要时自动重启一次"
                                           + ("" if insp.get("gpu_guard") else "；该主机尚未部署开机显卡自检")))

    levels = [a[0] for a in alerts]
    health = "critical" if "critical" in levels else ("warn" if "warn" in levels else ("ok" if running and insp and not insp.get("error") else "unknown"))

    idle_since = None
    if running and insp and not insp.get("error") and insp.get("connections") == 0:
        idle_since = max(filter(None, [_ts(insp.get("last_disconnect")), _ts(insp.get("session_created"))]), default=None)

    return {
        "compliance": compliance,
        "compliance_reasons": reasons,
        "health": health,
        "alerts": [{"level": lv, "message": m} for lv, m in alerts],
        "idle_since": idle_since,
    }
