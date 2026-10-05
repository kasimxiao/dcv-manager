"""开机显卡自检（主机侧 SYSTEM 计划任务 \\DCV\\DCV-GPU-Guard）。

背景：同一镜像换到不同显卡的机型（g6f 的 L4 分片 ↔ g4dn 的 T4 ↔ g5 的 A10G）后首次开机，
Windows 识别到新显卡后需要几分钟配置驱动，期间设备状态为 CM_PROB_REINSTALL，DCV 能连但没有 GPU 加速；
实测多数在 5–10 分钟内自行恢复，个别情况需要重启一次。AWS GRID 驱动本身同时支持这几种显卡，无需另装驱动。

自检逻辑（每次开机）：
  1. 开机后持续观察 5 分钟，检查在位的 NVIDIA 设备是否出现问题码（问题通常在开机 1–2 分钟后才出现）
  2. 有问题先执行 pnputil /scan-devices，并等待最多 10 分钟让 Windows 自行装好驱动（实测通常几分钟内自动恢复）
  3. 仍有问题且本机型尚未因此重启过 → 记录并重启一次（防止循环重启）
  4. 正常时清除重启记录，记录当前机型
日志：C:\\ProgramData\\dcv-gpu\\guard.log
"""
import aws_service

TASK = r"\DCV\DCV-GPU-Guard"
DIR = r"C:\ProgramData\dcv-gpu"
VERSION = "3"

_GUARD = r"""
$ErrorActionPreference = 'SilentlyContinue'
$dir = 'C:\ProgramData\dcv-gpu'
function Log($m) { Add-Content "$dir\guard.log" ("{0:s} {1}" -f (Get-Date), $m) }
function Bad { @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'PCI\VEN_10DE*' -and $_.Problem -and "$($_.Problem)" -ne 'CM_PROB_NONE' }) }
# Windows 识别新显卡后要过一两分钟才把设备标记为需要重新安装，因此开机后持续观察 5 分钟
$deadline = (Get-Date).AddMinutes(5)
Start-Sleep 30
do { $b = Bad; if ($b.Count) { break }; Start-Sleep 15 } while ((Get-Date) -lt $deadline)
$tok = Invoke-RestMethod -Method Put -Uri 'http://169.254.169.254/latest/api/token' -Headers @{'X-aws-ec2-metadata-token-ttl-seconds'='60'}
$type = Invoke-RestMethod -Uri 'http://169.254.169.254/latest/meta-data/instance-type' -Headers @{'X-aws-ec2-metadata-token'=$tok}
if (-not $b.Count) {
  Remove-Item "$dir\rebooted-*" -Force
  Set-Content "$dir\last-ok" "$type"
  Log "OK $type"
  exit 0
}
Log ("$type 显卡未就绪：" + (($b | ForEach-Object { "$($_.FriendlyName)[$($_.Problem)]" }) -join ', '))
# 多数情况下 Windows 会在几分钟内自行装好驱动，先等待最多 10 分钟，避免不必要的重启
pnputil /scan-devices | Out-Null
$until = (Get-Date).AddMinutes(10)
do { Start-Sleep 20; if (-not (Bad).Count) { Remove-Item "$dir\rebooted-*" -Force; Set-Content "$dir\last-ok" "$type"; Log "已自动就绪 $type"; exit 0 } } while ((Get-Date) -lt $until)
if (Test-Path "$dir\rebooted-$type") { Log "已为 $type 重启过一次仍未就绪，不再重启"; exit 1 }
Set-Content "$dir\rebooted-$type" (Get-Date -Format s)
Log "重启以加载 $type 的显卡驱动"
Restart-Computer -Force
"""


def install_commands():
    """返回安装/更新自检任务的 PowerShell 命令（幂等）。"""
    body = _GUARD.strip().replace("'", "''")
    return [
        "$ErrorActionPreference = 'Stop'",
        f"$d = '{DIR}'; New-Item -ItemType Directory -Force -Path $d | Out-Null",
        # 目录仅 SYSTEM 与管理员可写，防止普通用户篡改以 SYSTEM 运行的脚本
        "icacls $d /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null",
        f"[IO.File]::WriteAllText(\"$d\\gpu-guard.ps1\", '{body}', [Text.Encoding]::UTF8)",
        f"Set-Content \"$d\\version\" '{VERSION}'",
        "$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument \"-NoProfile -ExecutionPolicy Bypass -File $d\\gpu-guard.ps1\"",
        "$t = New-ScheduledTaskTrigger -AtStartup",
        "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest",
        "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -AllowStartIfOnBatteries",
        "Register-ScheduledTask -TaskPath '\\DCV\\' -TaskName 'DCV-GPU-Guard' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null",
        "Write-Output 'GPU_GUARD_OK'",
    ]


def install(instance_id):
    r = aws_service.run_powershell(instance_id, install_commands(), timeout=90)
    ok = r.get("status") == "Success" and "GPU_GUARD_OK" in (r.get("stdout") or "")
    return ok, (r.get("stderr") or r.get("stdout") or r.get("status") or "")[:300]


def status_snippet():
    """巡检脚本片段：自检任务是否就绪，以及显卡是否有问题。"""
    return [
        f"$r.gpu_guard = [bool]((Get-Content '{DIR}\\version' -ErrorAction SilentlyContinue) -eq '{VERSION}' -and (Get-ScheduledTask -TaskPath '\\DCV\\' -TaskName 'DCV-GPU-Guard' -ErrorAction SilentlyContinue))",
        "$r.gpu_problem = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'PCI\\VEN_10DE*' -and $_.Problem -and \"$($_.Problem)\" -ne 'CM_PROB_NONE' } | ForEach-Object { \"$($_.FriendlyName)[$($_.Problem)]\" }) -join ', '",
    ]
