<powershell>
# ============================================================
# DCV Windows 主机初始化脚本（加固版）
# 自动安装: NVIDIA GRID 驱动 + VC++2022 运行库 + Amazon DCV Server
# 创建标准用户 dcvuser（非管理员），配置自动 console 会话
# ------------------------------------------------------------
# 使用方法（示例）：
#   1) 修改下面的 $DcvPassword 为你的强口令
#      注意：口令中不要包含 "dcv" / "user" 字样，否则会触发 Windows 复杂度策略被拒
#   2) aws ec2 run-instances ... --user-data file://dcv-bootstrap.ps1
# 安全要点：dcvuser 仅加入 "Remote Desktop Users"，不加入 Administrators，
#          因此用户无法自行修改 DCV 权限，只能由管理平台通过 SSM 集中下发。
# ============================================================
$ErrorActionPreference = "Continue"
$DcvPassword = "CHANGE_ME_Str0ng#Pass27"   # <<< 请修改为你的强口令（勿含 dcv/user）

$log = "C:\dcv-setup.log"
function Log($m){ "$(Get-Date -Format o)  $m" | Out-File -FilePath $log -Append -Encoding utf8 }
Log "=== DCV bootstrap start (hardened) ==="

# 1. 创建 DCV 登录用户（标准用户，非管理员）
$pw = ConvertTo-SecureString $DcvPassword -AsPlainText -Force
try {
  New-LocalUser -Name "dcvuser" -Password $pw -FullName "Remote Access" -Description "DCV standard user" -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop
  Add-LocalGroupMember -Group "Remote Desktop Users" -Member "dcvuser" -ErrorAction SilentlyContinue
  Log "user dcvuser created (standard, non-admin)"
} catch { Log "user create: $_" }

# 2. NVIDIA GRID 驱动（从 S3 下载，需实例角色具备 S3 读权限）
try {
  $Bucket="ec2-windows-nvidia-drivers"; $KeyPrefix="latest"; $Local="C:\nvidia"
  New-Item -Path $Local -ItemType Directory -Force | Out-Null
  Import-Module AWSPowerShell -ErrorAction SilentlyContinue
  $objs = Get-S3Object -BucketName $Bucket -KeyPrefix $KeyPrefix -Region us-east-1
  foreach($o in $objs){ if($o.Size -gt 0){ $f=Join-Path $Local (Split-Path $o.Key -Leaf); Copy-S3Object -BucketName $Bucket -Key $o.Key -LocalFile $f -Region us-east-1 } }
  $exe = Get-ChildItem -Path $Local -Filter *.exe -Recurse | Select-Object -First 1
  if($exe){ Start-Process -FilePath $exe.FullName -ArgumentList "-s -clean -noreboot" -Wait; Log "NVIDIA driver installed" } else { Log "NVIDIA exe not found" }
} catch { Log "nvidia: $_" }

# 3. Visual C++ 2022 运行库（DCV 2024+ 依赖）
try {
  $vc="C:\vc_redist.x64.exe"
  Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vc -UseBasicParsing
  Start-Process -FilePath $vc -ArgumentList "/quiet /norestart" -Wait
  Log "VC++ redist installed"
} catch { Log "vcredist: $_" }

# 4. Amazon DCV Server
try {
  $msi="C:\dcv-server.msi"
  Invoke-WebRequest -Uri "https://d1uj6qtbmh3dt5.cloudfront.net/nice-dcv-server-x64-Release.msi" -OutFile $msi -UseBasicParsing
  Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /quiet /norestart ADDLOCAL=ALL /l*v C:\dcv-install.log" -Wait
  Log "DCV server installed"
} catch { Log "dcv install: $_" }

# 5. DCV 配置：8443 端口 / system 认证 / 自动 console 会话属主=dcvuser
#    注意：Windows 版 DCV 以 SYSTEM 运行，读取 HKEY_USERS\S-1-5-18 下的配置（写到 HKLM 不生效，
#    会导致开机后 console 会话属主变成 SYSTEM，用户连接时提示 "No sessions available"）
try {
  $base="Registry::HKEY_USERS\S-1-5-18\Software\GSettings\com\nicesoftware\dcv"
  New-Item -Path "$base\connectivity" -Force | Out-Null
  New-ItemProperty -Path "$base\connectivity" -Name "web-port" -Value 8443 -PropertyType DWord -Force | Out-Null
  New-Item -Path "$base\security" -Force | Out-Null
  New-ItemProperty -Path "$base\security" -Name "authentication" -Value "system" -PropertyType String -Force | Out-Null
  New-Item -Path "$base\session-management" -Force | Out-Null
  New-ItemProperty -Path "$base\session-management" -Name "create-session" -Value 1 -PropertyType DWord -Force | Out-Null
  New-Item -Path "$base\session-management\automatic-console-session" -Force | Out-Null
  New-ItemProperty -Path "$base\session-management\automatic-console-session" -Name "owner" -Value "dcvuser" -PropertyType String -Force | Out-Null
  Log "DCV configured"
} catch { Log "dcv config: $_" }

# 6. 权限文件目录（仅管理员/SYSTEM 可写，标准用户只读，防止用户篡改）
try {
  New-Item -Path "C:\dcv" -ItemType Directory -Force | Out-Null
  icacls "C:\dcv" /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
  Log "perm dir ACL hardened"
} catch { Log "acl: $_" }

# 7. 防火墙放行 DCV 8443
try {
  New-NetFirewallRule -DisplayName "DCV TCP 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -ErrorAction SilentlyContinue | Out-Null
  New-NetFirewallRule -DisplayName "DCV UDP 8443" -Direction Inbound -Protocol UDP -LocalPort 8443 -Action Allow -ErrorAction SilentlyContinue | Out-Null
  Log "firewall rules added"
} catch { Log "firewall: $_" }

# 8. 服务自启 + 重启加载 GPU 驱动
try { Set-Service -Name dcvserver -StartupType Automatic } catch {}
Log "=== bootstrap done, rebooting ==="
Restart-Computer -Force
</powershell>
<persist>false</persist>
