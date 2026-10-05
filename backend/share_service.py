"""S3 共享盘。

授权：每个共享盘一份（或多份）托管 IAM 策略，附加在服务器实例角色上。
  - 适用范围「指定服务器」时，用 aws:userid 条件限定到具体实例（EC2 角色会话的 userid 为 “角色ID:实例ID”）。
  - 只读盘只授予读取与列举权限；即使主机上的挂载参数被改动，S3 也会拒绝写入。
挂载：rclone + WinFsp，以 SYSTEM 身份运行的计划任务挂载为盘符，所有登录用户可见；开机自动挂载、异常退出自动重启。
"""
import base64
import concurrent.futures as cf
import hashlib
import json
import re

import aws_service
from config import (AWS_REGION, INSTANCE_ROLE_NAME, LAUNCH_PROFILE, RCLONE_SHA256, RCLONE_URL,
                    SHARE_ROOT, WINFSP_SHA256, WINFSP_URL)

iam = aws_service._session.client("iam")
_s3 = {}

BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
DRIVES = [chr(c) for c in range(ord("E"), ord("Z") + 1)]
MAX_TARGETS_PER_POLICY = 110  # 托管策略最多 6144 字符，每台服务器约占 44 字符
RO_ACTIONS = ["s3:GetObject", "s3:GetObjectVersion"]
RW_ACTIONS = RO_ACTIONS + ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
_role_id = None


def s3(region=AWS_REGION):
    if region not in _s3:
        _s3[region] = aws_service._session.client("s3", region_name=region)
    return _s3[region]


def role_id():
    global _role_id
    if _role_id is None:
        _role_id = iam.get_role(RoleName=INSTANCE_ROLE_NAME)["Role"]["RoleId"]
    return _role_id


# ---------------- 校验 ----------------

def clean_prefix(p):
    p = (p or "").strip().strip("/")
    if ".." in p.split("/") or "\\" in p or "*" in p or "?" in p:
        raise ValueError("路径前缀不合法")
    return p


def validate(share, others):
    if not share.get("name", "").strip():
        raise ValueError("请填写名称")
    if not BUCKET_RE.match(share.get("bucket", "")):
        raise ValueError("存储桶名称不合法（3–63 位小写字母、数字、点或连字符）")
    if share.get("drive") not in DRIVES:
        raise ValueError("盘符需为 E–Z")
    if share.get("mode") not in ("ro", "rw"):
        raise ValueError("访问方式不合法")
    if share.get("scope") not in ("all", "selected"):
        raise ValueError("适用范围不合法")
    if not 1 <= int(share.get("cache_gb") or 0) <= 500:
        raise ValueError("本地缓存需在 1–500 GB 之间")
    for o in others:
        if o["drive"] == share["drive"]:
            raise ValueError(f"盘符 {share['drive']}: 已被共享盘「{o['name']}」使用")
        if o["bucket"] == share["bucket"]:
            a, b = o["prefix"], share["prefix"]
            if a == b or not a or not b or a.startswith(b + "/") or b.startswith(a + "/"):
                where = f"s3://{o['bucket']}/{a}" if a else f"整个存储桶 {o['bucket']}"
                raise ValueError(f"该路径与共享盘「{o['name']}」（{where}）重叠。同一存储桶内的共享盘路径不能相互包含，"
                                 "否则无法按服务器分别授权")


# ---------------- S3 存储桶 ----------------

def list_buckets():
    names = [b["Name"] for b in s3().list_buckets().get("Buckets", [])][:300]

    def region_of(n):
        try:
            loc = s3().get_bucket_location(Bucket=n).get("LocationConstraint")
            return n, loc or "us-east-1"
        except Exception:  # noqa: BLE001
            return n, None
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        return [{"name": n, "region": r} for n, r in ex.map(region_of, names) if r]


def bucket_region(bucket):
    try:
        loc = s3().get_bucket_location(Bucket=bucket).get("LocationConstraint")
    except s3().exceptions.NoSuchBucket:
        raise ValueError(f"存储桶 {bucket} 不存在")
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"无法访问存储桶 {bucket}：{e}")
    return loc or "us-east-1"


def create_bucket(bucket, region, versioning=True):
    c = s3(region)
    kw = {"Bucket": bucket}
    if region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        c.create_bucket(**kw)
    except c.exceptions.BucketAlreadyOwnedByYou:
        raise ValueError(f"存储桶 {bucket} 已存在，请选择「使用已有存储桶」")
    except c.exceptions.BucketAlreadyExists:
        raise ValueError(f"存储桶名称 {bucket} 已被其他 AWS 账号占用，请换一个名称")
    c.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    c.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "dcv:share", "Value": "true"}]})
    if versioning:
        # 版本控制可找回误删/误改的文件；旧版本保留 30 天后自动清理，控制存储费用
        c.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        c.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [{
            "ID": "dcv-share-noncurrent-30d", "Status": "Enabled", "Filter": {},
            "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]})


# ---------------- IAM 授权 ----------------

def policy_documents(share, target_ids):
    """返回策略文档列表（每个共享盘一份）。

    放行语句不带服务器条件；「指定服务器」时追加一条拒绝语句，拒绝名单外的服务器访问该路径。
    名单只出现一次，单份策略可容纳约 110 台服务器（托管策略上限 6144 字符）。
    拒绝语句只覆盖本共享盘的存储路径，validate() 保证同一存储桶内各共享盘路径互不重叠。
    """
    b, p = share["bucket"], share["prefix"]
    obj_res = [f"arn:aws:s3:::{b}/{p}/*", f"arn:aws:s3:::{b}/{p}"] if p else [f"arn:aws:s3:::{b}/*"]
    prefix_like = [p, f"{p}/", f"{p}/*"] if p else None
    actions = RW_ACTIONS if share["mode"] == "rw" else RO_ACTIONS
    if share["scope"] == "selected":
        ids = sorted(set(target_ids))
        if not ids:
            return []
        if len(ids) > MAX_TARGETS_PER_POLICY:
            raise ValueError(f"单个共享盘最多指定 {MAX_TARGETS_PER_POLICY} 台服务器，超过时请把适用范围设为「全部服务器」")
    st = [
        {"Sid": "List", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{b}",
         **({"Condition": {"StringLike": {"s3:prefix": prefix_like}}} if p else {})},
        {"Sid": "Objects", "Effect": "Allow", "Action": actions, "Resource": obj_res},
        {"Sid": "Location", "Effect": "Allow", "Action": ["s3:GetBucketLocation"], "Resource": f"arn:aws:s3:::{b}"},
    ]
    if share.get("kms_key"):
        st.append({"Sid": "Kms", "Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": share["kms_key"]})
    if share["scope"] == "selected":
        cond = {"StringNotEquals": {"aws:userid": [f"{role_id()}:{i}" for i in ids]}}
        if p:
            # 对象请求没有 s3:prefix，IfExists 使其同样被拒绝；列举本路径以外的请求不受影响
            cond["StringLikeIfExists"] = {"s3:prefix": prefix_like}
        st.append({"Sid": "OnlyAuthorizedServers", "Effect": "Deny", "Action": ["s3:ListBucket", *RW_ACTIONS],
                   "Resource": [f"arn:aws:s3:::{b}", *obj_res], "Condition": cond})
    doc = {"Version": "2012-10-17", "Statement": st}
    if len(json.dumps(doc, separators=(",", ":"))) > 6000:
        raise ValueError("授权服务器过多，超出 IAM 策略大小限制，请改用「全部服务器」范围")
    return [doc]


def _account():
    return aws_service.account_id()


def _policy_arn(share_id, n):
    return f"arn:aws:iam::{_account()}:policy/dcv-manager/dcv-share-{share_id}-{n}"


def _attached():
    out, marker = set(), None
    while True:
        kw = {"RoleName": INSTANCE_ROLE_NAME}
        if marker:
            kw["Marker"] = marker
        r = iam.list_attached_role_policies(**kw)
        out |= {p["PolicyArn"] for p in r["AttachedPolicies"]}
        if not r.get("IsTruncated"):
            return out
        marker = r["Marker"]


def _put_policy(arn, name, doc, desc):
    body = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    try:
        iam.get_policy(PolicyArn=arn)
    except iam.exceptions.NoSuchEntityException:
        iam.create_policy(PolicyName=name, Path="/dcv-manager/", PolicyDocument=body, Description=desc[:1000])
        return
    vers = sorted(iam.list_policy_versions(PolicyArn=arn)["Versions"], key=lambda v: v["CreateDate"])
    old = [v for v in vers if not v["IsDefaultVersion"]]
    if len(vers) >= 5 and old:
        iam.delete_policy_version(PolicyArn=arn, VersionId=old[0]["VersionId"])
    iam.create_policy_version(PolicyArn=arn, PolicyDocument=body, SetAsDefault=True)
    for v in old[1:] if len(vers) >= 5 else old:
        try:
            iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
        except Exception:  # noqa: BLE001
            pass


def _drop_policy(arn):
    try:
        iam.detach_role_policy(RoleName=INSTANCE_ROLE_NAME, PolicyArn=arn)
    except iam.exceptions.NoSuchEntityException:
        pass
    try:
        for v in iam.list_policy_versions(PolicyArn=arn)["Versions"]:
            if not v["IsDefaultVersion"]:
                iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
        iam.delete_policy(PolicyArn=arn)
    except iam.exceptions.NoSuchEntityException:
        pass


def sync_iam(share, target_ids):
    """按当前配置创建/更新/删除该共享盘的策略，返回策略 ARN 列表。"""
    if not INSTANCE_ROLE_NAME:
        raise ValueError("尚未设置服务器实例角色，请先在「系统设置」中完成初始化")
    docs = policy_documents(share, target_ids)
    old = json.loads(share.get("policy_arn") or "[]")
    attached = _attached()
    need_new = [ _policy_arn(share["id"], n) for n in range(len(docs)) if _policy_arn(share["id"], n) not in attached]
    if len(attached) + len(need_new) > 10:
        raise ValueError(f"实例角色 {INSTANCE_ROLE_NAME} 最多只能附加 10 个托管策略（当前 {len(attached)} 个）。"
                         "请减少共享盘数量、改用「全部服务器」范围，或在 IAM 配额中提高上限")
    arns = []
    for n, d in enumerate(docs):
        arn = _policy_arn(share["id"], n)
        _put_policy(arn, f"dcv-share-{share['id']}-{n}", d,
                    f"DCV 共享盘「{share['name']}」 s3://{share['bucket']}/{share['prefix']} {'读写' if share['mode'] == 'rw' else '只读'}")
        if arn not in attached:
            iam.attach_role_policy(RoleName=INSTANCE_ROLE_NAME, PolicyArn=arn)
        arns.append(arn)
    for arn in old:
        if arn not in arns:
            _drop_policy(arn)
    return arns


def delete_iam(share):
    for arn in json.loads(share.get("policy_arn") or "[]"):
        _drop_policy(arn)


# ---------------- 期望状态 ----------------

def desired_for(instance_id, shares):
    return [s for s in shares if s["scope"] == "all" or instance_id in s["target_ids"]]


def mount_args(s):
    """主机上 rclone 的完整参数（不含凭证；凭证来自实例角色）。"""
    root = SHARE_ROOT
    path = f"share{s['id']}:{s['bucket']}" + (f"/{s['prefix']}" if s["prefix"] else "")
    args = ["mount", path, f"{s['drive']}:",
            "--config", rf"{root}\rclone.conf", "--cache-dir", rf"{root}\cache\{s['id']}",
            "--vfs-cache-mode", "full", "--vfs-cache-max-size", f"{int(s['cache_gb'])}G", "--vfs-cache-max-age", "72h",
            "--vfs-fast-fingerprint", "--dir-cache-time", "30s", "--poll-interval", "0",
            "--volname", s["name"][:32], "--transfers", "8", "--s3-chunk-size", "16M",
            "--rc", "--rc-addr", f"127.0.0.1:{5600 + int(s['id'])}",
            "--log-file", rf"{root}\logs\{s['id']}.log", "--log-level", "NOTICE"]
    if s["mode"] == "ro":
        args += ["--read-only", "-o", "FileSecurity=D:P(A;;FRFX;;;WD)"]
    else:
        # 挂载进程属 SYSTEM，需显式给所有用户完整读写权限，否则普通用户无法保存文件
        args += ["-o", "FileSecurity=D:P(A;;FA;;;WD)"]
    return args


def host_spec(s):
    args = mount_args(s)
    conf = [f"[share{s['id']}]", "type = s3", "provider = AWS", "env_auth = true", f"region = {s['region']}",
            "no_check_bucket = true"]
    if s.get("kms_key"):
        conf += ["server_side_encryption = aws:kms", f"sse_kms_key_id = {s['kms_key']}"]
    h = hashlib.sha256(json.dumps([args, conf], ensure_ascii=False).encode()).hexdigest()[:16]
    return {"id": int(s["id"]), "name": s["name"], "drive": s["drive"], "mode": s["mode"], "args": args, "conf": conf, "hash": h}


# ---------------- 主机脚本 ----------------

_SYNC = r"""
$ErrorActionPreference = 'Stop'
$cfg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__B64__')) | ConvertFrom-Json
$root = $cfg.root; $bin = "$root\bin"
$out = [ordered]@{ installed = @(); shares = @(); removed = @(); errors = @() }
function Ensure-Dir($p) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null } }
Ensure-Dir $root; Ensure-Dir $bin; Ensure-Dir "$root\cache"; Ensure-Dir "$root\logs"
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Get-Verified($url, $sha, $dest) {
  Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
  $h = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
  if ($h -ne $sha) { Remove-Item $dest -Force; throw "下载文件校验失败：$url" }
}
function Rc($id, $path) {
  $pass = (Get-Content "$root\rc.secret" -Raw).Trim()
  $auth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("dcv:$pass"))
  Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$(5600 + $id)/$path" -Headers @{ Authorization = $auth } -TimeoutSec 5
}
function Pending($id) { try { $s = (Rc $id 'vfs/stats').diskCache; return [int]$s.uploadsInProgress + [int]$s.uploadsQueued } catch { return -1 } }
function Stop-Share($id, $waitSec) {
  $t = 0; while ($t -lt $waitSec) { $p = Pending $id; if ($p -le 0) { break }; Start-Sleep 3; $t += 3 }
  if ((Pending $id) -gt 0) { return $false }
  Set-Content "$root\stop-$id" '1'
  try { Rc $id 'core/quit' | Out-Null } catch {}
  Start-Sleep 3
  Stop-ScheduledTask -TaskPath '\DCV\' -TaskName "DCV-Share-$id" -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process -Filter "Name='rclone.exe'" | Where-Object { $_.CommandLine -like "* share$($id):*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Remove-Item "$root\stop-$id" -Force -ErrorAction SilentlyContinue
  return $true
}

# 1. 组件
if (-not (Test-Path "${env:ProgramFiles(x86)}\WinFsp\bin\winfsp-x64.dll")) {
  $m = "$root\winfsp.msi"; Get-Verified $cfg.winfsp_url $cfg.winfsp_sha $m
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$m`" /qn /norestart" -Wait -PassThru
  Remove-Item $m -Force
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "WinFsp 安装失败（$($p.ExitCode)）" }
  $out.installed += 'WinFsp'
}
$exe = "$bin\rclone.exe"
if (-not (Test-Path $exe) -or (Get-Content "$bin\rclone.sha256" -ErrorAction SilentlyContinue) -ne $cfg.rclone_sha) {
  $z = "$root\rclone.zip"; Get-Verified $cfg.rclone_url $cfg.rclone_sha $z
  Get-ScheduledTask -TaskPath '\DCV\' -ErrorAction SilentlyContinue | Where-Object TaskName -like 'DCV-Share-*' | ForEach-Object { Stop-Share ([int]($_.TaskName -replace 'DCV-Share-', '')) 120 | Out-Null }
  Expand-Archive $z "$root\x" -Force
  Copy-Item (Get-ChildItem "$root\x" -Recurse -Filter rclone.exe | Select-Object -First 1).FullName $exe -Force
  Remove-Item "$root\x", $z -Recurse -Force
  Set-Content "$bin\rclone.sha256" $cfg.rclone_sha
  $out.installed += 'rclone'
}
if (-not (Test-Path "$root\rc.secret")) {
  $b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  Set-Content "$root\rc.secret" ([Convert]::ToBase64String($b))
}
Set-Content "$bin\run.ps1" -Encoding UTF8 -Value @'
param([int]$Id)
$root = '__ROOT__'
Remove-Item "$root\stop-$Id" -Force -ErrorAction SilentlyContinue
while ($true) {
  $a = Get-Content "$root\share-$Id.json" -Raw -Encoding UTF8 | ConvertFrom-Json
  $env:RCLONE_RC_USER = 'dcv'; $env:RCLONE_RC_PASS = (Get-Content "$root\rc.secret" -Raw).Trim()
  & "$root\bin\rclone.exe" @($a.args)
  if (Test-Path "$root\stop-$Id") { break }
  Start-Sleep 10
}
'@

# 2. rclone 配置（不含任何密钥，凭证来自实例角色）
$conf = @(); foreach ($s in $cfg.shares) { $conf += $s.conf; $conf += '' }
Set-Content "$root\rclone.conf" $conf -Encoding ASCII

# 3. 移除不再授权的共享盘
$want = @($cfg.shares | ForEach-Object { [int]$_.id })
foreach ($t in @(Get-ScheduledTask -TaskPath '\DCV\' -ErrorAction SilentlyContinue | Where-Object TaskName -like 'DCV-Share-*')) {
  $id = [int]($t.TaskName -replace 'DCV-Share-', '')
  if ($want -contains $id) { continue }
  if (Stop-Share $id 120) {
    Unregister-ScheduledTask -TaskPath '\DCV\' -TaskName $t.TaskName -Confirm:$false
    Remove-Item "$root\share-$id.json", "$root\logs\$id.log" -Force -ErrorAction SilentlyContinue
    Remove-Item "$root\cache\$id" -Recurse -Force -ErrorAction SilentlyContinue
    $out.removed += $id
  } else { $out.errors += "共享盘 #$id 仍有文件在上传，暂未卸载，稍后会自动重试" }
}

# 4. 挂载授权的共享盘
foreach ($s in $cfg.shares) {
  $r = [ordered]@{ id = [int]$s.id; drive = $s.drive; ok = $false; message = '' }
  try {
    $jf = "$root\share-$($s.id).json"; $tn = "DCV-Share-$($s.id)"
    $old = if (Test-Path $jf) { (Get-Content $jf -Raw -Encoding UTF8 | ConvertFrom-Json).hash } else { '' }
    $task = Get-ScheduledTask -TaskPath '\DCV\' -TaskName $tn -ErrorAction SilentlyContinue
    if ($task -and $old -ne $s.hash) {
      if (-not (Stop-Share $s.id 120)) { throw '仍有文件在上传，暂不能更新挂载参数，稍后会自动重试' }
    }
    $used = Get-PSDrive -PSProvider FileSystem -Name $s.drive -ErrorAction SilentlyContinue
    $mine = Get-CimInstance Win32_Process -Filter "Name='rclone.exe'" | Where-Object { $_.CommandLine -like "* share$($s.id):*" }
    if ($used -and -not $mine) { throw "盘符 $($s.drive): 已被占用（$($used.Root) $($used.Description)）" }
    ($s | Select-Object id, name, drive, mode, args, hash | ConvertTo-Json -Depth 4) | Set-Content $jf -Encoding UTF8
    if (-not $task -or $old -ne $s.hash) {
      $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$bin\run.ps1`" -Id $($s.id)"
      $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
      $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
      Register-ScheduledTask -TaskPath '\DCV\' -TaskName $tn -Action $act -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $set -Principal $pr -Description "DCV 共享盘 $($s.name)" -Force | Out-Null
    }
    if ((Get-ScheduledTask -TaskPath '\DCV\' -TaskName $tn).State -ne 'Running') { Start-ScheduledTask -TaskPath '\DCV\' -TaskName $tn }
    $n = 0; while (-not (Test-Path "$($s.drive):\") -and $n -lt 40) { Start-Sleep -Milliseconds 750; $n++ }
    if (-not (Test-Path "$($s.drive):\")) { throw ('挂载超时。' + ((Get-Content "$root\logs\$($s.id).log" -Tail 3 -ErrorAction SilentlyContinue) -join ' ')) }
    try { Get-ChildItem "$($s.drive):\" -ErrorAction Stop | Select-Object -First 1 | Out-Null } catch { throw "已挂载但无法读取：$($_.Exception.Message)" }
    $r.ok = $true; $r.message = "已挂载为 $($s.drive):"
  } catch { $r.message = "$($_.Exception.Message)" }
  $out.shares += $r
}
'###JSON###' + ($out | ConvertTo-Json -Compress -Depth 4)
"""

# 巡检时追加到巡检脚本中的片段：上报本机共享盘实际状态
STATUS_SNIPPET = r"""
$sroot = '__ROOT__'; $sh = @()
foreach ($t in @(Get-ScheduledTask -TaskPath '\DCV\' -ErrorAction SilentlyContinue | Where-Object TaskName -like 'DCV-Share-*')) {
  $id = [int]($t.TaskName -replace 'DCV-Share-', '')
  $j = $null; try { $j = Get-Content "$sroot\share-$id.json" -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
  $pend = -1
  try { $pw = (Get-Content "$sroot\rc.secret" -Raw).Trim(); $au = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("dcv:$pw"))
        $st = (Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$(5600 + $id)/vfs/stats" -Headers @{ Authorization = $au } -TimeoutSec 3).diskCache
        $pend = [int]$st.uploadsInProgress + [int]$st.uploadsQueued } catch {}
  $d = if ($j) { $j.drive } else { '' }
  $err = ''; $lg = "$sroot\logs\$id.log"
  if (Test-Path $lg) { $e = Get-Content $lg -Tail 30 | Where-Object { $_ -match 'ERROR|CRITICAL' } | Select-Object -Last 1; if ($e) { $err = "$e".Substring(0, [Math]::Min(300, "$e".Length)) } }
  $sh += [ordered]@{ id = $id; hash = $(if ($j) { $j.hash } else { '' }); drive = $d; task = "$($t.State)"; mounted = [bool]($d -and (Test-Path "$($d):\")); pending = $pend; last_error = $err }
}
$r.shares = $sh
"""


def _host_payload(desired):
    return {"root": SHARE_ROOT, "rclone_url": RCLONE_URL, "rclone_sha": RCLONE_SHA256,
            "winfsp_url": WINFSP_URL, "winfsp_sha": WINFSP_SHA256, "shares": [host_spec(s) for s in desired]}


def sync_commands(desired):
    b64 = base64.b64encode(json.dumps(_host_payload(desired), ensure_ascii=False).encode("utf-8")).decode()
    script = _SYNC.replace("__B64__", b64).replace("__ROOT__", SHARE_ROOT)
    # SSM 逐行执行会破坏 here-string，因此整体作为一个脚本块传递
    return [script]


def sync_host(instance_id, desired, timeout=420):
    res = aws_service.run_powershell(instance_id, sync_commands(desired), timeout=timeout)
    out = res.get("stdout", "")
    if "###JSON###" in out:
        try:
            return json.loads(out.split("###JSON###", 1)[1].strip())
        except ValueError:
            pass
    err = (res.get("stderr") or out or res.get("status") or "").strip()
    return {"fatal": err[-600:] or "执行失败"}


def status_snippet():
    return [ln for ln in STATUS_SNIPPET.replace("__ROOT__", SHARE_ROOT).strip().splitlines() if ln.strip()]


# ---------------- 状态评估 ----------------

def evaluate(inst, insp, shares):
    """对比期望与主机实际，返回 (每个共享盘状态列表, 是否需要同步, 告警列表)。"""
    desired = desired_for(inst["instance_id"], shares)
    live = insp is not None and not insp.get("error") and "shares" in insp
    actual = {int(x["id"]): x for x in (insp or {}).get("shares") or []} if live else {}
    rows, alerts, drift = [], [], False
    if inst.get("iam_profile") and inst["iam_profile"] != LAUNCH_PROFILE and desired:
        alerts.append(("warn", f"实例角色为 {inst['iam_profile']}，不是 {LAUNCH_PROFILE}，无法访问共享盘"))
    for s in desired:
        want = host_spec(s)["hash"]
        a = actual.get(int(s["id"]))
        if inst.get("state") != "running":
            st = "stopped"
        elif not live:
            st = "unknown"
        elif not a:
            st, drift = "missing", True
        elif a.get("hash") != want:
            st, drift = "outdated", True
        elif not a.get("mounted"):
            st, drift = "failed", True
        else:
            st = "ok"
        row = {"id": s["id"], "name": s["name"], "drive": s["drive"], "mode": s["mode"], "status": st,
               "pending": (a or {}).get("pending", -1), "last_error": (a or {}).get("last_error", "")}
        rows.append(row)
        if st in ("missing", "failed"):
            alerts.append(("warn", f"共享盘 {s['drive']}:（{s['name']}）未挂载" + (f"：{row['last_error']}" if row["last_error"] else "")))
    extra = [i for i in actual if i not in {int(s["id"]) for s in desired}]
    if extra:
        drift = True
        alerts.append(("warn", f"主机上有 {len(extra)} 个未授权的共享盘挂载，将自动卸载"))
    return rows, drift, alerts
