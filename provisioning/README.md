# 新 DCV 主机部署（加固版）

`dcv-bootstrap.ps1` 会在开机时自动完成：NVIDIA GRID 驱动、VC++2022、Amazon DCV Server 安装，
并创建 **标准用户 dcvuser（非管理员）**，配置自动 console 会话。

> 关键安全点：dcvuser 只加入 `Remote Desktop Users`，不加入 `Administrators`。
> 因此连接用户无法自行修改 DCV 权限（权限文件/注册表/服务均需管理员权限），
> 只能由管理平台通过 SSM（以 SYSTEM 身份）集中下发。

## 前置资源

1. **实例 IAM 角色**（实例配置文件），需具备：
   - S3 读取（下载 NVIDIA 驱动 + DCV 授权校验）：`ec2-windows-nvidia-drivers`、`dcv-license.<region>`
   - `AmazonSSMManagedInstanceCore`（供管理平台远程下发权限）
   - 可在平台「系统设置 → 初始化」中新建（默认名 `dcv-instance-role`）
2. **安全组**：放行入站 8443/tcp、8443/udp（DCV），按需放行 3389/tcp（RDP，仅维护）
3. **密钥对**：用于取回本地 Administrator 密码（维护用）

## 启动示例（eu-central-1）

```bash
# 1. 修改脚本中的 $DcvPassword 为强口令（勿含 dcv/user 字样）
#    provisioning/dcv-bootstrap.ps1

# 2. 启动实例（Windows Server 2022 基础镜像）
AMI=$(aws ssm get-parameter --region eu-central-1 \
  --name /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base \
  --query 'Parameter.Value' --output text)

aws ec2 run-instances --region eu-central-1 \
  --image-id "$AMI" \
  --instance-type g6f.xlarge \
  --iam-instance-profile Name=dcv-instance-role \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":60,"VolumeType":"gp3"}}]' \
  --network-interfaces '[{"DeviceIndex":0,"SubnetId":"<公有子网>","AssociatePublicIpAddress":true,"Groups":["<安全组>"]}]' \
  --user-data file://provisioning/dcv-bootstrap.ps1 \
  --tag-specifications '[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":"dcv-xxx"},{"Key":"dcv","Value":"true"}]}]'
```

打了 `dcv=true` 标签后，该机器会自动出现在管理平台仪表盘中。

## 维护（需要管理员时）

dcvuser 是标准用户，无法安装软件/改系统。若需维护：
- 用密钥取回 Administrator 口令，通过 RDP 或 DCV 以 Administrator 登录；或
- 通过管理平台/SSM 以 SYSTEM 身份远程执行命令。
