#!/usr/bin/env bash
# DCV 管理平台一键部署 / 更新（幂等，可重复执行）
#
# 用法：
#   ./deploy/deploy.sh                                   # 新建 VPC 部署到 eu-central-1
#   ./deploy/deploy.sh --region eu-central-1 --vpc vpc-xxx --subnet subnet-xxx   # 部署到已有 VPC 的私有子网
#   ./deploy/deploy.sh --admin-email a@example.com       # 管理员用户名（默认 admin）可附邮箱
# 选项：
#   --region R          部署区域（默认 eu-central-1）
#   --stack NAME        堆栈名（默认 dcv-manager）
#   --vpc ID --subnet ID   使用已有 VPC 与私有子网（子网需能访问互联网，VPC 需挂互联网网关）
#   --vpc-cidr CIDR     新建 VPC 的网段（默认 10.90.0.0/24）
#   --instance-type T   平台服务器机型（默认 t4g.small）
#   --admin NAME        初始管理员用户名（默认 admin）
#   --admin-email EMAIL 管理员邮箱（可选）
# 依赖：aws CLI v2（已配置凭证）、tar、python3
set -euo pipefail

REGION=eu-central-1; STACK=dcv-manager; VPC=""; SUBNET=""; VPC_CIDR=10.90.0.0/24
ITYPE=t4g.small; ADMIN=admin; ADMIN_EMAIL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --region) REGION="$2"; shift 2;;
    --stack) STACK="$2"; shift 2;;
    --vpc) VPC="$2"; shift 2;;
    --subnet) SUBNET="$2"; shift 2;;
    --vpc-cidr) VPC_CIDR="$2"; shift 2;;
    --instance-type) ITYPE="$2"; shift 2;;
    --admin) ADMIN="$2"; shift 2;;
    --admin-email) ADMIN_EMAIL="$2"; shift 2;;
    -h|--help) sed -n '2,17p' "$0"; exit 0;;
    *) echo "未知参数：$1"; exit 2;;
  esac
done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AWS="aws --region ${REGION}"
say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m错误：%s\033[0m\n' "$*" >&2; exit 1; }

say "检查环境"
ACCOUNT=$(${AWS} sts get-caller-identity --query Account --output text) || die "AWS 凭证不可用"
echo "账号 ${ACCOUNT}，区域 ${REGION}，堆栈 ${STACK}"
if [ -n "${VPC}${SUBNET}" ]; then
  [ -n "${VPC}" ] && [ -n "${SUBNET}" ] || die "--vpc 与 --subnet 需同时指定"
  MODE=existing
  SVPC=$(${AWS} ec2 describe-subnets --subnet-ids "${SUBNET}" --query 'Subnets[0].VpcId' --output text) || die "子网 ${SUBNET} 不存在"
  [ "${SVPC}" = "${VPC}" ] || die "子网 ${SUBNET} 不属于 ${VPC}"
  IGW=$(${AWS} ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values="${VPC}" --query 'length(InternetGateways)' --output text)
  [ "${IGW}" -ge 1 ] || die "${VPC} 没有互联网网关（CloudFront VPC 源站要求 VPC 挂有互联网网关）"
  RT=$(${AWS} ec2 describe-route-tables --filters Name=association.subnet-id,Values="${SUBNET}" --query 'RouteTables[0].Routes[?DestinationCidrBlock==`0.0.0.0/0`]|[0].[GatewayId,NatGatewayId,TransitGatewayId]' --output text)
  if [ "${RT}" = "None" ] || [ -z "${RT}" ]; then
    RT=$(${AWS} ec2 describe-route-tables --filters Name=vpc-id,Values="${VPC}" Name=association.main,Values=true --query 'RouteTables[0].Routes[?DestinationCidrBlock==`0.0.0.0/0`]|[0].[GatewayId,NatGatewayId,TransitGatewayId]' --output text)
  fi
  case "${RT}" in
    igw-*) die "${SUBNET} 是公有子网（默认路由到互联网网关）。CloudFront VPC 源站要求私有子网，请选择经 NAT 访问互联网的子网";;
    *nat-*|*tgw-*) echo "使用已有 VPC ${VPC}，私有子网 ${SUBNET}（出网：$(echo ${RT} | tr '\t' ' ' | sed 's/None//g')）";;
    *) die "${SUBNET} 没有到互联网的默认路由，平台无法访问 AWS API 与安装依赖";;
  esac
else
  MODE=create; echo "新建 VPC ${VPC_CIDR}（公有子网 + NAT 网关 + 私有子网）"
fi
PL=$(${AWS} ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing --query 'PrefixLists[0].PrefixListId' --output text)
[ "${PL}" != "None" ] || die "未找到 CloudFront 源站前缀列表"

say "打包并上传平台代码"
BUCKET="dcv-manager-deploy-${ACCOUNT}-${REGION}"
if ! ${AWS} s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  if [ "${REGION}" = us-east-1 ]; then ${AWS} s3api create-bucket --bucket "${BUCKET}" >/dev/null
  else ${AWS} s3api create-bucket --bucket "${BUCKET}" --create-bucket-configuration LocationConstraint="${REGION}" >/dev/null; fi
  ${AWS} s3api put-public-access-block --bucket "${BUCKET}" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  ${AWS} s3api put-bucket-encryption --bucket "${BUCKET}" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  ${AWS} s3api put-bucket-versioning --bucket "${BUCKET}" --versioning-configuration Status=Enabled
  echo "已创建部署存储桶 ${BUCKET}"
fi
PKG=$(mktemp -t dcv-manager-XXXX).tar.gz
COPYFILE_DISABLE=1 tar -czf "${PKG}" -C "${ROOT}" --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
  backend frontend lambda provisioning requirements.txt README.md
KEY=dcv-manager/app.tar.gz
${AWS} s3 cp "${PKG}" "s3://${BUCKET}/${KEY}" --only-show-errors
VER=$(date +%Y%m%d-%H%M%S); ${AWS} s3 cp "${PKG}" "s3://${BUCKET}/dcv-manager/releases/${VER}.tar.gz" --only-show-errors
echo "代码包 $(du -h "${PKG}" | cut -f1)，版本 ${VER}"; rm -f "${PKG}"

say "创建或更新 CloudFormation 堆栈（首次约 15–25 分钟：NAT、CloudFront VPC 源站与分发较慢）"
PARAMS=(VpcMode=${MODE} VpcCidr=${VPC_CIDR} ExistingVpcId=${VPC} ExistingSubnetId=${SUBNET} InstanceType=${ITYPE}
        ArtifactBucket=${BUCKET} ArtifactKey=${KEY} CloudFrontPrefixListId=${PL})
EXISTS=$(${AWS} cloudformation describe-stacks --stack-name "${STACK}" --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo NONE)
case "${EXISTS}" in ROLLBACK_COMPLETE|ROLLBACK_FAILED) echo "上次创建失败（${EXISTS}），先删除"; ${AWS} cloudformation delete-stack --stack-name "${STACK}"; ${AWS} cloudformation wait stack-delete-complete --stack-name "${STACK}"; EXISTS=NONE;; esac
set +e
${AWS} cloudformation deploy --stack-name "${STACK}" --template-file "${ROOT}/deploy/platform.yaml" \
  --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset --parameter-overrides "${PARAMS[@]}" \
  --tags dcv:managed-by=dcv-manager
RC=$?
set -e
if [ ${RC} -ne 0 ]; then
  echo "堆栈部署失败，最近的失败事件："
  ${AWS} cloudformation describe-stack-events --stack-name "${STACK}" --max-items 40 \
    --query 'StackEvents[?contains(ResourceStatus,`FAILED`)].[LogicalResourceId,ResourceStatusReason]' --output text | head -10
  exit 1
fi
out() { ${AWS} cloudformation describe-stacks --stack-name "${STACK}" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
URL=$(out Url); POOL=$(out UserPoolId); IID=$(out PlatformInstanceId)

if [ "${EXISTS}" != NONE ]; then
  say "更新平台服务器上的代码"
  CID=$(${AWS} ssm send-command --instance-ids "${IID}" --document-name AWS-RunShellScript --comment "dcv-manager update ${VER}" \
    --parameters 'commands=["/opt/dcv-manager/update.sh"]' --query Command.CommandId --output text)
  for i in $(seq 1 60); do
    ST=$(${AWS} ssm get-command-invocation --command-id "${CID}" --instance-id "${IID}" --query Status --output text 2>/dev/null || echo Pending)
    case "${ST}" in Success) echo "已更新到 ${VER}"; break;; Failed|Cancelled|TimedOut) ${AWS} ssm get-command-invocation --command-id "${CID}" --instance-id "${IID}" --query StandardErrorContent --output text; die "更新失败";; esac
    sleep 5
  done
fi

say "初始化管理员"
if ${AWS} cognito-idp admin-get-user --user-pool-id "${POOL}" --username "${ADMIN}" >/dev/null 2>&1; then
  echo "管理员 ${ADMIN} 已存在（未修改其密码）"; TMP_PW=""
else
  TMP_PW=$(python3 -c "import secrets,string;a=string.ascii_letters+string.digits;p=[secrets.choice(string.ascii_uppercase),secrets.choice(string.ascii_lowercase),secrets.choice(string.digits),secrets.choice('#%+=@')]+[secrets.choice(a) for _ in range(12)];secrets.SystemRandom().shuffle(p);print(''.join(p))")
  if [ -n "${ADMIN_EMAIL}" ]; then
    ${AWS} cognito-idp admin-create-user --user-pool-id "${POOL}" --username "${ADMIN}" --temporary-password "${TMP_PW}" \
      --message-action SUPPRESS --user-attributes Name=email,Value="${ADMIN_EMAIL}" Name=email_verified,Value=true >/dev/null
  else
    ${AWS} cognito-idp admin-create-user --user-pool-id "${POOL}" --username "${ADMIN}" --temporary-password "${TMP_PW}" \
      --message-action SUPPRESS >/dev/null
  fi
  ${AWS} cognito-idp admin-add-user-to-group --user-pool-id "${POOL}" --username "${ADMIN}" --group-name admin
fi

say "检查访问"
for i in $(seq 1 60); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "${URL}/" || true)
  [ "${CODE}" = 200 ] && break; sleep 10
done
API=$(curl -s -o /dev/null -w '%{http_code}' "${URL}/api/instances" || true)
echo "首页 ${CODE}，未登录访问接口 ${API}（应为 401）"

cat <<EOF

部署完成
  平台地址：${URL}
  管理员：  ${ADMIN}
EOF
if [ -n "${TMP_PW}" ]; then
  echo "  临时密码：${TMP_PW}     （仅显示这一次；首次登录时需设置新密码，7 天内有效）"
fi
cat <<EOF
  下一步：登录后进入「系统设置 → 开始初始化」，为 DCV 服务器配置网络、安全组、实例角色并部署托管组件。
  更新代码：再次执行本脚本；删除平台：./deploy/destroy.sh --region ${REGION}
EOF
