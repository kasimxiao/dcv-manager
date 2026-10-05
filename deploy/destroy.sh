#!/usr/bin/env bash
# 删除 DCV 管理平台
#
# 用法：
#   ./deploy/destroy.sh                       # 删除平台本身（堆栈：平台服务器、CloudFront、Cognito 用户池、平台 VPC）与部署存储桶
#   ./deploy/destroy.sh --purge-dcv eu-central-1,eu-west-2
#       同时删除平台在这些区域创建的 DCV 资源：DCV 服务器（标签 dcv=true）、定时任务与调度组、托管开机函数、
#       事件规则与日志组、初始化向导新建的 VPC 与安全组，以及全局的 dcv-* 角色和 /dcv-manager/ 策略。
#       快照（AMI）与共享盘存储桶不删除。
# 选项：--region R（默认 eu-central-1）  --stack NAME（默认 dcv-manager）  --yes（不询问确认）
set -euo pipefail
REGION=eu-central-1; STACK=dcv-manager; PURGE=""; YES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --region) REGION="$2"; shift 2;;
    --stack) STACK="$2"; shift 2;;
    --purge-dcv) PURGE="$2"; shift 2;;
    --yes) YES=1; shift;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "未知参数：$1"; exit 2;;
  esac
done
AWS="aws --region ${REGION}"
ACCOUNT=$(${AWS} sts get-caller-identity --query Account --output text)
BUCKET="dcv-manager-deploy-${ACCOUNT}-${REGION}"
echo "将删除：堆栈 ${STACK}（${REGION}）、部署存储桶 ${BUCKET}"
[ -n "${PURGE}" ] && echo "并清理以下区域中平台创建的 DCV 资源：${PURGE}（含 DCV 服务器，不可恢复）"
if [ -z "${YES}" ]; then read -r -p "输入 yes 确认：" A; [ "${A}" = yes ] || { echo "已取消"; exit 1; }; fi

if [ -n "${PURGE}" ]; then
  for R in ${PURGE//,/ }; do
    A="aws --region ${R}"
    echo "== 清理 ${R}"
    IDS=$(${A} ec2 describe-instances --filters Name=tag:dcv,Values=true Name=instance-state-name,Values=pending,running,stopping,stopped --query 'Reservations[].Instances[].InstanceId' --output text)
    if [ -n "${IDS}" ]; then ${A} ec2 terminate-instances --instance-ids ${IDS} >/dev/null; ${A} ec2 wait instance-terminated --instance-ids ${IDS}; echo "已终止 DCV 服务器：${IDS}"; fi
    for N in $(${A} scheduler list-schedules --group-name dcv-manager --query 'Schedules[].Name' --output text 2>/dev/null); do ${A} scheduler delete-schedule --group-name dcv-manager --name "${N}"; done
    ${A} scheduler delete-schedule-group --name dcv-manager 2>/dev/null && echo "已删除调度组" || true
    ${A} lambda delete-function --function-name dcv-power 2>/dev/null && echo "已删除托管开机函数" || true
    for RULE in dcv-fallback-revert dcv-instance-state-change; do
      T=$(${A} events list-targets-by-rule --rule ${RULE} --query 'Targets[].Id' --output text 2>/dev/null || true)
      [ -n "${T}" ] && ${A} events remove-targets --rule ${RULE} --ids ${T} >/dev/null
      ${A} events delete-rule --name ${RULE} 2>/dev/null && echo "已删除规则 ${RULE}" || true
    done
    for G in /aws/events/dcv-instance-state /aws/lambda/dcv-power; do ${A} logs delete-log-group --log-group-name ${G} 2>/dev/null || true; done
    ${A} logs delete-resource-policy --policy-name dcv-eventbridge-to-logs 2>/dev/null || true
    # 初始化向导新建的网络（带 dcv:managed-by 标签；平台自身的 VPC 由堆栈删除）
    for V in $(${A} ec2 describe-vpcs --filters Name=tag:dcv:managed-by,Values=dcv-manager --query 'Vpcs[].VpcId' --output text); do
      [ "$(${A} ec2 describe-instances --filters Name=vpc-id,Values=${V} Name=instance-state-name,Values=pending,running,stopping,stopped --query 'length(Reservations[])' --output text)" = 0 ] || { echo "跳过 ${V}：仍有实例"; continue; }
      for S in $(${A} ec2 describe-security-groups --filters Name=vpc-id,Values=${V} --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text); do ${A} ec2 delete-security-group --group-id ${S} || true; done
      for S in $(${A} ec2 describe-subnets --filters Name=vpc-id,Values=${V} --query 'Subnets[].SubnetId' --output text); do ${A} ec2 delete-subnet --subnet-id ${S}; done
      for T in $(${A} ec2 describe-route-tables --filters Name=vpc-id,Values=${V} --query 'RouteTables[?length(Associations[?Main==`true`])==`0`].RouteTableId' --output text); do ${A} ec2 delete-route-table --route-table-id ${T}; done
      for G in $(${A} ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values=${V} --query 'InternetGateways[].InternetGatewayId' --output text); do ${A} ec2 detach-internet-gateway --internet-gateway-id ${G} --vpc-id ${V}; ${A} ec2 delete-internet-gateway --internet-gateway-id ${G}; done
      ${A} ec2 delete-vpc --vpc-id ${V} && echo "已删除 VPC ${V}"
    done
    for S in $(${A} ec2 describe-security-groups --filters Name=tag:dcv:managed-by,Values=dcv-manager --query 'SecurityGroups[].GroupId' --output text); do ${A} ec2 delete-security-group --group-id ${S} 2>/dev/null || true; done
  done
  echo "== 清理全局 IAM（dcv-* 角色、/dcv-manager/ 策略）"
  for ROLE in $(aws iam list-roles --query 'Roles[?starts_with(RoleName,`dcv-`)].RoleName' --output text); do
    for P in $(aws iam list-attached-role-policies --role-name ${ROLE} --query 'AttachedPolicies[].PolicyArn' --output text); do aws iam detach-role-policy --role-name ${ROLE} --policy-arn ${P}; done
    for P in $(aws iam list-role-policies --role-name ${ROLE} --query 'PolicyNames[]' --output text); do aws iam delete-role-policy --role-name ${ROLE} --policy-name ${P}; done
    for IP in $(aws iam list-instance-profiles-for-role --role-name ${ROLE} --query 'InstanceProfiles[].InstanceProfileName' --output text); do
      aws iam remove-role-from-instance-profile --instance-profile-name ${IP} --role-name ${ROLE}; aws iam delete-instance-profile --instance-profile-name ${IP}; done
    aws iam delete-role --role-name ${ROLE} && echo "已删除角色 ${ROLE}"
  done
  for P in $(aws iam list-policies --scope Local --path-prefix /dcv-manager/ --query 'Policies[].Arn' --output text); do
    for V in $(aws iam list-policy-versions --policy-arn ${P} --query 'Versions[?!IsDefaultVersion].VersionId' --output text); do aws iam delete-policy-version --policy-arn ${P} --version-id ${V}; done
    aws iam delete-policy --policy-arn ${P}
  done
fi

echo "== 删除堆栈 ${STACK}（CloudFront 与 VPC 源站删除较慢，约 10–20 分钟）"
if ${AWS} cloudformation describe-stacks --stack-name "${STACK}" >/dev/null 2>&1; then
  ${AWS} cloudformation delete-stack --stack-name "${STACK}"
  ${AWS} cloudformation wait stack-delete-complete --stack-name "${STACK}" && echo "堆栈已删除"
fi
if ${AWS} s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  python3 - "${BUCKET}" "${REGION}" <<'PY' 2>/dev/null || $AWS s3 rb "s3://$BUCKET" --force
import sys, json, subprocess
b, r = sys.argv[1], sys.argv[2]
while True:
    out = json.loads(subprocess.check_output(["aws", "--region", r, "s3api", "list-object-versions", "--bucket", b, "--max-items", "900", "--output", "json"]) or b"{}")
    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for k in ("Versions", "DeleteMarkers") for o in out.get(k) or []]
    if not objs:
        break
    subprocess.check_call(["aws", "--region", r, "s3api", "delete-objects", "--bucket", b, "--delete", json.dumps({"Objects": objs, "Quiet": True})])
subprocess.check_call(["aws", "--region", r, "s3api", "delete-bucket", "--bucket", b])
PY
  echo "部署存储桶已删除"
fi
echo "完成。快照（AMI）未删除。"
