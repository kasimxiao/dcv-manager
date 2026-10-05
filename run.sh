#!/usr/bin/env bash
# DCV 管理平台本地开发启动脚本（生产部署请使用 deploy/deploy.sh）
set -e
cd "$(dirname "$0")"

# 创建虚拟环境
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q -r requirements.txt

# 环境变量（按需覆盖）
export AWS_REGION="${AWS_REGION:-eu-central-1}"
export DCV_TAG_KEY="${DCV_TAG_KEY:-dcv}"
export DCV_TAG_VALUE="${DCV_TAG_VALUE:-true}"
export DCV_ADMIN_PASSWORD="${DCV_ADMIN_PASSWORD:-changeme}"
export DCV_SCHEDULER_TZ="${DCV_SCHEDULER_TZ:-Asia/Shanghai}"

# Cognito 用户管理（配置后启用；留空则回退到简单口令认证，仅用于本地开发）
export COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-}"
export COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-}"
# 本地数据目录（与 AWS 部署分开）
export DCV_DB_PATH="${DCV_DB_PATH:-$(pwd)/data.db}"
export DCV_SETTINGS_PATH="${DCV_SETTINGS_PATH:-$(pwd)/settings.json}"

echo "启动中… 打开 http://127.0.0.1:8000"
cd backend
exec uvicorn app:app --host 127.0.0.1 --port 8000
