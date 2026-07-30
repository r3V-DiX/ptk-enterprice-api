#!/bin/bash
# update-image.sh — called by GitHub Actions on every deploy
set -euo pipefail

ECR_REGISTRY="$1"
ECR_REPO="$2"
IMAGE_TAG="$3"
AWS_REGION="${4:-ap-south-1}"
SECRET_NAME="ptk-enterprise-api/prod"

DEPLOY_DIR="/opt/ptk-enterprise-api"
cd "$DEPLOY_DIR"

echo "[deploy] Fetching secrets from AWS Secrets Manager..."
aws secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --region "$AWS_REGION" \
  --query 'SecretString' \
  --output text | python3 -c "
import json, sys
data = json.load(sys.stdin)
for k, v in data.items():
    print(f'{k}={v}')
" > .env.prod
chmod 600 .env.prod
echo "[deploy] Secrets written to .env.prod"

echo "[deploy] Logging into ECR..."
aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "[deploy] Pulling image $ECR_REGISTRY/$ECR_REPO:$IMAGE_TAG"
docker pull "$ECR_REGISTRY/$ECR_REPO:$IMAGE_TAG"

echo "[deploy] Restarting services..."
ECR_REGISTRY="$ECR_REGISTRY" ECR_REPO="$ECR_REPO" IMAGE_TAG="$IMAGE_TAG" \
  docker compose -f docker-compose.prod.yml up -d --remove-orphans

docker image prune -f

echo "[deploy] Done. Running containers:"
docker compose -f docker-compose.prod.yml ps
