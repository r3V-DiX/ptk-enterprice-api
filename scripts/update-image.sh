#!/bin/bash
# update-image.sh — called by GitHub Actions on every deploy to EC2
# Usage: bash update-image.sh <ecr_registry> <ecr_repo> <image_tag> [aws_region]
# Example: bash update-image.sh 123456789.dkr.ecr.us-east-1.amazonaws.com ptk-enterprise-api abc1234 us-east-1
set -euo pipefail

ECR_REGISTRY="$1"
ECR_REPO="$2"
IMAGE_TAG="$3"
AWS_REGION="${4:-us-east-1}"

DEPLOY_DIR="/opt/ptk-enterprise-api"
cd "$DEPLOY_DIR"

echo "[deploy] Logging into ECR..."
aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"

echo "[deploy] Pulling image $ECR_REGISTRY/$ECR_REPO:$IMAGE_TAG"
docker pull "$ECR_REGISTRY/$ECR_REPO:$IMAGE_TAG"

echo "[deploy] Restarting services..."
ECR_REGISTRY="$ECR_REGISTRY" ECR_REPO="$ECR_REPO" IMAGE_TAG="$IMAGE_TAG" \
  docker compose -f docker-compose.prod.yml up -d --remove-orphans

echo "[deploy] Cleaning up old images..."
docker image prune -f

echo "[deploy] Done. Running containers:"
docker compose -f docker-compose.prod.yml ps
