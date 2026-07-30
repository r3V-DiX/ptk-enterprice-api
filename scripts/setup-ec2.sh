#!/bin/bash
# setup-ec2.sh — Run ONCE on a fresh Ubuntu 22.04 EC2 instance
# Usage: bash setup-ec2.sh
set -euo pipefail

AWS_REGION="us-east-1"
ECR_REPO="ptk-enterprise-api"
DEPLOY_DIR="/opt/ptk-enterprise-api"

echo "==> Installing Docker"
apt-get update -y
apt-get install -y ca-certificates curl gnupg nginx certbot python3-certbot-nginx awscli unzip
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable --now docker

echo "==> Creating deploy directory"
mkdir -p "$DEPLOY_DIR"
cd "$DEPLOY_DIR"

echo "==> Writing update-image.sh"
cat > update-image.sh << 'SCRIPT'
#!/bin/bash
# update-image.sh — called by GitHub Actions on every deploy
set -euo pipefail
ECR_REGISTRY="$1"
ECR_REPO="$2"
IMAGE_TAG="$3"
AWS_REGION="${4:-us-east-1}"

cd /opt/ptk-enterprise-api

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
SCRIPT
chmod +x update-image.sh

echo "==> Configuring Nginx for enterprise.pentoolkit.com"
cat > /etc/nginx/sites-available/ptk-enterprise << 'NGINX'
server {
    listen 80;
    server_name enterprise.pentoolkit.com;

    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name enterprise.pentoolkit.com;

    ssl_certificate     /etc/letsencrypt/live/enterprise.pentoolkit.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/enterprise.pentoolkit.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 10M;

    location / {
        proxy_pass         http://127.0.0.1:8002;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/ptk-enterprise /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ""
echo "============================================"
echo " EC2 setup complete."
echo ""
echo " NEXT STEPS:"
echo " 1. Copy your .env.prod file to $DEPLOY_DIR/.env.prod"
echo " 2. Copy docker-compose.prod.yml to $DEPLOY_DIR/"
echo " 3. Point enterprise.pentoolkit.com DNS A record to this EC2's public IP"
echo " 4. Once DNS propagates, run:"
echo "      certbot --nginx -d enterprise.pentoolkit.com"
echo " 5. Push to main branch — GitHub Actions will do the rest."
echo "============================================"
