#!/usr/bin/env bash
# ------------------------------------------------------------------
# Docker Infrastructure Setup Script with Traefik, Portainer, Netdata & Watchtower Email
# ------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
DEPLOY_USER="deploy"
BASE_DIR="/home/${DEPLOY_USER}"
DOCKER_DIR="${BASE_DIR}/docker"

DOMAIN=""
ADMIN_EMAIL=""
TIMEZONE="UTC"
TRAEFIK_PASSWORD=""
TRAEFIK_AUTH_HASH=""

SSMTP_CONFIGURED=false
GMAIL_USER=""
EMAIL_TO=""
EMAIL_NOTIFICATIONS=false

# Helpers
msg() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*"; }

ask() {
    local prompt="$1"
    local var="$2"
    local secret="${3:-false}"
    local val
    echo -en "${CYAN}${prompt}${NC}"
    if [ "$secret" = true ]; then
        read -r -s val || true; echo
    else
        read -r val || true
    fi
    printf -v "$var" "%s" "$val"
}

check_user() {
    if [ "$(whoami)" != "$DEPLOY_USER" ]; then
        err "Run as $DEPLOY_USER"
        exit 1
    fi
}

check_ssmtp() {
    if command -v ssmtp >/dev/null 2>&1; then
        msg "ssmtp found"
        SSMTP_CONFIGURED=true
        if [ -r /etc/ssmtp/ssmtp.conf ]; then
            GMAIL_USER=$(grep -E '^AuthUser=' /etc/ssmtp/ssmtp.conf | cut -d'=' -f2-)
        fi
    else
        warn "ssmtp not installed. Email notifications disabled"
        SSMTP_CONFIGURED=false
    fi
}

gather_config() {
    ask "Enter domain (example.com): " DOMAIN
    [ -z "$DOMAIN" ] && { err "Domain required"; exit 1; }

    ask "Enter admin email (for Let's Encrypt): " ADMIN_EMAIL
    [ -z "$ADMIN_EMAIL" ] && { err "Email required"; exit 1; }

    ask "Timezone [UTC]: " TIMEZONE
    TIMEZONE="${TIMEZONE:-UTC}"

    ask "Password for Traefik dashboard: " TRAEFIK_PASSWORD true
    [ -z "$TRAEFIK_PASSWORD" ] && { err "Password required"; exit 1; }

    # Traefik basic auth hash
    if command -v htpasswd >/dev/null; then
        TRAEFIK_AUTH_HASH=$(htpasswd -nb admin "$TRAEFIK_PASSWORD" | sed -e s/\\$/\\$\\$/g)
    else
        TRAEFIK_AUTH_HASH="admin:$(openssl passwd -apr1 "$TRAEFIK_PASSWORD" | sed -e s/\\$/\\$\\$/g)"
    fi

    # Email notifications
    if [ "$SSMTP_CONFIGURED" = true ]; then
        ask "Enable Watchtower email notifications? [Y/n]: " yn
        yn="${yn:-Y}"
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            ask "Email to send notifications to [$ADMIN_EMAIL]: " EMAIL_TO
            EMAIL_TO="${EMAIL_TO:-$ADMIN_EMAIL}"
            EMAIL_NOTIFICATIONS=true
        fi
    fi
}

create_dirs() {
    msg "Creating directories..."
    mkdir -p "${DOCKER_DIR}/infrastructure/traefik/dynamic"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/traefik/certs"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/portainer"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/netdata/config"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/netdata/data"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/netdata/cache"
    touch "${DOCKER_DIR}/infrastructure/data/traefik/certs/acme.json"
    chmod 600 "${DOCKER_DIR}/infrastructure/data/traefik/certs/acme.json"
}

create_compose() {
    msg "Creating docker-compose.yml..."
    cat > "${DOCKER_DIR}/infrastructure/docker-compose.yml" <<EOF
services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    hostname: traefik-proxy
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    environment:
      - TZ=${TIMEZONE}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik:/etc/traefik:ro
      - ./data/traefik/certs:/etc/ssl/traefik
    networks:
      - web-network
      - management-network
    labels:
      - traefik.enable=true
      - traefik.http.routers.traefik.rule=Host(\`traefik.${DOMAIN}\`)
      - traefik.http.routers.traefik.entrypoints=websecure
      - traefik.http.routers.traefik.tls.certresolver=letsencrypt
      - traefik.http.routers.traefik.middlewares=auth
      - traefik.http.middlewares.auth.basicauth.users=${TRAEFIK_AUTH_HASH}
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

  portainer:
    image: portainer/portainer-ce:latest
    container_name: portainer
    expose:
      - "9000"
    environment:
      - TZ=${TIMEZONE}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data/portainer:/data
    networks:
      - management-network
      - web-network
    labels:
      - traefik.enable=true
      - traefik.http.routers.portainer.rule=Host(\`portainer.${DOMAIN}\`)
      - traefik.http.routers.portainer.entrypoints=websecure
      - traefik.http.routers.portainer.tls.certresolver=letsencrypt
      - traefik.http.services.portainer.loadbalancer.server.port=9000
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

  netdata:
    image: netdata/netdata:latest
    container_name: netdata
    expose:
      - "19999"
    environment:
      - TZ=${TIMEZONE}
      - DOCKER_HOST=unix:///var/run/docker.sock
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /etc/passwd:/host/etc/passwd:ro
      - /etc/group:/host/etc/group:ro
      - ./data/netdata/config:/etc/netdata
      - ./data/netdata/data:/var/lib/netdata
      - ./data/netdata/cache:/var/cache/netdata
    networks:
      - management-network
      - web-network
    labels:
      - traefik.enable=true
      - traefik.http.routers.netdata.rule=Host(\`netdata.${DOMAIN}\`)
      - traefik.http.routers.netdata.entrypoints=websecure
      - traefik.http.routers.netdata.tls.certresolver=letsencrypt
      - traefik.http.services.netdata.loadbalancer.server.port=19999
      - traefik.http.routers.netdata.middlewares=auth
      - traefik.http.middlewares.auth.basicauth.users=${TRAEFIK_AUTH_HASH}
    cap_add:
      - SYS_PTRACE
    security_opt:
      - apparmor=unconfined
    restart: unless-stopped

  watchtower:
    image: containrrr/watchtower:latest
    container_name: watchtower
    environment:
      - TZ=${TIMEZONE}
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_LABEL_ENABLE=true
      - WATCHTOWER_INCLUDE_RESTARTING=true
      - WATCHTOWER_SCHEDULE=0 0 4 * * *
      - WATCHTOWER_NOTIFICATIONS=${EMAIL_NOTIFICATIONS:+email}
      - WATCHTOWER_NOTIFICATION_EMAIL_FROM=${GMAIL_USER:-alerts@${DOMAIN}}
      - WATCHTOWER_NOTIFICATION_EMAIL_TO=${EMAIL_TO}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - management-network
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true

networks:
  web-network:
    external: true
  management-network:
    external: true
EOF
}

create_traefik_config() {
    msg "Writing traefik.yml..."
    cat > "${DOCKER_DIR}/infrastructure/traefik/traefik.yml" <<EOF
api:
  dashboard: true
  insecure: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entrypoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"

certificatesResolvers:
  letsencrypt:
    acme:
      email: ${ADMIN_EMAIL}
      storage: /etc/ssl/traefik/acme.json
      httpChallenge:
        entryPoint: web

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: web-network
  file:
    directory: /etc/traefik/dynamic
    watch: true

log:
  level: INFO

accessLog: {}
EOF
}

main() {
    check_user
    check_ssmtp
    gather_config
    create_dirs
    create_compose
    create_traefik_config

    msg "✅ Setup complete."
    echo "Next steps:"
    echo "1. Ensure DNS points to this server:"
    echo "   - traefik.${DOMAIN}, portainer.${DOMAIN}, netdata.${DOMAIN}"
    echo "2. Run: cd ~/docker/infrastructure && docker compose up -d"
    echo "3. Access:"
    echo "   - https://traefik.${DOMAIN}"
    echo "   - https://portainer.${DOMAIN}"
    echo "   - https://netdata.${DOMAIN}"
    echo "Login: user=admin, password=the one you set."
    [ "$EMAIL_NOTIFICATIONS" = true ] && echo "📧 Watchtower notifications enabled for: $EMAIL_TO"
}

main "$@"