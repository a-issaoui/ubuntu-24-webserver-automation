#!/usr/bin/env bash
# ------------------------------------------------------------------
# Docker Environment Complete Setup Script with ssmtp Integration
# Fixed version matching docker-compose.yml structure
# Run as the 'deploy' user (recommended):
#   sudo su - deploy
#   ./setup-docker-stack.sh
# ------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables (defaults)
DEPLOY_USER="deploy"
BASE_DIR="/home/${DEPLOY_USER}"
DOCKER_DIR="${BASE_DIR}/docker"

# State variables (populated later)
SSMTP_CONFIGURED=false
GMAIL_USER=""
EMAIL_NOTIFICATIONS=false
EMAIL_TO=""
ADMIN_EMAIL=""
DOMAIN=""
TIMEZONE="UTC"
TRAEFIK_PASSWORD=""
TRAEFIK_AUTH=""

# Helpers for printing
print_status() { echo -e "${GREEN}[INFO]${NC} $*"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }
print_debug() { echo -e "${BLUE}[DEBUG]${NC} $*"; }
print_header() {
    echo -e "${PURPLE}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  🐳 Docker Infrastructure Complete Setup Script             ║
║                                                              ║
║  This script will create a production-ready Docker          ║
║  environment with Traefik, Portainer, Netdata & more        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝${NC}"
}

# Read input into a variable (safe variable name assignment)
read_input() {
    local prompt="$1"
    local var_name="$2"
    local is_password=${3:-false}
    local value

    echo -en "${CYAN}${prompt}${NC}"

    if [ "$is_password" = true ]; then
        read -r -s value || true
        echo
    else
        read -r value || true
    fi

    printf -v "$var_name" "%s" "$value"
}

# Check we are running as the expected user
check_user() {
    if [ "$(whoami)" != "$DEPLOY_USER" ]; then
        print_error "This script must be run as the '$DEPLOY_USER' user"
        print_status "Please run: sudo su - $DEPLOY_USER && ./$(basename "$0")"
        exit 1
    fi
}
# Detect ssmtp and try to read AuthUser if available
check_ssmtp() {
    if command -v ssmtp >/dev/null 2>&1; then
        print_status "ssmtp command found"
        SSMTP_CONFIGURED=true

        if [ -r /etc/ssmtp/ssmtp.conf ]; then
            GMAIL_USER=$(grep -E '^AuthUser=' /etc/ssmtp/ssmtp.conf 2>/dev/null | cut -d'=' -f2- || true)
        else
            if sudo -n test -r /etc/ssmtp/ssmtp.conf 2>/dev/null; then
                GMAIL_USER=$(sudo grep -E '^AuthUser=' /etc/ssmtp/ssmtp.conf 2>/dev/null | cut -d'=' -f2- || true)
            fi
        fi

        if [ -n "$GMAIL_USER" ]; then
            print_status "Email configured with: $GMAIL_USER"
        else
            print_status "Email system detected but couldn't read configuration"
            GMAIL_USER=""
        fi
    else
        print_warning "ssmtp is not installed - email notifications will be disabled"
        SSMTP_CONFIGURED=false
        GMAIL_USER=""
    fi
}

# Gather configuration interactively
gather_config() {
    print_status "Please provide configuration details..."
    echo

    # Domain
    while true; do
        read_input "Enter your main domain (e.g., example.com): " DOMAIN
        if [ -n "$DOMAIN" ]; then break; fi
        print_warning "Domain cannot be empty"
    done

    # Timezone
    read_input "Enter timezone [UTC]: " TIMEZONE
    TIMEZONE=${TIMEZONE:-UTC}

    # Admin email for Let's Encrypt
    while true; do
        read_input "Enter admin email for Let's Encrypt: " ADMIN_EMAIL
        if [ -n "$ADMIN_EMAIL" ]; then break; fi
        print_warning "Admin email cannot be empty"
    done

    # Traefik dashboard password
    while true; do
        read_input "Enter password for Traefik dashboard: " TRAEFIK_PASSWORD true
        if [ -n "$TRAEFIK_PASSWORD" ]; then break; fi
        print_warning "Password cannot be empty"
    done

    # Email notifications
    echo
    if [ "$SSMTP_CONFIGURED" = true ]; then
        print_status "Email system is configured - notifications available"
        read_input "Enable email notifications for Docker updates? [Y/n]: " ENABLE_EMAIL
        ENABLE_EMAIL=${ENABLE_EMAIL:-Y}

        if [[ "$ENABLE_EMAIL" =~ ^[Yy]$ ]]; then
            read_input "Email to send alerts to [$ADMIN_EMAIL]: " EMAIL_TO_INPUT
            EMAIL_TO=${EMAIL_TO_INPUT:-$ADMIN_EMAIL}

            if [[ ! "$EMAIL_TO" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
                print_warning "Invalid email format, using admin email instead"
                EMAIL_TO=$ADMIN_EMAIL
            fi

            EMAIL_NOTIFICATIONS=true
            print_status "Email notifications will be sent to: $EMAIL_TO"
        else
            EMAIL_NOTIFICATIONS=false
            EMAIL_TO=""
        fi
    else
        print_warning "Email notifications disabled (ssmtp not configured)"
        EMAIL_NOTIFICATIONS=false
        EMAIL_TO=""
    fi

    print_status "Configuration collected successfully!"
}

# Create directories
create_directories() {
    print_status "Creating directory structure..."

    if [ -d "$DOCKER_DIR" ]; then
        print_warning "Docker directory already exists at $DOCKER_DIR"
        read_input "Do you want to remove it and start fresh? [y/N]: " REMOVE_OLD
        if [[ "$REMOVE_OLD" =~ ^[Yy]$ ]]; then
            local backup_dest="${DOCKER_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
            print_status "Backing up old docker directory to: $backup_dest"
            mv -- "$DOCKER_DIR" "$backup_dest"
        else
            print_status "Keeping existing directory structure"
            return 0
        fi
    fi

    mkdir -p "${DOCKER_DIR}/infrastructure/traefik/dynamic"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/traefik/certs"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/portainer"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/netdata/config"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/netdata/data"
    mkdir -p "${DOCKER_DIR}/infrastructure/data/netdata/cache"
    mkdir -p "${DOCKER_DIR}/apps/template/html"
    mkdir -p "${DOCKER_DIR}/scripts"
    mkdir -p "${DOCKER_DIR}/backups/infrastructure"
    mkdir -p "${DOCKER_DIR}/backups/apps"

    chmod -R 755 "$DOCKER_DIR"
    chmod 700 "${DOCKER_DIR}/infrastructure/data/traefik/certs" || true

    touch "${DOCKER_DIR}/infrastructure/data/traefik/certs/acme.json"
    chmod 600 "${DOCKER_DIR}/infrastructure/data/traefik/certs/acme.json" || true

    print_status "Directory structure created successfully"
}
# Create docker-compose for infrastructure (FIXED VERSION)
create_infrastructure_compose() {
    print_status "Creating infrastructure docker-compose.yml..."

    cat > "${DOCKER_DIR}/infrastructure/docker-compose.yml" <<'EOF'
version: "3.9"

services:
  traefik:
    container_name: traefik
    image: traefik:v3.1
    hostname: traefik-proxy
    command:
      - --ping
      - --ping.entrypoint=ping
      - --entrypoints.ping.address=:8082
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"   # Dashboard
      - "8082:8082"   # Healthcheck (ping)
    environment:
      - TZ=${TIMEZONE:-UTC}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik:/etc/traefik:ro
      - ./data/traefik/certs:/etc/ssl/traefik
    restart: unless-stopped
    networks:
      - web-network
      - management-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik.rule=Host(`traefik.${DOMAIN}`)"
      - "traefik.http.routers.traefik.entrypoints=websecure"
      - "traefik.http.routers.traefik.tls.certresolver=letsencrypt"
      - "traefik.http.routers.traefik.service=api@internal"
      - "traefik.http.routers.traefik.middlewares=auth"
      - "traefik.http.middlewares.auth.basicauth.users=${TRAEFIK_AUTH}"
      - "com.centurylinklabs.watchtower.enable=true"
    security_opt:
      - no-new-privileges:true

  portainer:
    container_name: portainer
    image: portainer/portainer-ce:latest
    hostname: portainer-manager
    expose:
      - "9000"
    environment:
      - TZ=${TIMEZONE:-UTC}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data/portainer:/data
    restart: unless-stopped
    networks:
      - management-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.portainer.rule=Host(`portainer.${DOMAIN}`)"
      - "traefik.http.routers.portainer.entrypoints=websecure"
      - "traefik.http.routers.portainer.tls.certresolver=letsencrypt"
      - "traefik.http.services.portainer.loadbalancer.server.port=9000"
      - "com.centurylinklabs.watchtower.enable=true"
    security_opt:
      - no-new-privileges:true

  netdata:
    container_name: netdata
    image: netdata/netdata:latest
    hostname: netdata-monitor
    expose:
      - "19999"
    environment:
      - TZ=${TIMEZONE:-UTC}
      - DOCKER_HOST=unix:///var/run/docker.sock
      - NETDATA_CLAIM_TOKEN=${NETDATA_CLAIM_TOKEN:-}
      - NETDATA_CLAIM_URL=${NETDATA_CLAIM_URL:-}
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /etc/passwd:/host/etc/passwd:ro
      - /etc/group:/host/etc/group:ro
      - ./data/netdata/config:/etc/netdata
      - ./data/netdata/data:/var/lib/netdata
      - ./data/netdata/cache:/var/cache/netdata
    cap_add:
      - SYS_PTRACE
      - SYS_ADMIN
    security_opt:
      - apparmor=unconfined
    restart: unless-stopped
    networks:
      - management-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.netdata.rule=Host(`netdata.${DOMAIN}`)"
      - "traefik.http.routers.netdata.entrypoints=websecure"
      - "traefik.http.routers.netdata.tls.certresolver=letsencrypt"
      - "traefik.http.services.netdata.loadbalancer.server.port=19999"
      - "traefik.http.routers.netdata.middlewares=auth"
      - "traefik.http.middlewares.auth.basicauth.users=${TRAEFIK_AUTH}"
      - "com.centurylinklabs.watchtower.enable=true"

  watchtower:
    container_name: watchtower
    image: containrrr/watchtower:latest
    hostname: watchtower-updater
    environment:
      - TZ=${TIMEZONE:-UTC}
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_LABEL_ENABLE=true
      - WATCHTOWER_INCLUDE_RESTARTING=true
      - WATCHTOWER_SCHEDULE=0 0 4 * * *
      - WATCHTOWER_NOTIFICATIONS=${WATCHTOWER_NOTIFICATIONS:-}
      - WATCHTOWER_NOTIFICATION_EMAIL_FROM=${EMAIL_FROM:-}
      - WATCHTOWER_NOTIFICATION_EMAIL_TO=${EMAIL_TO:-}
      - WATCHTOWER_NOTIFICATION_EMAIL_SERVER=smtp.gmail.com
      - WATCHTOWER_NOTIFICATION_EMAIL_SERVER_PORT=587
      - WATCHTOWER_NOTIFICATION_EMAIL_SERVER_USER=${EMAIL_FROM:-}
      - WATCHTOWER_NOTIFICATION_EMAIL_DELAY=2
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped
    networks:
      - management-network
    security_opt:
      - no-new-privileges:true

networks:
  management-network:
    external: true
    name: management-network
  web-network:
    external: true
    name: web-network
EOF

    print_status "Infrastructure docker-compose.yml created"
}
# Create .env file (FIXED for proper escaping)
create_infrastructure_env() {
    print_status "Creating infrastructure .env file..."

    # Create password hash for Traefik basic auth
    if command -v htpasswd >/dev/null 2>&1; then
        TRAEFIK_AUTH_RAW=$(htpasswd -nb admin "$TRAEFIK_PASSWORD" 2>/dev/null || true)
    else
        TRAEFIK_AUTH_RAW="admin:$(openssl passwd -apr1 "$TRAEFIK_PASSWORD")"
    fi

    # Escape $ to $$ for docker-compose
    TRAEFIK_AUTH=${TRAEFIK_AUTH_RAW//$/\$\$}

    # Determine email notification setting
    if [ "$EMAIL_NOTIFICATIONS" = true ]; then
        WATCHTOWER_NOTIFICATIONS="email"
    else
        WATCHTOWER_NOTIFICATIONS=""
    fi

    # Write .env
    cat > "${DOCKER_DIR}/infrastructure/.env" <<EOF
# Domain Configuration
DOMAIN=${DOMAIN}
TIMEZONE=${TIMEZONE}

# Traefik Authentication
TRAEFIK_AUTH=${TRAEFIK_AUTH}

# Email Configuration (ssmtp-based)
WATCHTOWER_NOTIFICATIONS=${WATCHTOWER_NOTIFICATIONS}
EMAIL_FROM=${GMAIL_USER:-alerts@${DOMAIN}}
EMAIL_TO=${EMAIL_TO}

# Netdata Cloud Integration (optional - add tokens if needed)
NETDATA_CLAIM_TOKEN=
NETDATA_CLAIM_URL=
EOF

    print_status ".env file created"
}

# Create Traefik configuration files
create_traefik_config() {
    print_status "Creating Traefik configuration..."

    cat > "${DOCKER_DIR}/infrastructure/traefik/traefik.yml" <<EOF
api:
  dashboard: true
  debug: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entrypoint:
          to: websecure
          scheme: https
          permanent: true
  websecure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt
  ping:
    address: ":8082"

certificatesResolvers:
  letsencrypt:
    acme:
      email: ${ADMIN_EMAIL}
      storage: /etc/ssl/traefik/acme.json
      httpChallenge:
        entryPoint: web
      # caServer: https://acme-staging-v02.api.letsencrypt.org/directory # Uncomment for testing

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: web-network
  file:
    directory: /etc/traefik/dynamic
    watch: true

ping:
  entryPoint: ping

log:
  level: INFO

accessLog: {}
EOF

    # Create dynamic configuration for middlewares
    cat > "${DOCKER_DIR}/infrastructure/traefik/dynamic/middlewares.yml" <<'EOF'
http:
  middlewares:
    default-headers:
      headers:
        frameDeny: true
        sslRedirect: true
        browserXssFilter: true
        contentTypeNosniff: true
        forceSTSHeader: true
        stsIncludeSubdomains: true
        stsPreload: true
        stsSeconds: 31536000
        customRequestHeaders:
          X-Forwarded-Proto: "https"

    rate-limit:
      rateLimit:
        average: 100
        burst: 50

    auth:
      basicAuth:
        usersFile: /etc/traefik/users
EOF

    print_status "Traefik configuration created"
}
