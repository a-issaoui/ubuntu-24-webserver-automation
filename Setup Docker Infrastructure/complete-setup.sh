#!/bin/bash

# Docker Environment Complete Setup Script with ssmtp Integration
# This script creates the entire Docker infrastructure for the deploy user
# Run as: ./setup-docker-stack.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables
DEPLOY_USER="deploy"
BASE_DIR="/home/$DEPLOY_USER"
DOCKER_DIR="$BASE_DIR/docker"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

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

# Function to check if running as correct user
check_user() {
    if [ "$(whoami)" != "$DEPLOY_USER" ]; then
        print_error "This script must be run as the '$DEPLOY_USER' user"
        print_status "Please run: sudo su - $DEPLOY_USER && ./$(basename $0)"
        exit 1
    fi
}

# Function to check if ssmtp is configured
check_ssmtp() {
    if [ -f /etc/ssmtp/ssmtp.conf ]; then
        print_status "✅ ssmtp is already configured"
        SSMTP_CONFIGURED=true
        # Extract Gmail user from config for notifications
        GMAIL_USER=$(grep "^AuthUser=" /etc/ssmtp/ssmtp.conf | cut -d'=' -f2 || echo "")
    else
        print_warning "ssmtp is not configured - email notifications will be disabled"
        SSMTP_CONFIGURED=false
        GMAIL_USER=""
    fi
}

# Function to gather user input
gather_config() {
    print_status "Please provide configuration details..."
    echo

    # Domain configuration
    read -p "$(echo -e ${CYAN}Enter your main domain (e.g., example.com): ${NC})" DOMAIN
    while [ -z "$DOMAIN" ]; do
        print_warning "Domain cannot be empty"
        read -p "$(echo -e ${CYAN}Enter your main domain: ${NC})" DOMAIN
    done

    # Timezone
    read -p "$(echo -e ${CYAN}Enter timezone [UTC]: ${NC})" TIMEZONE
    TIMEZONE=${TIMEZONE:-UTC}

    # Admin email
    read -p "$(echo -e ${CYAN}Enter admin email for Let's Encrypt: ${NC})" ADMIN_EMAIL
    while [ -z "$ADMIN_EMAIL" ]; do
        print_warning "Admin email cannot be empty"
        read -p "$(echo -e ${CYAN}Enter admin email: ${NC})" ADMIN_EMAIL
    done

    # Traefik dashboard password
    read -s -p "$(echo -e ${CYAN}Enter password for Traefik dashboard: ${NC})" TRAEFIK_PASSWORD
    echo
    while [ -z "$TRAEFIK_PASSWORD" ]; do
        print_warning "Password cannot be empty"
        read -s -p "$(echo -e ${CYAN}Enter password for Traefik dashboard: ${NC})" TRAEFIK_PASSWORD
        echo
    done

    # Email notifications configuration
    if [ "$SSMTP_CONFIGURED" = true ]; then
        echo
        print_status "ssmtp is configured - email notifications available"
        read -p "$(echo -e ${CYAN}Enable email notifications for Docker updates? [Y/n]: ${NC})" ENABLE_EMAIL
        ENABLE_EMAIL=${ENABLE_EMAIL:-Y}

        if [[ $ENABLE_EMAIL =~ ^[Yy]$ ]]; then
            read -p "$(echo -e ${CYAN}Email to send alerts to [$ADMIN_EMAIL]: ${NC})" EMAIL_TO
            EMAIL_TO=${EMAIL_TO:-$ADMIN_EMAIL}
            EMAIL_NOTIFICATIONS=true
        else
            EMAIL_NOTIFICATIONS=false
        fi
    else
        echo
        print_warning "Email notifications disabled (ssmtp not configured)"
        print_status "To enable email notifications:"
        print_status "1. Configure ssmtp with: sudo nano /etc/ssmtp/ssmtp.conf"
        print_status "2. Or re-run the hardening script with --install-mail-utils"
        EMAIL_NOTIFICATIONS=false
        EMAIL_TO=""
    fi

    echo
    print_status "Configuration collected successfully!"
}

# Function to create directory structure
create_directories() {
    print_status "Creating directory structure..."

    # Main directories
    mkdir -p "$DOCKER_DIR"/{infrastructure/{traefik/{dynamic},data/{traefik/certs,portainer,netdata/{config,data,cache}}},apps,scripts,backups/{infrastructure,apps}}

    # Set permissions
    chmod -R 755 "$DOCKER_DIR"
    chmod 700 "$DOCKER_DIR/infrastructure/data/traefik/certs"

    print_status "✅ Directory structure created"
}

# Function to create infrastructure docker-compose.yml
create_infrastructure_compose() {
    print_status "Creating infrastructure docker-compose.yml..."

    cat > "$DOCKER_DIR/infrastructure/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  traefik:
    container_name: traefik
    image: traefik:v3.0
    hostname: traefik-proxy
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
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
      - "traefik.http.routers.traefik.tls.certresolver=letsencrypt"
      - "traefik.http.routers.traefik.middlewares=auth"
      - "traefik.http.middlewares.auth.basicauth.users=${TRAEFIK_AUTH}"
      - "com.centurylinklabs.watchtower.enable=true"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

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
      - "traefik.http.routers.portainer.tls.certresolver=letsencrypt"
      - "traefik.http.services.portainer.loadbalancer.server.port=9000"
      - "com.centurylinklabs.watchtower.enable=true"
    security_opt:
      - no-new-privileges:true
    user: "1000:1000"
    read_only: true
    tmpfs:
      - /tmp

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
      - "traefik.http.routers.netdata.tls.certresolver=letsencrypt"
      - "traefik.http.services.netdata.loadbalancer.server.port=19999"
      - "traefik.http.routers.netdata.middlewares=auth"
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
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /etc/ssmtp/ssmtp.conf:/etc/ssmtp/ssmtp.conf:ro
    restart: unless-stopped
    networks:
      - management-network
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

networks:
  management-network:
    name: management-network
    driver: bridge
    internal: true
  web-network:
    name: web-network
    driver: bridge
    external: false
EOF

    print_status "✅ Infrastructure docker-compose.yml created"
}

# Function to create infrastructure .env file
create_infrastructure_env() {
    print_status "Creating infrastructure .env file..."

    # Generate Traefik auth hash
    if command -v htpasswd >/dev/null 2>&1; then
        TRAEFIK_AUTH_HASH=$(htpasswd -nb admin "$TRAEFIK_PASSWORD")
    else
        # Fallback to openssl if htpasswd not available
        TRAEFIK_AUTH_HASH="admin:$(openssl passwd -apr1 "$TRAEFIK_PASSWORD")"
    fi

    cat > "$DOCKER_DIR/infrastructure/.env" << EOF
# Domain Configuration
DOMAIN=$DOMAIN
TIMEZONE=$TIMEZONE

# Traefik Authentication
TRAEFIK_AUTH=$TRAEFIK_AUTH_HASH

# Email Configuration (ssmtp-based)
WATCHTOWER_NOTIFICATIONS=${EMAIL_NOTIFICATIONS:+email}
EMAIL_FROM=${GMAIL_USER:-alerts@$DOMAIN}
EMAIL_TO=$EMAIL_TO

# Netdata Cloud Integration (optional - add tokens if needed)
NETDATA_CLAIM_TOKEN=
NETDATA_CLAIM_URL=
EOF

    print_status "✅ Infrastructure .env file created"
}

# Function to create Traefik configuration
create_traefik_config() {
    print_status "Creating Traefik configuration..."

    cat > "$DOCKER_DIR/infrastructure/traefik/traefik.yml" << EOF
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
      email: $ADMIN_EMAIL
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

# Global middlewares
http:
  middlewares:
    rate-limit:
      rateLimit:
        burst: 50
        average: 20
    security-headers:
      headers:
        frameDeny: true
        sslRedirect: true
        browserXssFilter: true
        contentTypeNosniff: true
        customRequestHeaders:
          X-Forwarded-Proto: "https"
    compress:
      compress: {}
EOF

    # Create dynamic middlewares config
    cat > "$DOCKER_DIR/infrastructure/traefik/dynamic/middlewares.yml" << 'EOF'
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

    secure-headers:
      headers:
        accessControlAllowMethods:
          - GET
          - OPTIONS
          - PUT
        accessControlMaxAge: 100
        hostsProxyHeaders:
          - "X-Forwarded-Host"
        referrerPolicy: "same-origin"
EOF

    print_status "✅ Traefik configuration created"
}

# Function to create email notification scripts
create_email_scripts() {
    if [ "$EMAIL_NOTIFICATIONS" = true ]; then
        print_status "Creating email notification scripts..."

        mkdir -p "$DOCKER_DIR/infrastructure/scripts"

        # Daily status email script
        cat > "$DOCKER_DIR/infrastructure/scripts/daily-status.sh" << EOF
#!/bin/sh

# Daily Docker status email
EMAIL_TO="$EMAIL_TO"
EMAIL_FROM="${GMAIL_USER:-alerts@$DOMAIN}"
HOSTNAME=\$(hostname)
DATE=\$(date)

# Generate status report
STATUS_REPORT="/tmp/docker-status-\$\$.txt"

cat > "\$STATUS_REPORT" << EOL
Docker Infrastructure Daily Status Report
==========================================

Server: \$HOSTNAME
Date: \$DATE
Domain: $DOMAIN

Service Status:
EOL

# Check each service
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" >> "\$STATUS_REPORT"

echo "" >> "\$STATUS_REPORT"
echo "System Resources:" >> "\$STATUS_REPORT"
echo "Memory Usage: \$(free -h | grep Mem | awk '{print \$3 "/" \$2}')" >> "\$STATUS_REPORT"
echo "Disk Usage: \$(df -h / | tail -1 | awk '{print \$3 "/" \$2 " (" \$5 " used)"}')" >> "\$STATUS_REPORT"

echo "" >> "\$STATUS_REPORT"
echo "Docker Images:" >> "\$STATUS_REPORT"
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | head -10 >> "\$STATUS_REPORT"

# Send email
ssmtp "\$EMAIL_TO" << EOL
To: \$EMAIL_TO
From: \$EMAIL_FROM
Subject: Daily Docker Status - $DOMAIN

\$(cat "\$STATUS_REPORT")

--
Automated report from \$HOSTNAME
EOL

# Cleanup
rm -f "\$STATUS_REPORT"
EOF

        # Make executable
        chmod +x "$DOCKER_DIR/infrastructure/scripts/daily-status.sh"

        print_status "✅ Email notification scripts created"
    fi
}

# Function to create app template
create_app_template() {
    print_status "Creating app template..."

    mkdir -p "$DOCKER_DIR/apps/template"

    cat > "$DOCKER_DIR/apps/template/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  web:
    container_name: ${PROJECT_NAME}-web
    image: nginx:alpine
    environment:
      - TZ=${TIMEZONE:-UTC}
    volumes:
      - ./html:/usr/share/nginx/html:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    restart: unless-stopped
    networks:
      - web-network
      - app-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.${PROJECT_NAME}.rule=Host(`${DOMAIN}`)"
      - "traefik.http.routers.${PROJECT_NAME}.tls.certresolver=letsencrypt"
      - "traefik.http.services.${PROJECT_NAME}.loadbalancer.server.port=80"
      - "traefik.http.routers.${PROJECT_NAME}.middlewares=${MIDDLEWARES:-default-headers}"
      - "com.centurylinklabs.watchtower.enable=true"
    security_opt:
      - no-new-privileges:true

networks:
  web-network:
    name: web-network
    external: true
  app-network:
    name: ${PROJECT_NAME}-network
    driver: bridge
    internal: true
EOF

    cat > "$DOCKER_DIR/apps/template/.env" << 'EOF'
PROJECT_NAME=mywebsite
DOMAIN=mywebsite.com
TIMEZONE=UTC
MIDDLEWARES=default-headers,rate-limit
EOF

    # Create sample HTML
    mkdir -p "$DOCKER_DIR/apps/template/html"
    cat > "$DOCKER_DIR/apps/template/html/index.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to Your New Site</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .status { background: #e8f5e8; padding: 20px; border-radius: 4px; border-left: 4px solid #4caf50; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 Your Website is Live!</h1>
        <div class="status">
            <h3>✅ Successfully Deployed</h3>
            <p>Your Docker-based website is now running with:</p>
            <ul>
                <li>🔒 Automatic HTTPS (Let's Encrypt)</li>
                <li>🚀 Traefik reverse proxy</li>
                <li>🐳 Docker containerization</li>
                <li>📊 Monitoring with Netdata</li>
                <li>⚙️ Management with Portainer</li>
                <li>📧 Email notifications (ssmtp)</li>
            </ul>
        </div>
        <p><strong>Next steps:</strong></p>
        <ol>
            <li>Replace this template with your actual website content</li>
            <li>Configure your domain's DNS to point to this server</li>
            <li>Monitor your site through the Netdata dashboard</li>
        </ol>
        <p style="text-align: center; color: #666; margin-top: 40px;">
            Powered by Docker 🐳 | Secured by Traefik 🔒 | Notifications by ssmtp 📧
        </p>
    </div>
</body>
</html>
EOF

    # Create basic nginx config
    cat > "$DOCKER_DIR/apps/template/nginx.conf" << 'EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    server {
        listen 80;
        server_name _;

        root /usr/share/nginx/html;
        index index.html index.htm;

        location / {
            try_files $uri $uri/ =404;
        }

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        # Cache static assets
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
}
EOF

    print_status "✅ App template created"
}

# Function to create management scripts
create_scripts() {
    print_status "Creating management scripts..."

    # Setup script
    cat > "$DOCKER_DIR/scripts/setup.sh" << 'EOF'
#!/bin/bash
set -e

echo "🚀 Setting up Docker infrastructure..."

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Create networks if they don't exist
docker network ls | grep -q "web-network" || docker network create web-network
docker network ls | grep -q "management-network" || docker network create management-network

# Start infrastructure
cd ~/docker/infrastructure
echo "🔧 Starting infrastructure services..."
docker compose up -d

echo "✅ Infrastructure setup complete!"
echo "📊 Access your services at:"
echo "   - Traefik Dashboard: https://traefik.yourdomain.com"
echo "   - Portainer: https://portainer.yourdomain.com"
echo "   - Netdata: https://netdata.yourdomain.com"
echo ""
echo "🔐 Use 'admin' as username and the password you set during setup"

# Test email if configured
if [ -f /etc/ssmtp/ssmtp.conf ] && [ ! -z "$EMAIL_TO" ]; then
    echo "📧 Testing email notification..."
    echo "Docker infrastructure started successfully on $(hostname) at $(date)" | \
        ssmtp "$EMAIL_TO" || echo "⚠️  Email test failed - check ssmtp configuration"
fi
EOF

    # Deploy app script
    cat > "$DOCKER_DIR/scripts/deploy-app.sh" << 'EOF'
#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <app-name>"
    echo "Example: $0 myblog"
    exit 1
fi

APP_NAME=$1
APP_DIR=~/docker/apps/$APP_NAME

if [ ! -d "$APP_DIR" ]; then
    echo "❌ App directory $APP_DIR does not exist"
    exit 1
fi

cd "$APP_DIR"
echo "🚀 Deploying $APP_NAME..."
docker compose pull
docker compose up -d

echo "✅ $APP_NAME deployed successfully!"
docker compose ps

# Send deployment notification
if [ -f /etc/ssmtp/ssmtp.conf ] && [ ! -z "$EMAIL_TO" ]; then
    echo "Application $APP_NAME deployed successfully on $(hostname) at $(date)" | \
        ssmtp "$EMAIL_TO" || echo "⚠️  Email notification failed"
fi
EOF

    # Backup script
    cat > "$DOCKER_DIR/scripts/backup.sh" << 'EOF'
#!/bin/bash
set -e

BACKUP_DIR=~/docker/backups
DATE=$(date +%Y%m%d_%H%M%S)

echo "📦 Creating backup..."

# Backup infrastructure data
tar -czf "$BACKUP_DIR/infrastructure/infrastructure_$DATE.tar.gz" \
    -C ~/docker/infrastructure/data .

# Backup each app
for app_dir in ~/docker/apps/*/; do
    if [ -d "$app_dir" ]; then
        app_name=$(basename "$app_dir")
        if [ "$app_name" != "template" ] && [ -d "$app_dir/data" ]; then
            tar -czf "$BACKUP_DIR/apps/${app_name}_$DATE.tar.gz" \
                -C "$app_dir/data" .
        fi
    fi
done

echo "✅ Backup completed in $BACKUP_DIR"
echo "📁 Files created:"
ls -la "$BACKUP_DIR"/{infrastructure,apps}/*_$DATE.tar.gz 2>/dev/null || true

# Send backup notification
if [ -f /etc/ssmtp/ssmtp.conf ] && [ ! -z "$EMAIL_TO" ]; then
    echo "Backup completed successfully on $(hostname) at $(date). Files: $(ls "$BACKUP_DIR"/{infrastructure,apps}/*_$DATE.tar.gz 2>/dev/null | wc -l) archives created." | \
        ssmtp "$EMAIL_TO" || echo "⚠️  Email notification failed"
fi
EOF

    # Email test script
    cat > "$DOCKER_DIR/scripts/test-email.sh" << EOF
#!/bin/bash

if [ ! -f /etc/ssmtp/ssmtp.conf ]; then
    echo "❌ ssmtp is not configured"
    echo "Configure with: sudo nano /etc/ssmtp/ssmtp.conf"
    exit 1
fi

EMAIL_TO="\${1:-$EMAIL_TO}"
if [ -z "\$EMAIL_TO" ]; then
    echo "Usage: \$0 <email-address>"
    echo "Example: \$0 admin@example.com"
    exit 1
fi

echo "📧 Sending test email to \$EMAIL_TO..."

cat << EOL | ssmtp "\$EMAIL_TO"
To: \$EMAIL_TO
From: ${GMAIL_USER:-alerts@$DOMAIN}
Subject: Docker Infrastructure Test Email

This is a test email from your Docker infrastructure.

Server: \$(hostname)
Date: \$(date)
Domain: $DOMAIN

Services Status:
\$(docker ps --format "table {{.Names}}\t{{.Status}}")

--
Automated test from your Docker infrastructure
EOL

echo "✅ Test email sent successfully!"
EOF

    # Make scripts executable
    chmod +x "$DOCKER_DIR/scripts"/*.sh

    print_status "✅ Management scripts created"
}

# Function to enhance .bashrc
enhance_bashrc() {
    print_status "Enhancing .bashrc with Docker aliases..."

    # Check if our additions already exist
    if ! grep -q "# Docker Management Aliases" "$BASE_DIR/.bashrc"; then
        cat >> "$BASE_DIR/.bashrc" << 'EOF'

# Docker Management Aliases
alias dc='docker compose'
alias dcu='docker compose up -d'
alias dcd='docker compose down'
alias dcl='docker compose logs -f'
alias dcp='docker compose ps'
alias dcr='docker compose restart'

# Quick navigation
alias cdinfra='cd ~/docker/infrastructure'
alias cdapps='cd ~/docker/apps'
alias cdscripts='cd ~/docker/scripts'

# Management functions
docker-status() {
    echo "🐳 Infrastructure Services:"
    cd ~/docker/infrastructure && docker compose ps
    echo ""
    echo "🌐 Web Applications:"
    for app in ~/docker/apps/*/; do
        if [ -d "$app" ] && [ -f "$app/docker-compose.yml" ] && [ "$(basename "$app")" != "template" ]; then
            app_name=$(basename "$app")
            echo "  📁 $app_name:"
            cd "$app" && docker compose ps | tail -n +2 | sed 's/^/    /'
        fi
    done
}

docker-logs() {
    if [ -z "$1" ]; then
        echo "Usage: docker-logs <service-name>"
        return 1
    fi
    docker logs -f --tail=100 "$1"
}

new-app() {
    if [ -z "$1" ]; then
        echo "Usage: new-app <app-name>"
        return 1
    fi

    APP_NAME=$1
    mkdir -p ~/docker/apps/$APP_NAME
    cp -r ~/docker/apps/template/* ~/docker/apps/$APP_NAME/

    # Update template values
    sed -i "s/mywebsite/$APP_NAME/g" ~/docker/apps/$APP_NAME/.env

    echo "✅ New app created: ~/docker/apps/$APP_NAME"
    echo "📝 Edit ~/docker/apps/$APP_NAME/.env to configure your app"
}

# Email functions
send-email() {
    if [ ! -f /etc/ssmtp/ssmtp.conf ]; then
        echo "❌ ssmtp not configured"
        return 1
    fi

    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: send-email <recipient> <subject> [message]"
        echo "Example: send-email admin@example.com 'Server Alert' 'Everything is fine'"
        return 1
    fi

    TO="$1"
    SUBJECT="$2"
    MESSAGE="${3:-Alert from $(hostname)}"

    cat << EOL | ssmtp "$TO"
To: $TO
Subject: $SUBJECT

$MESSAGE

--
Sent from $(hostname) at $(date)
EOL

    echo "✅ Email sent to $TO"
}

test-email() {
    ~/docker/scripts/test-email.sh "$@"
}

# Show Docker status on login
if [ -d ~/docker/infrastructure ]; then
    echo "🐳 Docker Environment Ready"
    echo "💡 Type 'docker-status' to see all services"
    echo "💡 Type 'new-app <name>' to create a new website"
    if [ -f /etc/ssmtp/ssmtp.conf ]; then
        echo "📧 Email notifications enabled - type 'test-email' to test"
    fi
fi
EOF

        print_status "✅ .bashrc enhanced with Docker aliases"
    else
        print_warning ".bashrc already contains Docker aliases, skipping"
    fi
}

# Function to create DNS instructions
create_dns_instructions() {
    print_status "Creating DNS setup instructions..."

    cat > "$DOCKER_DIR/DNS-SETUP.md" << EOF
# 🌐 DNS Configuration Instructions

To complete your Docker infrastructure setup, you need to configure DNS records for your domain.

## Required DNS Records

Point the following subdomains to your server IP address (\`$(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")\`):

### A Records (IPv4)
\`\`\`
traefik.$DOMAIN     → $(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")
portainer.$DOMAIN   → $(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")
netdata.$DOMAIN     → $(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")
\`\`\`

### For Each Website/App
\`\`\`
yourwebsite.$DOMAIN → $(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")
blog.$DOMAIN        → $(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")
shop.$DOMAIN        → $(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")
\`\`\`

## Example: Cloudflare Setup

1. Log in to your Cloudflare dashboard
2. Select your domain ($DOMAIN)
3. Go to DNS → Records
4. Add A records:
   - Name: \`traefik\`, Content: \`$(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")\`, Proxy: 🟡 (DNS only)
   - Name: \`portainer\`, Content: \`$(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")\`, Proxy: 🟡 (DNS only)
   - Name: \`netdata\`, Content: \`$(curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")\`, Proxy: 🟡 (DNS only)

## Testing DNS Propagation

\`\`\`bash
# Test if DNS is working
nslookup traefik.$DOMAIN
nslookup portainer.$DOMAIN
nslookup netdata.$DOMAIN
\`\`\`

## Email Configuration Status

EOF

    if [ "$SSMTP_CONFIGURED" = true ]; then
        cat >> "$DOCKER_DIR/DNS-SETUP.md" << EOF
✅ **ssmtp is configured** - Email notifications are enabled

Test email functionality:
\`\`\`bash
~/docker/scripts/test-email.sh your-email@domain.com
\`\`\`
EOF
    else
        cat >> "$DOCKER_DIR/DNS-SETUP.md" << EOF
⚠️  **ssmtp is not configured** - Email notifications are disabled

To enable email notifications:
1. Configure ssmtp: \`sudo nano /etc/ssmtp/ssmtp.conf\`
2. Or re-run the hardening script with \`--install-mail-utils\`

Example ssmtp configuration:
\`\`\`
root=your-email@gmail.com
mailhub=smtp.gmail.com:587
rewriteDomain=gmail.com
AuthUser=your-email@gmail.com
AuthPass=your-app-password
FromLineOverride=YES
UseSTARTTLS=YES
\`\`\`
EOF
    fi

    cat >> "$DOCKER_DIR/DNS-SETUP.md" << EOF

## After DNS is Configured

1. Wait for DNS propagation (can take up to 48 hours, usually 5-15 minutes)
2. Run the setup script: \`~/docker/scripts/setup.sh\`
3. Access your services:
   - Traefik: https://traefik.$DOMAIN
   - Portainer: https://portainer.$DOMAIN
   - Netdata: https://netdata.$DOMAIN

**Login credentials:** Username: \`admin\`, Password: (the one you set during setup)

## Email Notifications

If email is configured, you'll receive notifications for:
- Docker container updates (Watchtower)
- Application deployments
- Backup completions

## Troubleshooting

### Email Issues
\`\`\`bash
# Test ssmtp configuration
sudo ssmtp your-email@domain.com
# Type your message and press Ctrl+D

# Check ssmtp config
sudo cat /etc/ssmtp/ssmtp.conf

# Manual email test
echo "Test message" | ssmtp your-email@domain.com
\`\`\`

### Container Issues
\`\`\`bash
# Check all services
docker-status

# View logs
docker logs -f traefik
docker logs -f watchtower

# Restart infrastructure
cd ~/docker/infrastructure && docker compose restart
\`\`\`
EOF

    print_status "✅ DNS setup instructions created: $DOCKER_DIR/DNS-SETUP.md"
}

# Function to setup email cron job if enabled
setup_email_cron() {
    if [ "$EMAIL_NOTIFICATIONS" = true ]; then
        print_status "Setting up email cron job for daily reports..."

        # Add cron job for daily status email (7 AM)
        (crontab -l 2>/dev/null || echo "") | grep -v "docker-daily-status" | \
        { cat; echo "0 7 * * * $DOCKER_DIR/scripts/test-email.sh $EMAIL_TO >/dev/null 2>&1 # docker-daily-status"; } | \
        crontab -

        print_status "✅ Daily email report scheduled for 7:00 AM"
    fi
}

# Function to display final instructions
show_final_instructions() {
    echo
    print_header
    echo -e "${GREEN}
🎉 SETUP COMPLETE! 🎉

Your Docker infrastructure has been successfully created with:

📁 Directory Structure:
   ~/docker/infrastructure/     - Core services (Traefik, Portainer, Netdata)
   ~/docker/apps/              - Your websites and applications
   ~/docker/scripts/           - Management scripts
   ~/docker/backups/           - Backup storage

🔧 Management Tools:
   docker-status              - Check all services
   new-app <name>            - Create new website
   ~/docker/scripts/setup.sh  - Start infrastructure"

    if [ "$EMAIL_NOTIFICATIONS" = true ]; then
        echo -e "   send-email <to> <subject>     - Send email via ssmtp
   test-email [address]      - Test email functionality"
    fi

    echo -e "
🌐 Your Services (after DNS setup):
   https://traefik.$DOMAIN     - Traefik Dashboard
   https://portainer.$DOMAIN   - Docker Management
   https://netdata.$DOMAIN     - System Monitoring"

    if [ "$EMAIL_NOTIFICATIONS" = true ]; then
        echo -e "
📧 Email Notifications: ✅ ENABLED
   Recipient: $EMAIL_TO
   Daily reports: 7:00 AM
   Updates: Watchtower alerts
   Deployments: Automatic notifications"
    else
        echo -e "
📧 Email Notifications: ❌ DISABLED
   Reason: ssmtp not configured
   To enable: Configure /etc/ssmtp/ssmtp.conf"
    fi

    echo -e "
📋 NEXT STEPS:

1️⃣  Configure DNS records (see ~/docker/DNS-SETUP.md)
2️⃣  Run: ~/docker/scripts/setup.sh
3️⃣  Create your first website: new-app mysite
4️⃣  Edit ~/docker/apps/mysite/.env with your domain
5️⃣  Deploy: ~/docker/scripts/deploy-app.sh mysite"

    if [ "$EMAIL_NOTIFICATIONS" = true ]; then
        echo -e "6️⃣  Test email: test-email $EMAIL_TO"
    fi

    echo -e "
🔐 Login: admin / (your password)

${NC}Ready to deploy! 🚀"
}

# Main execution
main() {
    print_header

    # Check prerequisites
    check_user

    # Check if Docker is available
    if ! command -v docker >/dev/null 2>&1; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    # Check ssmtp configuration
    check_ssmtp

    # Gather configuration
    gather_config

    # Create everything
    create_directories
    create_infrastructure_compose
    create_infrastructure_env
    create_traefik_config
    create_email_scripts
    create_app_template
    create_scripts
    enhance_bashrc
    create_dns_instructions
    setup_email_cron

    # Final instructions
    show_final_instructions
}

# Run main function
main "$@"
