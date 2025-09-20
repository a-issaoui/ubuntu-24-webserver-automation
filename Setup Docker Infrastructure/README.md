# 🐳 Docker Infrastructure Complete Setup Script

[![Docker](https://img.shields.io/badge/Docker-CE-2496ED?style=flat&logo=docker)](https://docker.com/)
[![Traefik](https://img.shields.io/badge/Traefik-v3.0-24A1C1?style=flat&logo=traefik)](https://traefik.io/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=flat&logo=ubuntu)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A **comprehensive, production-ready** Docker infrastructure setup script that creates a complete web hosting environment with reverse proxy, monitoring, management tools, and email notifications. Designed to work seamlessly with the Ubuntu 24.04 hardening script.

---

## ✨ Features

### Core Infrastructure

- **🚀 Traefik v3.0** - Automatic HTTPS with Let's Encrypt, modern reverse proxy
- **📊 Portainer CE** - Intuitive Docker container management interface
- **📈 Netdata** - Real-time system and container monitoring
- **🔄 Watchtower** - Automated container updates with notifications
- **📧 Email Integration** - Uses existing ssmtp configuration for notifications

### Security & Best Practices

- **🔒 Security Headers** - Comprehensive HTTP security headers via Traefik
- **🛡️ Container Security** - Read-only containers, no-new-privileges, proper user isolation
- **🌐 Network Isolation** - Separate networks for web and management traffic
- **🔐 Authentication** - Password-protected dashboards with htpasswd

### Developer Experience

- **⚡ Quick App Deployment** - Template-based website creation
- **🎯 Zero-Downtime Updates** - Rolling updates with health checks
- **📝 Rich Documentation** - Comprehensive guides and troubleshooting
- **🔧 Management Scripts** - Automated backup, deployment, and maintenance

---

## 📋 Prerequisites

| Requirement          | Details                                           |
| -------------------- | ------------------------------------------------- |
| **Operating System** | Ubuntu 24.04 LTS (hardened with companion script) |
| **User Account**     | Non-root user (`deploy`) with Docker access       |
| **Docker**           | Docker CE with Docker Compose v2                  |
| **Domain**           | Registered domain with DNS control                |
| **Email (Optional)** | Configured ssmtp for notifications                |
| **Resources**        | Min: 2GB RAM, 20GB disk space                     |

### Compatibility with Hardening Script

This script is designed to work with the companion Ubuntu 24.04 hardening script:

```bash
# 1. Run hardening script first
./harden-docker.sh \
  --ssh-key "ssh-ed25519 AAAAC3NzaC1..." \
  --install-mail-utils \
  --gmail-user "alerts@yourdomain.com" \
  --gmail-app-password "abcdefghijklmnop" \
  --email "admin@yourdomain.com"

# 2. Then run this infrastructure setup
sudo su - deploy
./complete-setup.sh
```

---

## 🚀 Quick Start

### 1. Download and Prepare

```bash
# Switch to deploy user (created by hardening script)
sudo su - deploy

# Download the script
wget https://raw.githubusercontent.com/your-repo/complete-setup.sh
chmod +x complete-setup.sh
```

### 2. Run Interactive Setup

```bash
./complete-setup.sh
```

The script will prompt you for:

- **Domain name** (e.g., `example.com`)
- **Timezone** (e.g., `America/New_York`)
- **Admin email** (for Let's Encrypt certificates)
- **Traefik dashboard password**
- **Email notifications** (if ssmtp is configured)

### 3. Configure DNS Records

Follow the generated `~/docker/DNS-SETUP.md` instructions:

```bash
# Required A records pointing to your server IP
traefik.yourdomain.com    → YOUR_SERVER_IP
portainer.yourdomain.com  → YOUR_SERVER_IP
netdata.yourdomain.com    → YOUR_SERVER_IP
```

### 4. Start Infrastructure

```bash
~/docker/scripts/setup.sh
```

### 5. Access Your Services

- **Traefik Dashboard**: `https://traefik.yourdomain.com`
- **Portainer**: `https://portainer.yourdomain.com`
- **Netdata**: `https://netdata.yourdomain.com`

**Login**: Username `admin` with your chosen password

---

## 📁 Directory Structure

```
~/docker/
├── infrastructure/           # Core services
│   ├── docker-compose.yml   # Main infrastructure stack
│   ├── .env                 # Environment configuration
│   ├── traefik/             # Traefik configuration
│   │   ├── traefik.yml      # Main Traefik config
│   │   └── dynamic/         # Dynamic configuration
│   └── data/                # Persistent data
│       ├── traefik/certs/   # SSL certificates
│       ├── portainer/       # Portainer data
│       └── netdata/         # Netdata data
├── apps/                    # Your applications
│   ├── template/            # App template
│   └── [your-apps]/         # Individual applications
├── scripts/                 # Management scripts
│   ├── setup.sh            # Infrastructure startup
│   ├── deploy-app.sh       # App deployment
│   ├── backup.sh           # Backup creation
│   └── test-email.sh       # Email testing
├── backups/                # Backup storage
│   ├── infrastructure/     # Infrastructure backups
│   └── apps/               # Application backups
└── DNS-SETUP.md            # DNS configuration guide
```

---

## 🔧 Configuration Details

### Infrastructure Services

#### Traefik (Reverse Proxy)

- **Purpose**: Automatic HTTPS, load balancing, routing
- **Features**: Let's Encrypt integration, security headers, rate limiting
- **Access**: `https://traefik.yourdomain.com`
- **Config**: `~/docker/infrastructure/traefik/traefik.yml`

#### Portainer (Container Management)

- **Purpose**: Web-based Docker management interface
- **Features**: Container logs, stats, terminal access, stack management
- **Access**: `https://portainer.yourdomain.com`
- **Data**: `~/docker/infrastructure/data/portainer/`

#### Netdata (Monitoring)

- **Purpose**: Real-time system and container monitoring
- **Features**: Performance metrics, alerts, dashboards
- **Access**: `https://netdata.yourdomain.com`
- **Data**: `~/docker/infrastructure/data/netdata/`

#### Watchtower (Auto-Updates)

- **Purpose**: Automated container updates
- **Schedule**: Daily at 4:00 AM
- **Features**: Email notifications, cleanup, label-based filtering
- **Logs**: `docker logs -f watchtower`

### Email Integration

The script integrates with ssmtp for notifications:

```bash
# Check email configuration status
cat /etc/ssmtp/ssmtp.conf

# Test email functionality
~/docker/scripts/test-email.sh admin@yourdomain.com

# Manual email sending
echo "Test message" | ssmtp recipient@domain.com
```

**Email Notifications Include:**

- Infrastructure startup/shutdown
- Application deployments
- Backup completions
- Container updates (Watchtower)
- Daily status reports (optional)

---

## 🌐 Application Deployment

### Creating a New Website

```bash
# Create new application
new-app myblog

# Configure the application
cd ~/docker/apps/myblog
nano .env  # Set PROJECT_NAME=myblog, DOMAIN=myblog.yourdomain.com

# Add your content
# Replace files in ./html/ directory

# Deploy the application
~/docker/scripts/deploy-app.sh myblog
```

### Application Template Structure

```
~/docker/apps/template/
├── docker-compose.yml      # Service definition
├── .env                   # Environment variables
├── nginx.conf             # Nginx configuration
└── html/                  # Website content
    └── index.html         # Homepage
```

### Environment Variables (.env)

```bash
PROJECT_NAME=mywebsite           # Unique identifier
DOMAIN=mywebsite.yourdomain.com  # Full domain name
TIMEZONE=UTC                     # Container timezone
MIDDLEWARES=default-headers      # Traefik middlewares
```

---

## 🔐 Security Features

### Network Isolation

```yaml
# Web network (external access)
web-network:
  - Traefik
  - Application containers

# Management network (internal only)
management-network:
  - Portainer
  - Netdata
  - Watchtower
```

### Container Security

- **Read-only filesystems** with tmpfs for writable areas
- **No new privileges** security option
- **Non-root users** where possible
- **Security context** restrictions
- **Resource limits** (CPU/memory)

### Traefik Security Headers

```yaml
# Applied to all routes
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
```

---

## 📊 Monitoring and Maintenance

### Built-in Commands

```bash
# Check all services status
docker-status

# View service logs
docker-logs <service-name>

# Navigate quickly
cdinfra    # Go to infrastructure directory
cdapps     # Go to applications directory
cdscripts  # Go to scripts directory

# Email functions
send-email recipient@domain.com "Subject" "Message"
test-email recipient@domain.com
```

### Backup Management

```bash
# Create manual backup
~/docker/scripts/backup.sh

# Backup includes:
# - Infrastructure data (Traefik certs, Portainer data, Netdata data)
# - Application data (for apps with data/ directories)
# - Compressed with timestamp: YYYYMMDD_HHMMSS.tar.gz
```

### Log Management

```bash
# View infrastructure logs
cd ~/docker/infrastructure
docker compose logs -f

# View specific service
docker logs -f traefik
docker logs -f portainer
docker logs -f netdata

# View application logs
cd ~/docker/apps/myapp
docker compose logs -f
```

---

## 🔧 Management Scripts

### setup.sh

```bash
~/docker/scripts/setup.sh
```

- Creates Docker networks
- Starts infrastructure services
- Verifies service health
- Sends startup notification email

### deploy-app.sh

```bash
~/docker/scripts/deploy-app.sh <app-name>
```

- Pulls latest images
- Performs rolling update
- Verifies deployment
- Sends deployment notification

### backup.sh

```bash
~/docker/scripts/backup.sh
```

- Creates compressed backups
- Timestamps all archives
- Includes infrastructure and app data
- Sends backup completion email

### test-email.sh

```bash
~/docker/scripts/test-email.sh <recipient>
```

- Tests ssmtp configuration
- Sends system status report
- Verifies email delivery
- Troubleshoots email issues

---

## 🌐 DNS Configuration

### Required DNS Records

For domain `example.com`:

| Subdomain               | Type | Value            | Purpose              |
| ----------------------- | ---- | ---------------- | -------------------- |
| `traefik.example.com`   | A    | `YOUR_SERVER_IP` | Traefik dashboard    |
| `portainer.example.com` | A    | `YOUR_SERVER_IP` | Portainer interface  |
| `netdata.example.com`   | A    | `YOUR_SERVER_IP` | Monitoring dashboard |
| `app.example.com`       | A    | `YOUR_SERVER_IP` | Your applications    |

### DNS Providers

#### Cloudflare

1. Dashboard → DNS → Records
2. Add A records with Proxy Status: "DNS only" (gray cloud)
3. TTL: Auto or 5 minutes for faster propagation

#### Other Providers

1. Access DNS management
2. Create A records pointing to server IP
3. Set TTL to 300 seconds (5 minutes)

### Verification

```bash
# Test DNS propagation
nslookup traefik.yourdomain.com
nslookup portainer.yourdomain.com

# Check from multiple locations
dig traefik.yourdomain.com @8.8.8.8
dig traefik.yourdomain.com @1.1.1.1
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Email Notifications Not Working

**Symptoms**: No email notifications received

**Diagnosis**:

```bash
# Check ssmtp configuration
sudo cat /etc/ssmtp/ssmtp.conf

# Test email manually
echo "Test" | ssmtp your-email@domain.com

# Check container email access
docker exec watchtower which ssmtp
```

**Solutions**:

- Verify ssmtp configuration file exists and is readable
- Test Gmail App Password validity
- Check email recipient address
- Ensure 2FA is enabled on Gmail account

#### 2. Services Not Starting

**Symptoms**: Docker containers failing to start

**Diagnosis**:

```bash
# Check service status
docker-status

# View specific service logs
docker logs traefik
docker logs portainer

# Check Docker daemon
sudo systemctl status docker
```

**Solutions**:

- Verify DNS records are configured
- Check domain name in .env file
- Ensure ports 80/443 are available
- Verify certificate storage permissions

#### 3. SSL Certificate Issues

**Symptoms**: "Your connection is not private" errors

**Diagnosis**:

```bash
# Check Traefik logs
docker logs traefik | grep -i acme

# Verify certificate storage
ls -la ~/docker/infrastructure/data/traefik/certs/

# Test domain accessibility
curl -I https://traefik.yourdomain.com
```

**Solutions**:

- Verify DNS propagation (can take 24-48 hours)
- Check Let's Encrypt rate limits
- Ensure email in Traefik config is valid
- Clear certificate storage and retry

#### 4. Application Not Accessible

**Symptoms**: 404 or connection refused for applications

**Diagnosis**:

```bash
# Check application status
cd ~/docker/apps/myapp
docker compose ps

# Verify network connectivity
docker network ls
docker network inspect web-network

# Check Traefik routing
docker logs traefik | grep myapp
```

**Solutions**:

- Verify DNS record for application domain
- Check application .env configuration
- Ensure application is connected to web-network
- Verify Traefik labels in docker-compose.yml

### Performance Issues

#### High Memory Usage

**Diagnosis**:

```bash
# Check container resource usage
docker stats

# Check system resources
free -h
df -h
```

**Solutions**:

- Add resource limits to docker-compose.yml
- Implement log rotation
- Monitor Netdata for resource trends

#### Slow Response Times

**Diagnosis**:

```bash
# Check Traefik metrics
curl https://traefik.yourdomain.com/api/dashboard/

# Test direct container access
docker exec -it myapp-web curl localhost
```

**Solutions**:

- Enable compression in Traefik
- Optimize application configuration
- Add caching layers
- Monitor with Netdata

---

## 🔄 Updates and Maintenance

### Automatic Updates

Watchtower handles automatic updates:

- **Schedule**: Daily at 4:00 AM
- **Scope**: Containers with `com.centurylinklabs.watchtower.enable=true`
- **Process**: Pull new images, rolling restart, cleanup old images
- **Notifications**: Email alerts for successful/failed updates

### Manual Updates

```bash
# Update infrastructure
cd ~/docker/infrastructure
docker compose pull
docker compose up -d

# Update specific application
cd ~/docker/apps/myapp
docker compose pull
docker compose up -d

# Update all applications
for app in ~/docker/apps/*/; do
  if [ -f "$app/docker-compose.yml" ]; then
    cd "$app" && docker compose pull && docker compose up -d
  fi
done
```

### System Maintenance

```bash
# Clean up unused Docker resources
docker system prune -f

# Remove old images
docker image prune -a -f

# Clean up old backups (keep last 30 days)
find ~/docker/backups -name "*.tar.gz" -mtime +30 -delete
```

---

## ⚡ Performance Optimization

### Resource Limits

Add to docker-compose.yml:

```yaml
services:
  web:
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
        reservations:
          memory: 256M
```

### Traefik Optimization

```yaml
# In traefik.yml
http:
  middlewares:
    compress:
      compress: {}
    cache:
      headers:
        customResponseHeaders:
          Cache-Control: "public, max-age=3600"
```

### Nginx Optimization

```nginx
# In nginx.conf
worker_processes auto;
worker_connections 1024;
keepalive_timeout 65;
gzip on;
gzip_types text/plain text/css application/json application/javascript;
```

---

## 🔐 Advanced Security

### Additional Security Headers

```yaml
# In traefik dynamic config
middlewares:
  security-plus:
    headers:
      contentSecurityPolicy: "default-src 'self'"
      permissionsPolicy: "geolocation=(), microphone=(), camera=()"
      referrerPolicy: "strict-origin-when-cross-origin"
```

### Fail2ban Integration

```bash
# Add to fail2ban jail.local
[traefik-auth]
enabled = true
port = 80,443
filter = traefik-auth
logpath = /var/log/docker/traefik.log
maxretry = 3
bantime = 3600
```

### Container Scanning

```bash
# Scan images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image traefik:v3.0
```

---

## 📚 Additional Resources

### Official Documentation

- [Traefik Documentation](https://doc.traefik.io/traefik/)
- [Portainer Documentation](https://docs.portainer.io/)
- [Netdata Documentation](https://docs.netdata.cloud/)
- [Docker Compose Reference](https://docs.docker.com/compose/)

### Community Resources

- [Traefik Community](https://community.traefik.io/)
- [Docker Community](https://forums.docker.com/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)

### Monitoring and Alerting

- [Netdata Cloud](https://cloud.netdata.space/)
- [Grafana Integration](https://grafana.com/docs/)
- [Prometheus Metrics](https://prometheus.io/docs/)

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- **Multi-architecture support** (ARM64, x86)
- **Additional application templates** (WordPress, databases)
- **Enhanced monitoring** (custom dashboards)
- **Backup automation** (S3, remote storage)
- **Security enhancements** (secrets management)

### Development Setup

```bash
# Fork and clone repository
git clone https://github.com/your-fork/docker-infrastructure-setup
cd docker-infrastructure-setup

# Test in VM or container
vagrant up  # or docker run --privileged

# Run tests
./tests/test-setup.sh
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Docker Team** - Container technology
- **Traefik Labs** - Modern reverse proxy
- **Portainer Team** - Container management
- **Netdata Team** - Real-time monitoring
- **Let's Encrypt** - Free SSL certificates
- **Ubuntu/Canonical** - Stable foundation

---

<div align="center">

**🐳 Deploy with confidence, monitor with precision, maintain with ease!**

_A complete Docker infrastructure solution for modern web applications_

</div>
