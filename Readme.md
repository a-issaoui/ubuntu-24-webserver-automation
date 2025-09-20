# Ubuntu 24 Web Server Automation

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=flat&logo=ubuntu)](https://ubuntu.com/)
[![Docker](https://img.shields.io/badge/Docker-CE-2496ED?style=flat&logo=docker)](https://docker.com/)
[![Traefik](https://img.shields.io/badge/Traefik-v3.0-24A1C1?style=flat&logo=traefik)](https://traefik.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A complete automation solution for deploying secure, production-ready web servers on Ubuntu 24.04 LTS. This repository provides two powerful scripts that work together to create a hardened Docker infrastructure with modern reverse proxy, monitoring, and management tools.

## 🎯 What This Repository Provides

### 1. 🔒 Server Hardening Script (`harden-docker.sh`)

Comprehensive security hardening for Ubuntu 24.04 servers following CIS benchmarks:

- SSH hardening with key-based authentication
- Firewall configuration with UFW
- Docker security optimization
- Fail2ban intrusion prevention
- System monitoring and audit logging
- Email notifications via Gmail SMTP

### 2. 🐳 Docker Infrastructure Script (`complete-setup.sh`)

Complete Docker-based web hosting environment with:

- Traefik v3.0 reverse proxy with automatic HTTPS
- Portainer for container management
- Netdata for real-time monitoring
- Watchtower for automated updates
- Template-based application deployment

## 🚀 Quick Start

### Step 1: Server Hardening

First, secure your Ubuntu 24.04 server:

```bash
# Download hardening script
wget https://raw.githubusercontent.com/a-issaoui/ubuntu-24-webserver-automation/main/harden-docker.sh
chmod +x harden-docker.sh

# Generate SSH key on your local machine
ssh-keygen -t ed25519 -C "server-admin" -f ~/.ssh/id_ed25519_server

# Run hardening with basic security
./harden-docker.sh --ssh-key "$(cat ~/.ssh/id_ed25519_server.pub)"

# Or with email notifications
./harden-docker.sh \
  --ssh-key "$(cat ~/.ssh/id_ed25519_server.pub)" \
  --install-mail-utils \
  --gmail-user "alerts@yourdomain.com" \
  --gmail-app-password "your-gmail-app-password" \
  --email "admin@yourdomain.com"
```

### Step 2: Docker Infrastructure Setup

After hardening, deploy the web infrastructure:

```bash
# Switch to the deploy user created by hardening script
sudo su - deploy

# Download infrastructure script
wget https://raw.githubusercontent.com/a-issaoui/ubuntu-24-webserver-automation/main/complete-setup.sh
chmod +x complete-setup.sh

# Run interactive setup
./complete-setup.sh
```

The script will prompt you for:

- Domain name (e.g., `yourdomain.com`)
- Admin email for SSL certificates
- Dashboard passwords
- Timezone configuration

### Step 3: Configure DNS

Point these subdomains to your server IP:

```
traefik.yourdomain.com   → YOUR_SERVER_IP
portainer.yourdomain.com → YOUR_SERVER_IP
netdata.yourdomain.com   → YOUR_SERVER_IP
```

### Step 4: Access Your Services

- **Traefik Dashboard**: `https://traefik.yourdomain.com`
- **Portainer**: `https://portainer.yourdomain.com`
- **Netdata Monitoring**: `https://netdata.yourdomain.com`

## 📋 Prerequisites

| Requirement     | Details                       |
| --------------- | ----------------------------- |
| **OS**          | Fresh Ubuntu 24.04 LTS server |
| **Resources**   | Min: 2GB RAM, 20GB disk space |
| **Network**     | Public IP with domain name    |
| **Access**      | Root or sudo privileges       |
| **Local Tools** | SSH client, text editor       |

## 🔧 Key Features

### Security Hardening

- ✅ SSH key-based authentication only
- ✅ Custom SSH port configuration
- ✅ UFW firewall with strict rules
- ✅ Docker security benchmarking
- ✅ Fail2ban intrusion prevention
- ✅ Automatic security updates
- ✅ System audit logging

### Docker Infrastructure

- ✅ Traefik reverse proxy with auto-HTTPS
- ✅ Let's Encrypt SSL certificates
- ✅ Container management with Portainer
- ✅ Real-time monitoring with Netdata
- ✅ Automated updates with Watchtower
- ✅ Email notifications for all services
- ✅ Template-based app deployment

### Production Ready

- ✅ Security headers and rate limiting
- ✅ Container health checks
- ✅ Automated backups
- ✅ Log rotation and management
- ✅ Performance optimization
- ✅ Zero-downtime deployments

## 📁 Repository Structure

```
ubuntu-24-webserver-automation/
├── harden-docker.sh          # Server hardening script
├── complete-setup.sh         # Docker infrastructure setup
├── configs/                  # Configuration templates
│   ├── traefik/             # Traefik configurations
│   ├── docker/              # Docker compose files
│   └── security/            # Security-related configs
├── scripts/                 # Helper and management scripts
├── docs/                    # Detailed documentation
│   ├── HARDENING.md         # Server hardening guide
│   ├── INFRASTRUCTURE.md    # Docker setup guide
│   └── TROUBLESHOOTING.md   # Common issues & solutions
└── README.md               # This file
```

## 🔍 Detailed Documentation

### Server Hardening

- [📖 Complete Hardening Guide](docs/HARDENING.md) - Detailed security configuration
- [🛠 Hardening Script Options](docs/HARDENING.md#configuration-options) - All command-line flags
- [🔧 SSH Configuration](docs/HARDENING.md#ssh-hardening) - SSH security details

### Docker Infrastructure

- [📖 Infrastructure Setup Guide](docs/INFRASTRUCTURE.md) - Complete Docker deployment
- [🌐 Application Deployment](docs/INFRASTRUCTURE.md#application-deployment) - How to deploy websites
- [📊 Monitoring & Management](docs/INFRASTRUCTURE.md#monitoring-and-maintenance) - System monitoring

### Troubleshooting

- [🚨 Common Issues](docs/TROUBLESHOOTING.md) - Solutions for typical problems
- [📧 Email Setup Problems](docs/TROUBLESHOOTING.md#email-issues) - Gmail SMTP configuration
- [🔥 Firewall Issues](docs/TROUBLESHOOTING.md#firewall-issues) - UFW and port access

## ⚙️ Configuration Examples

### Basic Setup (HTTP only)

```bash
# Hardening
./harden-docker.sh --ssh-key "$(cat ~/.ssh/key.pub)"

# Infrastructure (will prompt for domain)
sudo su - deploy -c "./complete-setup.sh"
```

### Production Setup (HTTPS + Email)

```bash
# Hardening with email alerts
./harden-docker.sh \
  --ssh-key "$(cat ~/.ssh/key.pub)" \
  --install-mail-utils \
  --gmail-user "notifications@company.com" \
  --gmail-app-password "app-password" \
  --email "admin@company.com"

# Infrastructure with automatic SSL
sudo su - deploy -c "./complete-setup.sh"
```

### Custom Configuration

```bash
# Advanced hardening options
./harden-docker.sh \
  --ssh-key "$(cat ~/.ssh/key.pub)" \
  --ssh-port 2222 \
  --user webadmin \
  --timezone "America/New_York" \
  --restrict-ip "192.168.1.0/24" \
  --install-mail-utils \
  --gmail-user "alerts@domain.com" \
  --gmail-app-password "password" \
  --email "admin@domain.com"
```

## 🛡️ Security Features

This automation implements enterprise-grade security:

- **SSH**: Ed25519 keys, disabled passwords, custom ports
- **Firewall**: UFW with minimal open ports, rate limiting
- **Docker**: CIS benchmark compliance, security scanning
- **Monitoring**: Real-time intrusion detection, audit logs
- **Updates**: Automatic security patches, container updates
- **Encryption**: TLS 1.3, modern ciphers, HSTS headers

## 📞 Support & Contributing

### Getting Help

- 📖 **Documentation**: Check the [docs/](docs/) directory
- 🐛 **Issues**: [Create an issue](https://github.com/a-issaoui/ubuntu-24-webserver-automation/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/a-issaoui/ubuntu-24-webserver-automation/discussions)

### Contributing

Contributions welcome! Areas for improvement:

- IPv6 firewall support
- Additional email providers
- More application templates
- Enhanced monitoring dashboards

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Ubuntu Team** - Solid server foundation
- **Docker** - Container technology
- **Traefik Labs** - Modern reverse proxy
- **Let's Encrypt** - Free SSL certificates
- **CIS** - Security benchmarks

---

<div align="center">

**🚀 Deploy secure web infrastructure in minutes, not hours!**

_Complete automation for Ubuntu 24.04 web servers with Docker_

</div>
