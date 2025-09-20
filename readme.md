# 🔐 Docker Web Server Hardening Script

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?style=flat&logo=ubuntu)](https://ubuntu.com/)
[![Docker](https://img.shields.io/badge/Docker-CE-2496ED?style=flat&logo=docker)](https://docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-CIS%20Benchmarks-red.svg)](https://www.cisecurity.org/)

A **robust, fully automated** Bash tool designed to secure Ubuntu 24.04 LTS servers hosting Docker-based web applications. This script implements industry-standard security practices, aligning with **CIS (Center for Internet Security)** benchmarks for Ubuntu and Docker.

---

## ✨ Key Features

<table>
<tr>
<td>🔑 <strong>SSH Hardening</strong></td>
<td>Key-based authentication, disabled root login, modern cryptography (ChaCha20, SNTRUP761)</td>
</tr>
<tr>
<td>🔥 <strong>Firewall Protection</strong></td>
<td>Strict UFW rules allowing only necessary ports (SSH, HTTP/HTTPS)</td>
</tr>
<tr>
<td>🐳 <strong>Docker Security</strong></td>
<td>Secure daemon configuration + Docker Bench Security tool</td>
</tr>
<tr>
<td>🛡️ <strong>Intrusion Prevention</strong></td>
<td>Fail2ban protection for SSH and web servers</td>
</tr>
<tr>
<td>⚙️ <strong>System Hardening</strong></td>
<td>Kernel parameters, auditd monitoring, automatic updates</td>
</tr>
<tr>
<td>📊 <strong>Monitoring & Logging</strong></td>
<td>Comprehensive logging and security status checks</td>
</tr>
<tr>
<td>🔄 <strong>Idempotent</strong></td>
<td>Safe to run multiple times, skips completed steps</td>
</tr>
<tr>
<td>🧪 <strong>Dry-Run Mode</strong></td>
<td>Test changes without applying them</td>
</tr>
</table>

---

## 🚀 Quick Start

### 1. Download & Setup

```bash
# Download the script
wget https://github.com/a-issaoui/harden-server/harden-docker.sh
chmod +x harden-docker.sh
```

### 2. Generate SSH Key (on your local machine)

```bash
# Generate new key
ssh-keygen -t ed25519 -C "ubuntu25-deploy" -f ~/.ssh/id_ed25519-ubuntu25

# Copy to clipboard (choose your OS)
# macOS
pbcopy < ~/.ssh/id_ed25519-ubuntu25.pub

# Linux (X11)
xclip -sel clip < ~/.ssh/id_ed25519-ubuntu25.pub

# Linux (Wayland)
wl-copy < ~/.ssh/id_ed25519-ubuntu25.pub

# Windows PowerShell
Get-Content ~/.ssh/id_ed25519-ubuntu25.pub | Set-Clipboard

# Generic (copy output manually)
cat ~/.ssh/id_ed25519-ubuntu25.pub
```

### 3. Run the Script

**Basic usage:**

```bash
./harden-docker.sh --ssh-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM6L... ubuntu25-deploy"
```

**Advanced usage:**

```bash
./harden-docker.sh \
  --ssh-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM6L... ubuntu25-deploy" \
  --ssh-port 22222 \
  --user webadmin \
  --email admin@example.com \
  --restrict-ip 192.168.1.0/24 \
  --timezone America/New_York \
  --install-mail-utils
```

---

## ⚡ Prerequisites

| Requirement   | Details                                                    |
| ------------- | ---------------------------------------------------------- |
| **OS**        | Fresh Ubuntu 24.04 LTS (server edition recommended)        |
| **User**      | Non-root user with sudo privileges (or use `--allow-root`) |
| **Internet**  | Required for package updates and Docker GPG key            |
| **SSH Key**   | Ed25519 public key for secure access                       |
| **Resources** | Min: 512MB RAM, 2GB disk space (1GB+ RAM recommended)      |

**Pre-installed tools:** `curl`, `openssl`, `gpg`, `dpkg`, `apt`, `jq`

---

## 🛠️ Configuration Options

<details>
<summary><strong>Click to expand all command-line options</strong></summary>

| Option                      | Description                                    | Default     | Required |
| --------------------------- | ---------------------------------------------- | ----------- | -------- |
| `--user <name>`             | Admin user for SSH/sudo/Docker                 | `deploy`    | No       |
| `--ssh-port <port>`         | Custom SSH port (1-65535)                      | `2222`      | No       |
| `--ssh-key <key>`           | SSH public key (Ed25519 recommended)           | None        | **Yes**  |
| `--email <addr>`            | Email for update alerts and test message       | None        | No       |
| `--restrict-ip <ip/cidr>`   | Restrict HTTP/HTTPS to IP or CIDR              | None (open) | No       |
| `--timezone <tz>`           | System timezone                                | `UTC`       | No       |
| `--keep-swap`               | Preserve swap (disabled by default)            | `false`     | No       |
| `--allow-root`              | Allow running as root (not recommended)        | `false`     | No       |
| `--no-reboot`               | Skip final system reboot                       | `false`     | No       |
| `--no-docker-group`         | Don't add user to docker group                 | `false`     | No       |
| `--keep-current-ssh-users`  | Preserve existing SSH AllowUsers               | `false`     | No       |
| `--force-docker-restart`    | Restart Docker daemon (may disrupt containers) | `false`     | No       |
| `--fail2ban-bantime <secs>` | Fail2ban ban duration (-1 for permanent)       | `3600`      | No       |
| `--dry-run`                 | Simulate without changes                       | `false`     | No       |
| `--skip-bench`              | Skip Docker Bench Security test                | `false`     | No       |
| `--install-mail-utils`      | Install mailutils/postfix for alerts           | `false`     | No       |

</details>

---

## 🔒 Security Features

### SSH Hardening

- ✅ **Key-only authentication** - No password logins
- ✅ **Root login disabled** - Enhanced security
- ✅ **Modern cryptography** - ChaCha20, AES-GCM ciphers
- ✅ **Quantum-resistant KEX** - SNTRUP761, Curve25519
- ✅ **Rate limiting** - Max 5 concurrent sessions

### Firewall Protection

- ✅ **Default deny** - All incoming traffic blocked
- ✅ **SSH protection** - Rate-limited access
- ✅ **Web services** - HTTP/HTTPS with optional IP restrictions
- ✅ **UFW integration** - Simple firewall management

### Docker Security

- ✅ **Secure daemon config** - No ICC, live-restore enabled
- ✅ **Privilege restrictions** - No new privileges by default
- ✅ **Benchmark compliance** - Docker Bench Security v1.6.0
- ✅ **User isolation** - Proper group management

### System Hardening

- ✅ **Kernel hardening** - ASLR, syncookies, redirect protection
- ✅ **Audit monitoring** - Critical file and syscall tracking
- ✅ **Automatic updates** - Daily security patches
- ✅ **Intrusion detection** - Fail2ban for SSH and web services

---

## 📋 Post-Installation

### 1. Verify SSH Access

```bash
ssh -p <new-port> <new-user>@<server-ip>
```

### 2. Check System Status

```bash
sudo /usr/local/bin/security-check
```

### 3. Review Logs

```bash
# Main execution log
sudo less /var/log/harden-docker.log

# Summary report
sudo less /var/log/harden-docker-summary.log

# Docker security benchmark (if run)
sudo less /var/log/docker-bench.log
```

### 4. Manual Reboot (if `--no-reboot` was used)

```bash
sudo reboot
```

---

## 🔧 Troubleshooting

<details>
<summary><strong>SSH Connection Issues</strong></summary>

**Problem:** Can't connect after hardening

```bash
# Check SSH configuration
sudo cat /etc/ssh/sshd_config | grep -E "(Port|AllowUsers|PasswordAuthentication)"

# Check authentication logs
sudo tail -f /var/log/auth.log
```

**Solution:** Ensure correct port, username, and SSH key path

</details>

<details>
<summary><strong>Docker Issues</strong></summary>

**Problem:** Docker not responding

```bash
# Check Docker status
sudo systemctl status docker
sudo docker info

# Check Docker logs
sudo journalctl -u docker --no-pager -l
```

**Solution:** Restart Docker service if needed

```bash
sudo systemctl restart docker
```

</details>

<details>
<summary><strong>Firewall Blocking Services</strong></summary>

**Problem:** Can't access web services

```bash
# Check firewall status
sudo ufw status verbose

# Allow additional ports if needed
sudo ufw allow <port>/tcp
sudo ufw reload
```

</details>

<details>
<summary><strong>Email Alerts Not Working</strong></summary>

**Problem:** No email notifications

```bash
# Check mail logs
sudo tail -f /var/log/mail.log

# Test email manually
echo "Test message" | mail -s "Test Subject" your-email@domain.com
```

**Requirements:** Use `--install-mail-utils` and `--email` flags

</details>

---

## ⚠️ Important Notes

> **SSH Restart Warning**
> After hardening, SSH will restart with a 5-second countdown. Your current session may drop. Reconnect using the new port and user.

> **Swap Disabled**
> Swap is disabled by default for Docker performance. Use `--keep-swap` if you need it for stability.

> **Docker Containers**
> Docker daemon restart is skipped by default to avoid disrupting running containers. Use `--force-docker-restart` when safe.

---

## 🎯 Known Limitations

| Limitation            | Workaround                                                                     |
| --------------------- | ------------------------------------------------------------------------------ |
| **IPv6 Support**      | UFW rules are IPv4-only. Add IPv6 rules manually if needed                     |
| **Swap Management**   | Disabled by default. Use `--keep-swap` for memory-constrained systems          |
| **Docker Restart**    | Skipped to protect containers. Use `--force-docker-restart` when safe          |
| **Audit Rules**       | x86_64-specific. Add 32-bit rules for mixed architectures                      |
| **Rootless Docker**   | Not supported. Consider for enhanced container security                        |
| **HTTPS Enforcement** | Port 443 opened but TLS not enforced. Configure nginx/Let's Encrypt separately |

---

## 🤝 Contributing

We welcome contributions! Here are areas where help is needed:

- 🌐 **IPv6 firewall support**
- 🐳 **Rootless Docker integration**
- 📦 **Dynamic Docker Bench version detection**
- 🔍 **Enhanced audit rules for 32-bit compatibility**
- 📧 **Improved email notification system**

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Ubuntu 24.04 LTS** - Solid foundation for server security
- **Docker CE** - Containerization platform
- **CIS Benchmarks** - Security configuration standards
- **Docker Bench Security v1.6.0** - Compliance verification tool

---

## 📞 Support

- 🐛 **Found a bug?** [Create an issue](https://github.com/your-repo/issues)
- 💡 **Have a suggestion?** [Start a discussion](https://github.com/your-repo/discussions)
- 📧 **Need help?** Check the troubleshooting section above

---

<div align="center">

**🔐 Secure your Docker infrastructure with confidence!**

_Made with ❤️ for the security community_

</div>
