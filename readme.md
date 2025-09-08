# Ubuntu 25.x Server Hardening Runbook

Automated script that turns a **fresh Ubuntu 25** cloud instance into a **minimal, hardened Docker host** in \~5 minutes.
No web-server packages (Apache, Nginx, PHP, MySQL) are installed on the host – **everything web-related runs inside Docker Compose later**.

---

## 1. What You Get

| Area                | Hardening Action                                                                          |
| ------------------- | ----------------------------------------------------------------------------------------- |
| Access              | Password-less SSH key only, root login disabled, extra sudo user `deploy`                 |
| Firewall            | UFW – deny incoming by default, rate-limit SSH, allow 80/443                              |
| Intrusion Detection | fail2ban (SSH + UFW action)                                                               |
| Patches             | unattended-upgrades – security updates only, no auto-reboot                               |
| Kernel              | SYN-cookies, IP-spoofing protection, ICMP redirects off, ptrace scope, core-dump disabled |
| Logging             | auditd (file deletions, sudoers, passwd), AIDE daily integrity check                      |
| Docker              | Latest stable, socket locked to root\:docker, no TCP port exposed                         |

---

## 2. Quick Start

```bash
# 0. Log in as ubuntu (password-less sudo)
ssh ubuntu@YOUR_IP

# 1. Download & run
curl -fsSL https://raw.githubusercontent.com/YOU/repo/main/harden.sh -o ~/harden.sh
chmod +x ~/harden.sh
./harden.sh
# When prompted, paste your **Ed25519 public key** (see section 2-a below)

# 2. Reboot (recommended)
sudo reboot
```

---

### 2-a. Generate / Find Your Ed25519 Public Key

Run on your local computer (never on the server):

```bash
# Generate (skip if you already have one)
ssh-keygen -t ed25519 -C "ubuntu25-deploy" -f ~/.ssh/id_ed25519-ubuntu25

# Copy public key to clipboard

# macOS
pbcopy < ~/.ssh/id_ed25519-ubuntu25.pub

# Linux (X11)
xclip -sel clip < ~/.ssh/id_ed25519-ubuntu25.pub

# Linux (Wayland)
wl-copy < ~/.ssh/id_ed25519-ubuntu25.pub

# Windows PowerShell
Get-Content ~/.ssh/id_ed25519-ubuntu25.pub | Set-Clipboard

# Generic
cat ~/.ssh/id_ed25519-ubuntu25.pub   # then select & copy
```

You’ll get a single line like:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM6L… ubuntu25-deploy
```

Paste that line when the script asks for it.

---

## 3. Post-Run Checklist

| Command                            | Expected Result                  |
| ---------------------------------- | -------------------------------- |
| `ssh deploy@YOUR_IP`               | Key login works, password fails  |
| `sudo ufw status verbose`          | 22 (rate-limit), 80, 443 allowed |
| `sudo fail2ban-client status sshd` | Jail active, 0 banned (so far)   |
| `sudo docker run hello-world`      | Docker works, socket locked      |
| `sudo aide --check`                | "AIDE found NO differences"      |

---

## 4. File Integrity & Logging

* **auditd** logs to `/var/log/audit/audit.log`
* **AIDE** daily report is printed to `journalctl -u aide-check`
* Script log: `/var/log/harden.log`

---

## 5. Rollback / Customise

Edit the script before running:

| Variable      | Purpose                                       |
| ------------- | --------------------------------------------- |
| `NEWUSER`     | Name of extra sudo user (default `deploy`)    |
| `USERKEY`     | Your Ed25519 public key (asked interactively) |
| `UFW ports`   | Add more `sudo ufw allow <port>` lines        |
| Kernel params | Modify `/etc/sysctl.d/99-harden.conf` section |

---

## 6. What the Script Does **NOT** Touch

* No Apache, Nginx, PHP, MySQL, Redis, Certbot on the host
* No cloud-init packages removed (safe on AWS, GCP, Azure, Hetzner, etc.)
* No automatic reboot (you decide when)

---

## 7. Next Step

Move on to the Docker-Compose web stack:
**Traefik + Apache/Nginx + PHP-FPM 5.6 / 7.4 / 8.1 + MySQL + Redis** – everything runs inside containers, while the host stays minimal.

---

## 8. License & Disclaimer

* **MIT** – use at your own risk.
* Test on a throw-away VM first; cloud images vary slightly.

