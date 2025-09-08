#!/usr/bin/env bash
set -euo pipefail
################################################################################
# Ubuntu 25.x Server Hardening – DESTRUCTIVE FOR ROOT & UBUNTU SSH
# Run as ubuntu (password-less sudo).  Reboot-safe.
################################################################################
LOG=/var/log/harden.log
exec > >(tee -a "$LOG") 2>&1
echo "=== $(date) – hardening start ($(whoami))"

# colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

# 1. update first (prevents lock-out via fw)
sudo apt update -qq && sudo apt dist-upgrade -y

# 2. create deploy user + key
NEWUSER=deploy
read -rp "Paste your ED25519 public key (ssh-ed25519 …): " USERKEY
sudo adduser --disabled-password --gecos "" "$NEWUSER"
echo "$NEWUSER ALL=(ALL) NOPASSWD:ALL" | sudo tee "/etc/sudoers.d/99-$NEWUSER"
sudo mkdir -p "/home/$NEWUSER/.ssh"
echo "$USERKEY" | sudo tee "/home/$NEWUSER/.ssh/authorized_keys"
sudo chmod 700 "/home/$NEWUSER/.ssh"
sudo chmod 600 "/home/$NEWUSER/.ssh/authorized_keys"
sudo chown -R "$NEWUSER:$NEWUSER" "/home/$NEWUSER"

# 3. lock existing ubuntu account & root
sudo passwd -l ubuntu
sudo usermod --expiredate 1 ubuntu
sudo passwd -l root
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# 4. firewall (ufw)
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw limit 22/tcp              # rate-limit
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw --force enable

# 5. fail2ban (ssh + ufw action)
sudo apt install -y fail2ban
cat <<'EOF' | sudo tee /etc/fail2ban/jail.local
[DEFAULT]
banaction = ufw
[sshd]
enabled  = true
maxretry = 3
bantime  = 3600
findtime = 600
EOF
sudo systemctl enable --now fail2ban

# 6. unattended-upgrades (security only)
sudo apt install -y unattended-upgrades
cat <<'EOF' | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
sudo systemctl enable --now unattended-upgrades

# 7. kernel hardening
cat <<'EOF' | sudo tee /etc/sysctl.d/99-harden.conf
# SYN-flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
# IP-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# log martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# ignore bogus errors
net.ipv4.icmp_ignore_bogus_error_responses = 1
# RFC 1337
net.ipv4.tcp_rfc1337 = 1
# disable source-route
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# ptrace scope
kernel.yama.ptrace_scope = 1
# core dumps
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
EOF
sudo sysctl -p /etc/sysctl.d/99-harden.conf

# 8. systemd limits
cat <<'EOF' | sudo tee /etc/security/limits.d/99-harden.conf
*    hard core    0
*    soft nproc   4096
*    hard nproc   4096
*    soft nofile  65536
*    hard nofile  65536
root soft core    0
EOF

# 9. auditd
sudo apt install -y auditd audispd-plugins
cat <<'EOF' | sudo tee /etc/audit/rules.d/harden.rules
# delete / rename
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
# sudoers changes
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
# pam
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
EOF
sudo systemctl enable --now auditd
sudo augenrules --load

# 10. AIDE (file-integrity)
sudo apt install -y aide
sudo aideinit                              # initial DB
cat <<'EOF' | sudo tee /etc/systemd/system/aide-check.timer
[Unit]
Description=Daily AIDE check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
cat <<'EOF' | sudo tee /etc/systemd/system/aide-check.service
[Unit]
Description=AIDE integrity check
[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now aide-check.timer

# 11. Docker (latest stable)
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update -qq
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker

# 12. lock docker socket
sudo chmod 660 /var/run/docker.sock

# 13. final words
echo -e "${GREEN}=== Hardening complete – reboot recommended ===${NC}"
echo "SSH only via $NEWUSER + key – root & ubuntu locked"
echo "UFW active (22 ratelimit, 80, 443) – fail2ban watching SSH"
echo "Unattended-upgrades ON – auditd & AIDE daily"
echo "Docker ready – socket locked to root:docker"
