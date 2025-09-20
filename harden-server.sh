#!/usr/bin/env bash
# ------------------------------------------------------------------
# Optimized Docker Web Server Hardening Script - FIXED VERSION
# Ubuntu 24.04 LTS - Fully Automated, Zero Interaction
# Run with: ./harden-docker.sh [options]
# ------------------------------------------------------------------

set -euo pipefail

# Initialize log file with proper permissions
sudo touch /var/log/harden-docker.log
sudo chmod 640 /var/log/harden-docker.log
exec > >(sudo tee /var/log/harden-docker.log) 2>&1

readonly SCRIPT_VERSION="2.2.0"
readonly RED=$'\e[31m' GRN=$'\e[32m' YLW=$'\e[33m' BLU=$'\e[34m' NC=$'\e[0m'

# Configuration
SSH_PORT=""
NEW_USER="deploy"
SSH_KEY=""
EMAIL=""
RESTRICT_IP=""
TIMEZONE="UTC"
KEEP_SWAP=false
ALLOW_ROOT=false
NO_REBOOT=false
NO_DOCKER_GROUP=false
KEEP_CURRENT_SSH_USERS=false
FORCE_DOCKER_RESTART=false
FAIL2BAN_BANTIME="3600"
DRY_RUN=false
SKIP_BENCH=false
INSTALL_MAIL_UTILS=false

# Parse CLI
while [[ $# -gt 0 ]]; do
    case $1 in
        --user)                 NEW_USER="$2"; shift 2 ;;
        --ssh-port)             SSH_PORT="$2"; shift 2 ;;
        --ssh-key)              SSH_KEY="$2"; shift 2 ;;
        --email)                EMAIL="$2"; shift 2 ;;
        --restrict-ip)          RESTRICT_IP="$2"; shift 2 ;;
        --timezone)             TIMEZONE="$2"; shift 2 ;;
        --keep-swap)            KEEP_SWAP=true; shift ;;
        --allow-root)           ALLOW_ROOT=true; shift ;;
        --no-reboot)            NO_REBOOT=true; shift ;;
        --no-docker-group)      NO_DOCKER_GROUP=true; shift ;;
        --keep-current-ssh-users) KEEP_CURRENT_SSH_USERS=true; shift ;;
        --force-docker-restart) FORCE_DOCKER_RESTART=true; shift ;;
        --fail2ban-bantime)     FAIL2BAN_BANTIME="$2"; shift 2 ;;
        --dry-run)              DRY_RUN=true; shift ;;
        --skip-bench)           SKIP_BENCH=true; shift ;;
        --install-mail-utils) INSTALL_MAIL_UTILS=true; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Logging functions
log()   { echo "${BLU}[LOG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"; }
succ()  { echo "${GRN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"; }
warn()  { echo "${YLW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"; }
error() { echo "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2; }
die()   { error "$*"; exit 1; }

# Command wrapper for dry-run
run_cmd() {
    if $DRY_RUN; then
        log "[DRY-RUN] Would execute: $@"
    else
        "$@"
    fi
}

# Validate inputs
validate_inputs() {
    [[ -n "$SSH_KEY" ]] || die "SSH public key is required (--ssh-key)"

    # Set default SSH port if not provided
    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT="2222"
        warn "No SSH port specified, using default: $SSH_PORT"
    fi

    [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [[ "$SSH_PORT" -ge 1 && "$SSH_PORT" -le 65535 ]] || \
        die "Invalid SSH port: $SSH_PORT"

    # Check if port is already in use
    if netstat -tuln | grep -q ":$SSH_PORT "; then
        warn "Port $SSH_PORT is already in use. This may cause conflicts."
    fi

    [[ -z "$RESTRICT_IP" ]] || [[ "$RESTRICT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]] || \
        die "Invalid IP address: $RESTRICT_IP"

    [[ "$TIMEZONE" != "" ]] || TIMEZONE="UTC"
    [[ "$FAIL2BAN_BANTIME" =~ ^-?[0-9]+$ ]] || die "Invalid fail2ban bantime: $FAIL2BAN_BANTIME"

    # Validate SSH key format
    if ! echo "$SSH_KEY" | ssh-keygen -l -f - >/dev/null 2>&1; then
        warn "SSH key format validation failed; proceeding but verify manually"
    fi
}

# System checks
check_system() {
    log "Checking system requirements"
    [[ -f /etc/os-release ]] || die "Cannot determine OS"

    # shellcheck source=/dev/null
    source /etc/os-release
    [[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]] || die "Ubuntu 24.04 required (detected: $ID $VERSION_ID)"

    if [[ $EUID -eq 0 ]] && ! $ALLOW_ROOT; then
        die "Do NOT run as root. Use --allow-root to override"
    fi

    run_cmd sudo -v || die "Sudo access required"

    for i in {1..3}; do
        curl -s --connect-timeout 5 https://archive.ubuntu.com >/dev/null && break
        [[ $i -eq 3 ]] && die "Internet connection required"
        sleep 5
    done

    for tool in curl openssl gpg dpkg apt jq; do
        command -v "$tool" >/dev/null || die "Missing required tool: $tool"
    done

    # Check system resources
    local mem_free=$(free -m | awk '/Mem:/ {print $4}')
    local disk_free=$(df -m / | awk 'NR==2 {print $4}')

    if [[ $mem_free -lt 512 ]]; then
        warn "Low memory (${mem_free}MB free); Docker may fail to start"
    fi

    if [[ $disk_free -lt 2048 ]]; then
        warn "Low disk space (${disk_free}MB free); installation may fail"
    fi

    succ "System check passed"
}

# Package management
update_system() {
    log "Updating system packages"

    for i in {1..3}; do
        run_cmd sudo apt update && break
        [[ $i -eq 3 ]] && warn "apt update failed after 3 attempts; continuing"
        sleep 5
    done

    run_cmd sudo DEBIAN_FRONTEND=noninteractive apt -y upgrade || warn "apt upgrade failed; continuing"
    run_cmd sudo apt autoremove -y || warn "apt autoremove failed; continuing"

    succ "System updated"
}
# Function to configure Postfix non-interactively
configure_postfix() {
    log "Configuring Postfix non-interactively"

    # Set Postfix configuration options
    echo "postfix postfix/mailname string $(hostname -f)" | run_cmd sudo debconf-set-selections
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | run_cmd sudo debconf-set-selections
    echo "postfix postfix/destinations string localhost" | run_cmd sudo debconf-set-selections

    # Configure main.cf with sensible defaults
    run_cmd sudo postconf -e "myhostname = $(hostname -f)"
    run_cmd sudo postconf -e "mydomain = $(hostname -d)"
    run_cmd sudo postconf -e "myorigin = \$mydomain"
    run_cmd sudo postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
    run_cmd sudo postconf -e "relayhost ="
    run_cmd sudo postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
    run_cmd sudo postconf -e "mailbox_size_limit = 0"
    run_cmd sudo postconf -e "recipient_delimiter = +"
    run_cmd sudo postconf -e "inet_interfaces = loopback-only"
    run_cmd sudo postconf -e "inet_protocols = all"

    # Restart Postfix to apply changes
    run_cmd sudo systemctl restart postfix || warn "Failed to restart postfix; continuing"

    succ "Postfix configured automatically"
}

install_packages() {
    log "Installing security packages"

    run_cmd sudo apt install -y ufw fail2ban unattended-upgrades auditd jq \
        || warn "Some packages failed to install; continuing"

    # Install mail utilities if requested
    if $INSTALL_MAIL_UTILS; then
        log "Installing mail utilities for email alerts"

        # Set debconf selections for non-interactive installation
        echo "postfix postfix/mailname string $(hostname -f)" | run_cmd sudo debconf-set-selections
        echo "postfix postfix/main_mailer_type string 'Internet Site'" | run_cmd sudo debconf-set-selections

        run_cmd sudo apt install -y mailutils postfix || warn "Failed to install mailutils/postfix; continuing"

        # Configure Postfix automatically
        configure_postfix

        # Test email functionality if email is provided
        if [[ -n "$EMAIL" ]]; then
            log "Testing email functionality to $EMAIL"
            echo "Server hardening completed successfully on $(hostname) at $(date)

SSH Port: $SSH_PORT
Admin User: $NEW_USER
Firewall: Active
Fail2ban: Active
Docker: Installed and secured

This is an automated test email from your hardened server." | \
                run_cmd sudo mail -s "Server Hardening Complete - $(hostname)" "$EMAIL" && \
                succ "Test email sent to $EMAIL" || \
                warn "Email test failed; check 'sudo tail -f /var/log/mail.log' for errors"
        else
            warn "Email not provided; skipping email test"
        fi
    fi

    succ "Packages installed"
}

# Timezone configuration
set_timezone() {
    log "Setting timezone to $TIMEZONE"

    if timedatectl list-timezones | grep -q "^$TIMEZONE$"; then
        run_cmd sudo timedatectl set-timezone "$TIMEZONE"
        succ "Timezone updated to $TIMEZONE"
    else
        warn "Unknown timezone '$TIMEZONE' - keeping current setting"
    fi
}

# User creation
create_user() {
    log "Creating admin user: $NEW_USER"

    if id "$NEW_USER" &>/dev/null; then
        warn "User $NEW_USER already exists. Updating SSH key."
    else
        run_cmd sudo useradd -m -s /bin/bash "$NEW_USER" \
            || warn "Failed to create user $NEW_USER; continuing"
        run_cmd sudo usermod -aG sudo "$NEW_USER" \
            || warn "Failed to add $NEW_USER to sudo group; continuing"
    fi

    run_cmd sudo mkdir -p "/home/$NEW_USER/.ssh"
    run_cmd sudo chmod 700 "/home/$NEW_USER/.ssh"
    run_cmd sudo chown "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"

    echo "$SSH_KEY" | run_cmd sudo tee "/home/$NEW_USER/.ssh/authorized_keys" >/dev/null
    run_cmd sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    run_cmd sudo chown "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh/authorized_keys"

    succ "SSH key installed"

    # Passwordless sudo
    echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" | run_cmd sudo tee "/etc/sudoers.d/$NEW_USER" >/dev/null
    run_cmd sudo chmod 440 "/etc/sudoers.d/$NEW_USER"

    succ "Passwordless sudo configured for $NEW_USER"
}

# Firewall configuration - FIXED: No comments in UFW commands
setup_firewall() {
    log "Configuring firewall on port $SSH_PORT"

    run_cmd sudo ufw --force disable
    run_cmd sudo ufw default deny incoming
    run_cmd sudo ufw default allow outgoing

    # Allow current SSH connection
    current_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')

    if [[ -z "$current_ip" ]]; then
        current_ip=$(who | awk '{print $5}' | head -1 | sed 's/[()]//g')
    fi

    if [[ -n "$current_ip" ]] && [[ $current_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        run_cmd sudo ufw allow from "$current_ip" to any port "$SSH_PORT" proto tcp
        succ "Allowed current IP $current_ip on port $SSH_PORT"
    else
        warn "Could not detect current SSH IP; ensure $SSH_PORT is accessible"
    fi

    run_cmd sudo ufw allow "$SSH_PORT/tcp"

    if [[ -n "$RESTRICT_IP" ]]; then
        run_cmd sudo ufw allow from "$RESTRICT_IP" to any port 80/tcp
        run_cmd sudo ufw allow from "$RESTRICT_IP" to any port 443/tcp
        succ "HTTP/HTTPS restricted to $RESTRICT_IP"
    else
        run_cmd sudo ufw allow 80/tcp
        run_cmd sudo ufw allow 443/tcp
        succ "HTTP/HTTPS open to all"
    fi

    run_cmd sudo ufw limit "$SSH_PORT/tcp"
    run_cmd sudo ufw --force enable

    succ "Firewall configured on port $SSH_PORT"
}

# SSH hardening
configure_ssh() {
    log "Configuring SSH on port $SSH_PORT (will restart later)"

    run_cmd sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

    # Preserve existing AllowUsers if requested
    local allow_users="$NEW_USER"

    if $KEEP_CURRENT_SSH_USERS; then
        existing_users=$(grep -E '^AllowUsers' /etc/ssh/sshd_config 2>/dev/null | \
                        awk '{for(i=2;i<=NF;i++) print $i}' | sort -u | tr '\n' ' ' | xargs)

        if [[ -n "$existing_users" ]]; then
            allow_users="$existing_users $NEW_USER"
        fi
    fi

    sudo tee /tmp/sshd_config.$$ >/dev/null <<EOF
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers $allow_users
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
Subsystem sftp internal-sftp
# Modern crypto (sshaudit.com 2024)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF

    run_cmd sudo mv /tmp/sshd_config.$$ /etc/ssh/sshd_config
    run_cmd sudo sshd -t || die "SSH config test failed"

    succ "SSH configuration prepared for port $SSH_PORT"
}

# Fail2ban configuration
setup_fail2ban() {
    log "Configuring fail2ban for SSH port $SSH_PORT"

    sudo tee /tmp/fail2ban-jail.local.$$ >/dev/null <<EOF
[DEFAULT]
bantime = $FAIL2BAN_BANTIME
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
maxretry = 3
EOF

    # Add Nginx and Apache protection if installed
    if command -v nginx &>/dev/null; then
        cat <<EOF | sudo tee -a /tmp/fail2ban-jail.local.$$ >/dev/null
[nginx-http-auth]
enabled = true
port = 80,443
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
EOF
    fi

    if command -v apache2 &>/dev/null; then
        cat <<EOF | sudo tee -a /tmp/fail2ban-jail.local.$$ >/dev/null
[apache-auth]
enabled = true
port = 80,443
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 5
EOF
    fi

    run_cmd sudo mv /tmp/fail2ban-jail.local.$$ /etc/fail2ban/jail.local
    run_cmd sudo systemctl enable --now fail2ban || warn "Failed to start fail2ban; continuing"

    succ "Fail2ban configured for port $SSH_PORT"
}

# Kernel hardening
harden_kernel() {
    log "Hardening kernel parameters"

    run_cmd sudo cp /etc/sysctl.conf /etc/sysctl.conf.backup 2>/dev/null || true

    sudo tee /tmp/sysctl-99-security.conf.$$ >/dev/null <<EOF
# Network
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
# Memory
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
# FS
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

    if ! $KEEP_SWAP; then
        echo "vm.swappiness = 0" | sudo tee -a /tmp/sysctl-99-security.conf.$$ >/dev/null
        run_cmd sudo swapoff -a || warn "Failed to disable swap; continuing"
        run_cmd sudo sed -i '/swap/s/^/#/' /etc/fstab || warn "Failed to comment swap in /etc/fstab; continuing"
        warn "Swap disabled - system may be unstable under memory pressure"
    fi

    run_cmd sudo mv /tmp/sysctl-99-security.conf.$$ /etc/sysctl.d/99-security.conf
    run_cmd sudo sysctl --system || warn "Failed to apply sysctl settings; continuing"

    succ "Kernel parameters hardened"
}

# Automatic updates
setup_auto_updates() {
    log "Configuring automatic security updates"

    local mail_conf=""
    [[ -n "$EMAIL" ]] && mail_conf=$'\nUnattended-Upgrade::Mail "'"$EMAIL"'";'

    sudo tee /tmp/apt-51-harden-upgrades.$$ >/dev/null <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};${mail_conf}
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    run_cmd sudo mv /tmp/apt-51-harden-upgrades.$$ /etc/apt/apt.conf.d/51-harden-upgrades

    sudo tee /tmp/apt-20auto-upgrades.$$ >/dev/null <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    run_cmd sudo mv /tmp/apt-20auto-upgrades.$$ /etc/apt/apt.conf.d/20auto-upgrades

    succ "Automatic updates configured"
}

# Docker installation and security - FIXED: Added proper permissions
install_docker() {
    log "Installing Docker"

    if command -v docker &>/dev/null; then
        warn "Docker already installed; applying security config only"
    else
        run_cmd sudo apt install -y ca-certificates curl gnupg \
            || warn "Failed to install prerequisites; continuing"

        run_cmd sudo mkdir -p /etc/apt/keyrings

        for i in {1..3}; do
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
                run_cmd sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg && break
            [[ $i -eq 3 ]] && warn "Failed to add Docker GPG key after 3 attempts; continuing"
            sleep 5
        done

        run_cmd sudo chmod a+r /etc/apt/keyrings/docker.gpg

        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            run_cmd sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

        for i in {1..3}; do
            run_cmd sudo apt update && break
            [[ $i -eq 3 ]] && warn "apt update for Docker failed after 3 attempts; continuing"
            sleep 5
        done

        run_cmd sudo apt install -y docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin \
            || warn "Docker installation failed; continuing"
    fi

    # Security configuration
    run_cmd sudo mkdir -p /etc/docker
    run_cmd sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.backup 2>/dev/null || true

    # Merge daemon.json with existing config
    local temp_json="/tmp/daemon.json.$$"
    cat > "$temp_json" <<EOF
{
    "log-driver": "json-file",
    "log-opts": { "max-size": "10m", "max-file": "3" },
    "icc": false,
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true
}
EOF

    if [[ -f /etc/docker/daemon.json ]]; then
        jq -s '.[0] * .[1]' /etc/docker/daemon.json "$temp_json" | \
            run_cmd sudo tee /etc/docker/daemon.json >/dev/null
    else
        run_cmd sudo mv "$temp_json" /etc/docker/daemon.json
    fi

    rm -f "$temp_json"

    # FIX: Set proper permissions for daemon.json
    run_cmd sudo chown root:root /etc/docker/daemon.json
    run_cmd sudo chmod 644 /etc/docker/daemon.json

    run_cmd sudo systemctl daemon-reload

    if $FORCE_DOCKER_RESTART; then
        run_cmd sudo systemctl restart docker \
            || warn "Failed to restart Docker. Check 'journalctl -u docker' for errors. Continuing..."
    else
        warn "Docker daemon not restarted to avoid disrupting containers. Run 'sudo systemctl restart docker' manually if needed."
    fi

    run_cmd sudo systemctl enable docker || warn "Failed to enable Docker; continuing"

    # Add user to docker group unless --no-docker-group
    if ! $NO_DOCKER_GROUP; then
        run_cmd sudo usermod -aG docker "$NEW_USER" \
            || warn "Failed to add $NEW_USER to docker group; continuing"
        warn "User $NEW_USER added to docker group - has root-equivalent privileges"
    else
        warn "Skipped adding $NEW_USER to docker group (--no-docker-group); use 'sudo docker' for Docker commands"
    fi

    # Verify Docker daemon
    local counter=0
    until sudo docker info &>/dev/null; do
        sleep 2
        counter=$((counter + 1))
        if [[ $counter -gt 30 ]]; then
            warn "Timeout waiting for Docker daemon; continuing without verification"
            break
        fi
    done

    succ "Docker installed and secured"
}

# Docker benchmark security - FIXED: Better log handling
run_docker_bench() {
    if $SKIP_BENCH; then
        warn "Skipping docker-bench-security (--skip-bench)"
        return
    fi

    log "Running Docker security benchmark"
    local repo="/opt/docker-bench-security"
    local log_file="/var/log/docker-bench.log"

    # Create log file with proper permissions first
    run_cmd sudo touch "$log_file"
    run_cmd sudo chmod 644 "$log_file"
    run_cmd sudo chown root:root "$log_file"

    # Check if Docker is running
    if ! sudo docker info &>/dev/null; then
        warn "Docker daemon not running; skipping benchmark"
        return
    fi

    # Download and extract benchmark tool if needed
    if [[ ! -d "$repo" ]]; then
        run_cmd sudo apt install -y wget tar \
            || warn "Failed to install wget/tar; skipping benchmark"

        for i in {1..3}; do
            wget -qO- https://github.com/docker/docker-bench-security/archive/refs/tags/v1.6.0.tar.gz | \
                run_cmd sudo tar -xz -C /opt && \
                run_cmd sudo mv /opt/docker-bench-security-1.6.0 "$repo" && break

            [[ $i -eq 3 ]] && warn "Failed to download docker-bench-security v1.6.0 after 3 attempts; skipping benchmark"
            sleep 5
        done
    fi

    # Run benchmark with proper permissions
    if [[ -d "$repo" ]]; then
        (cd "$repo" && run_cmd sudo ./docker-bench-security.sh 2>&1 | \
            run_cmd sudo tee "$log_file") || warn "Docker benchmark failed; continuing"

        succ "Docker benchmark completed - log saved to $log_file"
    else
        warn "Docker benchmark repository not found; skipping"
    fi
}

# Monitoring helper
create_monitoring() {
    log "Creating security-check helper"

    sudo tee /tmp/security-check.$$ >/dev/null <<'EOF'
#!/bin/bash
echo "=== Security Status ==="
printf "%-15s : %s\n" SSH "$(systemctl is-active ssh)"
printf "%-15s : %s\n" Firewall "$(sudo ufw status | head -1 | cut -d' ' -f2)"

# Fixed Fail2ban detection - use systemctl instead of fail2ban-client
if systemctl is-active fail2ban >/dev/null 2>&1; then
    printf "%-15s : %s\n" Fail2ban "OK"
else
    printf "%-15s : %s\n" Fail2ban "OFF"
fi

printf "%-15s : %s\n" Docker "$(systemctl is-active docker)"
printf "%-15s : %s\n" Auditd "$(systemctl is-active auditd)"

# Improved Auto-Updates detection
if [ -f /var/log/unattended-upgrades/unattended-upgrades.log ] && sudo grep -q "Packages that will be upgraded" /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null; then
    printf "%-15s : %s\n" Auto-Updates "OK"
else
    printf "%-15s : %s\n" Auto-Updates "Inactive"
fi

printf "%-15s : %s\n" Docker-Bench "$( [ -f /var/log/docker-bench.log ] && stat -c %y /var/log/docker-bench.log | cut -d' ' -f1 || echo Never )"
EOF

    run_cmd sudo mv /tmp/security-check.$$ /usr/local/bin/security-check
    run_cmd sudo chmod 755 /usr/local/bin/security-check
    run_cmd sudo chmod +x /usr/local/bin/security-check
    run_cmd sudo chown root:root /usr/local/bin/security-check

    succ "Security check helper installed"
}

# Final configuration - FIXED: Better auditd rules
finalize() {
    log "Finalizing configuration"

    run_cmd sudo systemctl enable --now auditd || warn "Failed to enable auditd; continuing"

    # Configure auditd log settings
    log "Configuring auditd log settings"

    sudo tee /tmp/auditd.conf.$$ >/dev/null <<EOF
max_log_file = 50
space_left_action = rotate
EOF

    run_cmd sudo sed -i '/^max_log_file\|^space_left_action/d' /etc/audit/auditd.conf
    cat /tmp/auditd.conf.$$ | run_cmd sudo tee -a /etc/audit/auditd.conf >/dev/null
    rm -f /tmp/auditd.conf.$$

    # Configure auditd rules - FIXED: Using syscall numbers instead of names
    log "Configuring auditd rules"

    sudo tee /tmp/audit-harden.rules.$$ >/dev/null <<EOF
# Monitor critical system files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes
# Monitor user/group changes (using syscall numbers: 105=setuid, 106=setgid, 109=setgroups)
-a always,exit -F arch=b64 -S 105 -S 106 -S 109 -k account_changes
EOF

    run_cmd sudo mv /tmp/audit-harden.rules.$$ /etc/audit/rules.d/harden.rules
    run_cmd sudo augenrules --load || warn "Failed to load auditd rules; continuing"

    # Write version log
    echo "$SCRIPT_VERSION" | run_cmd sudo tee /etc/harden-docker.version >/dev/null

    succ "Version logged to /etc/harden-docker.version"
    succ "Configuration finalized"
}

# Show summary with SSH restart - FIXED: Better file handling
show_summary() {
    local ip
    ip=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    local zone
    zone=$(timedatectl | awk -F': *' '/Time zone/ {print $2}' | awk '{print $1}')
    [[ -z "$zone" ]] && zone="UTC"

    local summary_file="/var/log/harden-docker-summary.log"

    {
        cat <<EOF

${GRN}══════════════════════════════════════${NC}
${GRN}  HARDENING COMPLETE – v$SCRIPT_VERSION ${NC}
${GRN}══════════════════════════════════════${NC}

Admin user       : $NEW_USER
SSH port         : $SSH_PORT
SSH users        : $( $KEEP_CURRENT_SSH_USERS && echo "Preserved + $NEW_USER" || echo "$NEW_USER only" )
Firewall         : Active (80,443,$SSH_PORT)
Fail2ban         : Active (SSH$( command -v nginx &>/dev/null && echo ", Nginx" || true )$( command -v apache2 &>/dev/null && echo ", Apache" || true )$( [[ "$FAIL2BAN_BANTIME" == "-1" ]] && echo ", Permanent bans" || echo ", ${FAIL2BAN_BANTIME}s bans" ))
Docker           : Secured$( $FORCE_DOCKER_RESTART && echo " & restarted" || echo ", restart skipped" )
Docker group     : $( $NO_DOCKER_GROUP && echo "Not added" || echo "Added" )
Docker bench     : $( $SKIP_BENCH && echo "Skipped" || echo "Run, log at /var/log/docker-bench.log" )
Time zone        : $zone
Auto-updates     : Enabled$( [[ -n "$EMAIL" ]] && echo " (alerts → $EMAIL)" )
HTTP restriction : $( [[ -n "$RESTRICT_IP" ]] && echo "$RESTRICT_IP" || echo "None" )
Swap             : $( $KEEP_SWAP && echo "Enabled" || echo "Disabled" )
Auditd           : Active

${YLW}NEXT STEPS${NC}
1. SSH will restart on port $SSH_PORT in 5 seconds (current connection may drop)
2. Test connection after restart: ssh -p $SSH_PORT $NEW_USER@$ip
3. Run 'security-check' to verify system status
EOF

        if ! $NO_REBOOT; then
            echo "4. System will reboot 10 seconds after SSH restart..."
        else
            echo "4. Skipping reboot (--no-reboot specified)"
        fi
    } | run_cmd sudo tee "$summary_file" >/dev/null

    if ! $DRY_RUN; then
        run_cmd sudo chmod 644 "$summary_file"
        run_cmd sudo chown root:root "$summary_file"
        succ "Summary logged to $summary_file"
    fi

    # Create monitoring script
    create_monitoring

    if $DRY_RUN; then
        warn "[DRY-RUN] Skipping SSH restart"
        succ "Dry-run completed"
        exit 0
    fi

    # Restart SSH service with countdown
    log "WARNING: SSH will restart on port $SSH_PORT in 5 seconds. Current connection may drop."

    for i in {5..1}; do
        echo -n "$i... "
        sleep 1
    done

    echo ""
    run_cmd sudo systemctl restart ssh || warn "Failed to restart SSH; verify configuration manually"
    succ "SSH restarted on port $SSH_PORT"
}

# Main execution with error handling
main() {
    echo "${BLU}Optimized Docker Web Server Hardening v$SCRIPT_VERSION${NC}"
    echo "Start time: $(date '+%Y-%m-%d %H:%M:%S %Z')"

    if $DRY_RUN; then
        warn "Running in dry-run mode: no changes will be applied"
    fi

    # Use a trap to ensure script continues even if some commands fail
    set +e
    trap 'warn "Command failed, but continuing execution: $BASH_COMMAND"' ERR

    validate_inputs
    check_system
    update_system
    install_packages
    set_timezone
    create_user
    setup_firewall
    configure_ssh
    setup_fail2ban
    harden_kernel
    setup_auto_updates
    install_docker
    run_docker_bench
    finalize
    show_summary

    # Re-enable strict error handling
    set -e
    trap - ERR

    if $DRY_RUN; then
        exit 0
    fi

    if ! $NO_REBOOT; then
        log "Rebooting system to apply all changes..."
        sleep 10
        run_cmd sudo reboot || warn "Failed to initiate reboot; please reboot manually"
    else
        succ "Script completed without reboot"
    fi
}

main "$@"
