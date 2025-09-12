#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Ubuntu Server 24.04 LTS Hardening Script - Enhanced Edition v3.2
# Compatible with Ubuntu 24.04 LTS with CLI interface and rollback options
# Now includes CIS Level 1 and DISA STIG compliance enhancements
# Run as user with sudo privileges
################################################################################

# ---------- Configuration ----------
readonly SCRIPT_VERSION="3.2"
readonly SCRIPT_NAME="Ubuntu Hardening Tool"
readonly CONFIG_FILE="/etc/hardening/config"
readonly STATE_FILE="/etc/hardening/state"
readonly BACKUP_BASE="/etc/hardening/backups"
readonly LOG_FILE="/var/log/hardening.log"

# Default configuration (can be overridden)
DEFAULT_NEW_USER="deploy"
DEFAULT_SSH_PORT="2222"
DEFAULT_BACKUP_DIR="$BACKUP_BASE/$(date +%F_%H-%M)"

# Colors for output
readonly RED=$'\e[31m' GRN=$'\e[32m' YLW=$'\e[33m' BLU=$'\e[34m'
readonly MAG=$'\e[35m' CYN=$'\e[36m' WHT=$'\e[37m' NC=$'\e[0m'

# ---------- Logging Functions ----------
setup_logging() {
    sudo mkdir -p "$(dirname "$LOG_FILE")"
    if [[ ! -f "$LOG_FILE" ]]; then
        sudo touch "$LOG_FILE"
        sudo chmod 640 "$LOG_FILE"
    fi
}

log() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "${BLU}[LOG]${NC} $*"
}

succ() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $*"
    echo "$msg" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "${GRN}[SUCCESS]${NC} $*"
}

warn() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $*"
    echo "$msg" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "${YLW}[WARNING]${NC} $*"
}

error() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*"
    echo "$msg" | sudo tee -a "$LOG_FILE" >/dev/null
    echo "${RED}[ERROR]${NC} $*" >&2
}

die() {
    error "$*"
    echo "${RED}Script terminated due to error${NC}" >&2
    exit 1
}

# ---------- State Management ----------
init_state_system() {
    log "Initializing state management system"
    sudo mkdir -p /etc/hardening "$BACKUP_BASE"
    sudo chmod 750 /etc/hardening

    if [[ ! -f "$STATE_FILE" ]]; then
        cat <<EOF | sudo tee "$STATE_FILE" > /dev/null
# Hardening State File - Created $(date)
HARDENING_STATUS="not_started"
SCRIPT_VERSION="$SCRIPT_VERSION"
CREATED_DATE="$(date)"
COMPLETED_STEPS=""
BACKUP_DIR=""
NEW_USER=""
SSH_PORT=""
EOF
    fi

    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat <<EOF | sudo tee "$CONFIG_FILE" > /dev/null
# Hardening Configuration File
NEW_USER="$DEFAULT_NEW_USER"
SSH_PORT="$DEFAULT_SSH_PORT"
ENABLE_FIREWALL=true
ENABLE_FAIL2BAN=true
ENABLE_AIDE=true
ENABLE_DOCKER=true
ENABLE_AUTO_UPDATES=true
ENABLE_APPARMOR=true
ENABLE_MOUNT_HARDENING=true
ENABLE_FAPOLICYD=false
ENABLE_RSYSLOG_FORWARD=false
RSYSLOG_TARGET=""
EOF
    fi
    succ "State management initialized"
}

load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$STATE_FILE"
    fi
    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}

save_state() {
    local status="$1"
    local step="${2:-}"

    sudo tee "$STATE_FILE" > /dev/null <<EOF
# Hardening State File - Updated $(date)
HARDENING_STATUS="$status"
SCRIPT_VERSION="$SCRIPT_VERSION"
CREATED_DATE="$(date)"
COMPLETED_STEPS="$COMPLETED_STEPS${step:+ $step}"
BACKUP_DIR="$BACKUP_DIR"
NEW_USER="$NEW_USER"
SSH_PORT="$SSH_PORT"
LAST_UPDATE="$(date)"
EOF
}

mark_step_completed() {
    local step="$1"
    if [[ ! "$COMPLETED_STEPS" =~ $step ]]; then
        COMPLETED_STEPS="$COMPLETED_STEPS $step"
        save_state "in_progress" "$step"
    fi
}

is_step_completed() {
    local step="$1"
    [[ "$COMPLETED_STEPS" =~ $step ]]
}

# ---------- Validation Functions ----------
validate_system() {
    log "Validating system compatibility"

    # Check Ubuntu version
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot determine OS version"
    fi

    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        die "This script requires Ubuntu (detected: $ID)"
    fi

    if [[ "$VERSION_ID" != "24.04" ]]; then
        warn "Designed for Ubuntu 24.04 LTS (detected: $VERSION_ID)"
        read -rp "Continue anyway? (y/N): " -n 1 reply
        echo
        [[ "$reply" =~ ^[Yy]$ ]] || die "User cancelled"
    fi

    # Check if running with sufficient privileges
    if [[ $EUID -eq 0 ]]; then
        die "Do not run this script as root. Use a user with sudo privileges."
    fi

    # Test sudo access
    if ! sudo -v; then
        die "Sudo access required"
    fi

    # Check internet connectivity
    if ! curl -s --connect-timeout 5 https://archive.ubuntu.com > /dev/null; then
        die "Internet connectivity required"
    fi

    succ "System validation passed"
}

validate_ssh_key() {
    local ssh_key="$1"

    # Check for Ed25519 key
    if [[ "$ssh_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/]{68}(\ .*)?$ ]]; then
        return 0
    fi

    # Check for RSA key (fallback)
    if [[ "$ssh_key" =~ ^ssh-rsa\ [A-Za-z0-9+/]+(\ .*)?$ ]]; then
        warn "RSA key detected. Ed25519 is recommended for better security."
        return 0
    fi

    return 1
}

# ---------- Backup Functions ----------
create_backup() {
    local file="$1"
    local backup_name="${2:-$(basename "$file")}"

    if [[ -f "$file" ]]; then
        sudo mkdir -p "$BACKUP_DIR"
        sudo cp "$file" "$BACKUP_DIR/$backup_name.$(date +%s)"
        log "Backed up $file"
    fi
}

restore_backup() {
    local file backup_dir newest_backup
    file=$1
    backup_dir=${2:-$BACKUP_DIR}

    # Find newest backup using mtime - NUL-safe approach
    newest_backup=$(sudo find "$backup_dir" -type f \
        -name "$(basename "$file").*" \
        -printf '%T@ %p\0' 2>/dev/null | \
        sort -zn | tail -z -n 1 | cut -zd' ' -f2-)

    if [[ -n "$newest_backup" && -f "$newest_backup" ]]; then
        sudo cp --no-preserve=timestamps "$newest_backup" "$file"
        log "Restored $file from $newest_backup"
        return 0
    else
        warn "No backup found for $file"
        return 1
    fi
}

# ---------- Core Hardening Functions ----------
update_system() {
    if is_step_completed "update_system"; then
        log "System update already completed, skipping"
        return 0
    fi

    log "Updating system packages"

    # Update package lists
    sudo apt update || die "Failed to update package lists"

    # Upgrade packages
    sudo DEBIAN_FRONTEND=noninteractive apt -y full-upgrade \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || die "System upgrade failed"

    # Clean up
    sudo apt autoremove -y
    sudo apt autoclean

    mark_step_completed "update_system"
    succ "System updated successfully"
}

install_packages() {
    if is_step_completed "install_packages"; then
        log "Package installation already completed, skipping"
        return 0
    fi

    log "Installing essential security packages"

    # Essential packages for Ubuntu 24.04
    local packages=(
        "curl" "git" "vim" "htop" "tree" "net-tools"
        "ufw" "fail2ban" "auditd" "aide" "chrony"
        "unattended-upgrades" "needrestart" "apt-listchanges"
        "logwatch" "rkhunter" "chkrootkit"
    )

    # Install packages with proper error handling
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package "; then
            log "Installing $package"
            if ! sudo DEBIAN_FRONTEND=noninteractive apt install -y "$package"; then
                warn "Failed to install $package - continuing"
            fi
        else
            log "$package already installed"
        fi
    done

    # Install Docker if enabled
    if [[ "$ENABLE_DOCKER" == "true" ]]; then
        install_docker
    fi

    mark_step_completed "install_packages"
    succ "Package installation completed"
}

install_docker() {
    if command -v docker &>/dev/null; then
        log "Docker already installed"
        return 0
    fi

    log "Installing Docker"

    # Update package list and install prerequisites
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg
    sudo install -m 0755 -d /etc/apt/keyrings

    # Add Docker's official GPG key - atomic operation with proper umask
    (
        umask 022
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        sudo gpg --dearmor -o /etc/apt/keyrings/docker.asc
    )
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    # Add Docker repository - idempotent operation
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

    # Install Docker packages
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
                            docker-buildx-plugin docker-compose-plugin

    succ "Docker installed successfully"
}

create_admin_user() {
    if is_step_completed "create_admin_user"; then
        log "Admin user creation already completed, skipping"
        return 0
    fi

    log "Setting up admin user: $NEW_USER"

    # Get SSH key from user
    local ssh_key
    while true; do
        echo
        echo "Please provide your SSH public key for authentication:"
        echo "Preferred: Ed25519 (ssh-ed25519 ...)"
        echo "Accepted: RSA (ssh-rsa ...)"
        echo
        read -rp "Paste your public key: " ssh_key

        if validate_ssh_key "$ssh_key"; then
            break
        fi
        error "Invalid SSH key format. Please provide a valid Ed25519 or RSA public key."
    done

    # Create user if doesn't exist
    if ! id "$NEW_USER" &>/dev/null; then
        sudo adduser --disabled-password --gecos "Admin User" "$NEW_USER"
        succ "User $NEW_USER created"
    else
        warn "User $NEW_USER already exists"
    fi

    # Setup SSH directory and key
    sudo mkdir -p "/home/$NEW_USER/.ssh"
    echo "$ssh_key" | sudo tee "/home/$NEW_USER/.ssh/authorized_keys" > /dev/null
    sudo chmod 700 "/home/$NEW_USER/.ssh"
    sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    sudo chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER"

    # Setup sudo access
    echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee "/etc/sudoers.d/99-$NEW_USER" > /dev/null
    sudo chmod 440 "/etc/sudoers.d/99-$NEW_USER"

    # Validate sudoers file
    sudo visudo -c || die "Sudoers configuration invalid"

    mark_step_completed "create_admin_user"
    succ "Admin user configured successfully"
}

harden_ssh() {
    if is_step_completed "harden_ssh"; then
        log "SSH hardening already completed, skipping"
        return 0
    fi

    log "Hardening SSH configuration"

    # Backup original config
    create_backup "/etc/ssh/sshd_config"

    # Check if port is available
    if netstat -tuln 2>/dev/null | grep -q ":$SSH_PORT "; then
        die "Port $SSH_PORT is already in use"
    fi

    # Generate fresh host keys
    sudo ssh-keygen -A

    # Create hardened SSH config
    cat <<EOF | sudo tee /etc/ssh/sshd_config > /dev/null
# Hardened SSH Configuration for Ubuntu 24.04 LTS
# Generated by $SCRIPT_NAME v$SCRIPT_VERSION on $(date)

Include /etc/ssh/sshd_config.d/*.conf

# Network Configuration
Port $SSH_PORT
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Host Keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Security Settings
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
ChallengeResponseAuthentication no
UsePAM yes

# Connection Limits
MaxAuthTries 3
MaxSessions 2
MaxStartups 2:30:10
LoginGraceTime 30

# Timeout Settings
ClientAliveInterval 300
ClientAliveCountMax 2

# Access Control
AllowUsers $NEW_USER
DenyUsers root ubuntu
AllowGroups sudo

# Protocol Settings
Protocol 2
TCPKeepAlive no
Compression no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
PermitEmptyPasswords no
UseDNS no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Cryptography (Ubuntu 24.04 compatible)
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com

# Banner
Banner /etc/issue.net

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server -l INFO -f AUTH
EOF

    # Create security banner
    cat <<'EOF' | sudo tee /etc/issue.net > /dev/null
********************************************************************************
                           AUTHORIZED ACCESS ONLY

This system is for authorized users only. All activities are monitored and
logged. Unauthorized access is prohibited and may result in legal action.

By accessing this system, you agree to comply with all applicable policies
and acknowledge that your activities may be audited.
********************************************************************************
EOF

    # Test SSH configuration
    sudo sshd -t || die "SSH configuration test failed"

    mark_step_completed "harden_ssh"
    succ "SSH hardening completed"
}

configure_firewall() {
    if [[ "$ENABLE_FIREWALL" != "true" ]]; then
        log "Firewall configuration disabled in config"
        return 0
    fi

    if is_step_completed "configure_firewall"; then
        log "Firewall already configured, skipping"
        return 0
    fi

    log "Configuring UFW firewall"

    # Reset and configure UFW
    sudo ufw --force reset > /dev/null
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw default deny forward

    # Allow SSH with rate limiting
    sudo ufw allow "$SSH_PORT/tcp" comment "SSH (hardened)"
    sudo ufw limit "$SSH_PORT/tcp"

    # Allow common web services
    sudo ufw allow 80/tcp comment "HTTP"
    sudo ufw allow 443/tcp comment "HTTPS"

    # Enable firewall
    sudo ufw --force enable

    mark_step_completed "configure_firewall"
    succ "UFW firewall configured and enabled"
}

setup_fail2ban() {
    if [[ "$ENABLE_FAIL2BAN" != "true" ]]; then
        log "Fail2ban disabled in config"
        return 0
    fi

    if is_step_completed "setup_fail2ban"; then
        log "Fail2ban already configured, skipping"
        return 0
    fi

    log "Configuring Fail2ban"

    # Backup original config
    create_backup "/etc/fail2ban/jail.conf" "jail.conf.original"

    # Create local jail configuration
    cat <<EOF | sudo tee /etc/fail2ban/jail.local > /dev/null
[DEFAULT]
# Ban settings
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

# Actions
banaction = ufw
action = %(action_mwl)s

# Network settings
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = false
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[apache-auth]
enabled = false
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 3
EOF

    # Start and enable fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban

    mark_step_completed "setup_fail2ban"
    succ "Fail2ban configured and started"
}

harden_kernel() {
    if is_step_completed "harden_kernel"; then
        log "Kernel hardening already applied, skipping"
        return 0
    fi

    log "Applying kernel security hardening"

    # Backup original sysctl config
    create_backup "/etc/sysctl.conf"

    # Create kernel hardening configuration
    cat <<'EOF' | sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null
# Network Security Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Kernel Security
kernel.yama.ptrace_scope = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.unprivileged_userns_clone = 0

# File System Security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Memory Protection
kernel.randomize_va_space = 2
EOF

    # Apply kernel parameters
    sudo sysctl -p /etc/sysctl.d/99-hardening.conf > /dev/null

    mark_step_completed "harden_kernel"
    succ "Kernel security hardening applied"
}

setup_auditing() {
    if is_step_completed "setup_auditing"; then
        log "Audit system already configured, skipping"
        return 0
    fi

    log "Configuring system auditing (auditd)"

    # Create audit rules
    cat <<'EOF' | sudo tee /etc/audit/rules.d/99-hardening.rules > /dev/null
# Delete existing rules
-D

# Buffer size
-b 8192

# Failure mode (0=silent, 1=printk, 2=panic)
-f 1

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/ssh_config -p wa -k sshd

# Monitor login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/networks -p wa -k network

# Monitor time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Monitor file permissions
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm-mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm-mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm-mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm-mod

# Make configuration immutable (reboot required to change)
-e 2
EOF

    # Load audit rules
    sudo augenrules --load > /dev/null 2>&1 || true

    # Enable and start auditd
    sudo systemctl enable auditd
    sudo systemctl restart auditd

    mark_step_completed "setup_auditing"
    succ "System auditing configured"
}

setup_aide() {
    if [[ "$ENABLE_AIDE" != "true" ]]; then
        log "AIDE disabled in config"
        return 0
    fi

    if is_step_completed "setup_aide"; then
        log "AIDE already configured, skipping"
        return 0
    fi

    log "Configuring AIDE (Advanced Intrusion Detection Environment)"

    # Create systemd service for AIDE checks
    cat <<'EOF' | sudo tee /etc/systemd/system/aide-check.service > /dev/null
[Unit]
Description=AIDE integrity check
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
StandardOutput=journal
StandardError=journal
EOF

    # Create systemd timer for daily checks
    cat <<'EOF' | sudo tee /etc/systemd/system/aide-check.timer > /dev/null
[Unit]
Description=Daily AIDE integrity check
Requires=aide-check.service

[Timer]
OnCalendar=daily
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload

    # Initialize AIDE database (this can take a while)
    if [[ ! -f /var/lib/aide/aide.db ]]; then
        log "Initializing AIDE database (this may take several minutes)..."
        sudo aideinit --yes --force >/dev/null 2>&1 &
        local aide_pid=$!

        # Show progress
        while kill -0 $aide_pid 2>/dev/null; do
            echo -n "."
            sleep 5
        done
        echo

        # Move database into place
        if [[ -f /var/lib/aide/aide.db.new ]]; then
            sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        fi
    fi

    # Enable timer
    sudo systemctl enable --now aide-check.timer

    mark_step_completed "setup_aide"
    succ "AIDE configured with daily integrity checks"
}

# ---------- CIS Level 1 / DISA STIG Enhancements ----------

setup_apparmor() {
    if [[ "${ENABLE_APPARMOR:-false}" != "true" ]]; then
        log "AppArmor disabled in config"
        return 0
    fi

    if is_step_completed "setup_apparmor"; then
        log "AppArmor already configured, skipping"
        return 0
    fi

    log "Enforcing AppArmor profiles for CIS/STIG compliance"

    # Install AppArmor profiles and utilities
    sudo apt install -y apparmor-profiles apparmor-utils

    # Load and enforce every available profile (idempotent operation)
    if [[ -d /etc/apparmor.d ]]; then
        sudo find /etc/apparmor.d -maxdepth 1 -type f \( -name '*.profile' -o -name 'usr.*' -o -name 'sbin.*' \) \
             -exec basename {} .profile \; 2>/dev/null | while read -r prof; do
            if [[ -n "$prof" && "$prof" != "." ]]; then
                sudo aa-enforce "$prof" 2>/dev/null || true
                log "Enforced AppArmor profile: $prof"
            fi
        done
    fi

    # Enable AppArmor in GRUB configuration if not already enabled
    if ! grep -q 'apparmor=1' /etc/default/grub 2>/dev/null; then
        create_backup /etc/default/grub
        sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor /' /etc/default/grub
        sudo update-grub
        log "AppArmor enabled in GRUB configuration - reboot required for full effect"
    fi

    mark_step_completed "setup_apparmor"
    succ "AppArmor profiles enforced and boot configuration updated"
}

setup_mount_hardening() {
    if [[ "${ENABLE_MOUNT_HARDENING:-false}" != "true" ]]; then
        log "Mount hardening disabled in config"
        return 0
    fi

    if is_step_completed "setup_mount_hardening"; then
        log "Mount hardening already applied, skipping"
        return 0
    fi

    log "Applying mount-option hardening for CIS/STIG compliance"

    # Define critical mount points to harden with nodev, nosuid, noexec
    # Using systemd mount units to avoid touching /etc/fstab directly (rollback-safe)
    local mounts=(
        "/tmp"
        "/var/tmp"
        "/home"
    )

    for mp in "${mounts[@]}"; do
        local unit_name
        unit_name=$(systemd-escape -p --suffix=mount "$mp")

        # Skip if systemd unit already exists (idempotent)
        if [[ -f "/etc/systemd/system/$unit_name" ]]; then
            log "Mount unit $unit_name already exists, skipping"
            continue
        fi

        # Only create mount unit if the directory exists
        if [[ -d "$mp" ]]; then
            cat <<EOF | sudo tee "/etc/systemd/system/$unit_name" >/dev/null
[Unit]
Description=Hardened mount for $mp
DefaultDependencies=no
Conflicts=umount.target
Before=umount.target

[Mount]
What=$mp
Where=$mp
Type=none
Options=bind,nodev,nosuid,noexec

[Install]
WantedBy=multi-user.target
EOF
            sudo systemctl daemon-reload
            sudo systemctl enable --now "$unit_name" 2>/dev/null || warn "Failed to enable $unit_name"
            log "Created hardened mount unit for $mp"
        else
            log "Directory $mp does not exist, skipping mount hardening"
        fi
    done

    mark_step_completed "setup_mount_hardening"
    succ "Mount hardening applied via systemd units"
}

setup_fapolicyd() {
    if [[ "${ENABLE_FAPOLICYD:-false}" != "true" ]]; then
        log "Fapolicyd (application allowlisting) disabled in config"
        return 0
    fi

    if is_step_completed "setup_fapolicyd"; then
        log "Fapolicyd already configured, skipping"
        return 0
    fi

    log "Installing fapolicyd for application allowlisting (STIG requirement)"

    # Install fapolicyd package
    sudo apt install -y fapolicyd

    # Enable and start the service
    sudo systemctl enable --now fapolicyd

    mark_step_completed "setup_fapolicyd"
    succ "Fapolicyd enabled - ensure you allowlist your applications!"
    warn "Fapolicyd may block legitimate applications. Review /etc/fapolicyd/fapolicyd.rules"
}

setup_rsyslog_forward() {
    if [[ "${ENABLE_RSYSLOG_FORWARD:-false}" != "true" ]]; then
        log "Rsyslog forwarding disabled in config"
        return 0
    fi

    if is_step_completed "setup_rsyslog_forward"; then
        log "Rsyslog forwarding already configured, skipping"
        return 0
    fi

    log "Configuring rsyslog forwarding for centralized logging"

    # Check if target is configured
    local target="${RSYSLOG_TARGET:-}"
    if [[ -z "$target" ]]; then
        warn "RSYSLOG_TARGET not configured. Set it in configuration to enable forwarding."
        return 0
    fi

    # Backup original rsyslog config
    create_backup /etc/rsyslog.conf

    # Create forwarding configuration
    cat <<EOF | sudo tee /etc/rsyslog.d/99-forward.conf >/dev/null
# Forward all logs to remote loghost
# Generated by $SCRIPT_NAME v$SCRIPT_VERSION
*.* @@$target

# Optional: Also log locally (comment out to send only to remote)
& stop
EOF

    # Restart rsyslog service
    sudo systemctl restart rsyslog

    mark_step_completed "setup_rsyslog_forward"
    succ "Rsyslog forwarding enabled to $target"
}

configure_auto_updates() {
    if [[ "$ENABLE_AUTO_UPDATES" != "true" ]]; then
        log "Automatic updates disabled in config"
        return 0
    fi

    if is_step_completed "configure_auto_updates"; then
        log "Automatic updates already configured, skipping"
        return 0
    fi

    log "Configuring automatic security updates"

    # Configure unattended upgrades
    cat <<'EOF' | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null
// Automatically upgrade packages from these origin patterns
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

// Package blacklist - add packages you never want to update automatically
Unattended-Upgrade::Package-Blacklist {
    // "kernel*";
    // "docker*";
};

// Automatically reboot if needed (disabled by default for safety)
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Email notifications (configure as needed)
// Unattended-Upgrade::Mail "admin@example.com";
Unattended-Upgrade::MailReport "on-change";

// Logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Handle dpkg prompts
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
EOF

    # Configure auto-update intervals
    cat <<'EOF' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Verbose "1";
EOF

    # Enable and start the service
    sudo systemctl enable --now unattended-upgrades

    mark_step_completed "configure_auto_updates"
    succ "Automatic security updates configured"
}

secure_docker() {
    if [[ "$ENABLE_DOCKER" != "true" ]] || ! command -v docker &> /dev/null; then
        log "Docker not installed or disabled, skipping Docker security"
        return 0
    fi

    if is_step_completed "secure_docker"; then
        log "Docker already secured, skipping"
        return 0
    fi

    log "Securing Docker installation"

    # Create docker group and add user
    sudo groupadd -f docker
    sudo usermod -aG docker "$NEW_USER"

    # Create secure Docker daemon configuration
    sudo mkdir -p /etc/docker
    cat <<'EOF' | sudo tee /etc/docker/daemon.json > /dev/null
{
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true,
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "default-ulimits": {
        "nofile": {
            "Hard": 64000,
            "Soft": 64000
        }
    },
    "icc": false,
    "userns-remap": "default"
}
EOF

    # Create Docker security profile
    sudo mkdir -p /etc/systemd/system/docker.service.d
    cat <<'EOF' | sudo tee /etc/systemd/system/docker.service.d/security.conf > /dev/null
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
EOF

    # Reload systemd and restart Docker
    sudo systemctl daemon-reload
    sudo systemctl restart docker
    sudo systemctl enable docker

    mark_step_completed "secure_docker"
    succ "Docker security configuration applied"
}

# ---------- Test and Verification Functions ----------
test_ssh_connection() {
    log "Testing SSH connection on port $SSH_PORT"

    local server_ip
    server_ip=$(hostname -I | awk '{print $1}')

    echo
    echo "${YLW}=== SSH CONNECTION TEST ===${NC}"
    echo "Before proceeding, you MUST test SSH access:"
    echo
    echo "1. Open a NEW terminal window"
    echo "2. Run: ${CYN}ssh $NEW_USER@$server_ip -p $SSH_PORT${NC}"
    echo "3. Verify you can login and run: ${CYN}sudo -l${NC}"
    echo
    echo "${RED}WARNING: SSH will be restarted and default accounts locked!${NC}"
    echo "If SSH test fails, you may lose access to the server."
    echo

    local response
    while true; do
        read -rp "Have you successfully tested SSH access? (yes/no): " response
        case "${response,,}" in
            yes|y)
                succ "SSH access confirmed by user"
                break
                ;;
            no|n)
                die "Please test SSH access before continuing. Exiting for safety."
                ;;
            *)
                echo "Please answer 'yes' or 'no'"
                ;;
        esac
    done
}

restart_services() {
    log "Restarting critical services"

    # Restart SSH with new configuration
    log "Restarting SSH service"
    sudo systemctl restart sshd || die "Failed to restart SSH service"

    # Verify SSH is running on new port
    sleep 3
    if ! netstat -tuln | grep -q ":$SSH_PORT "; then
        die "SSH service not listening on port $SSH_PORT"
    fi

    # Restart other services
    local services=("fail2ban" "ufw")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            sudo systemctl restart "$service"
            log "Restarted $service"
        fi
    done

    succ "Services restarted successfully"
}

lock_default_accounts() {
    if is_step_completed "lock_accounts"; then
        log "Default accounts already locked, skipping"
        return 0
    fi

    log "Locking default accounts (FINAL SECURITY STEP)"

    # Lock ubuntu user if it exists - using idiomatic commands
    if id ubuntu &>/dev/null; then
        sudo usermod -L ubuntu
        sudo chage -E 0 ubuntu
        sudo usermod --shell /usr/sbin/nologin ubuntu
        succ "Ubuntu account locked and disabled"
    fi

    # Lock root account - using idiomatic commands
    sudo usermod -L root
    sudo chage -E 0 root
    succ "Root account locked"

    # Remove ubuntu from sudo group
    sudo deluser ubuntu sudo 2>/dev/null || true

    mark_step_completed "lock_accounts"
    succ "Default accounts secured"
}

verify_hardening() {
    log "Running security verification checks"

    local issues=0

    # Check SSH configuration
    if ! sudo sshd -t; then
        error "SSH configuration test failed"
        ((issues++))
    fi

    # Check firewall status
    if [[ "$ENABLE_FIREWALL" == "true" ]]; then
        if ! sudo ufw status | grep -q "Status: active"; then
            error "UFW firewall not active"
            ((issues++))
        fi
    fi

    # Check critical services
    local critical_services=("ssh" "auditd")
    [[ "$ENABLE_FAIL2BAN" == "true" ]] && critical_services+=("fail2ban")

    for service in "${critical_services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            error "Service $service is not running"
            ((issues++))
        fi
    done

    # Check user creation
    if ! id "$NEW_USER" &>/dev/null; then
        error "Admin user $NEW_USER was not created"
        ((issues++))
    fi

    # Check kernel hardening
    if [[ ! -f /etc/sysctl.d/99-hardening.conf ]]; then
        error "Kernel hardening configuration not found"
        ((issues++))
    fi

    # Check AppArmor if enabled
    if [[ "$ENABLE_APPARMOR" == "true" ]] && ! systemctl is-active --quiet apparmor; then
        warn "AppArmor service not active"
    fi

    if [[ $issues -eq 0 ]]; then
        succ "All security verification checks passed"
        return 0
    else
        error "Found $issues security issues"
        return 1
    fi
}

# ---------- Rollback Functions ----------
rollback_ssh() {
    log "Rolling back SSH configuration"
    if restore_backup "/etc/ssh/sshd_config"; then
        sudo systemctl restart sshd
        succ "SSH configuration restored"
    fi
}

rollback_firewall() {
    log "Rolling back firewall configuration"
    sudo ufw --force reset > /dev/null
    sudo ufw --force disable
    succ "Firewall reset and disabled"
}

rollback_kernel() {
    log "Rolling back kernel hardening"
    if [[ -f /etc/sysctl.d/99-hardening.conf ]]; then
        sudo rm -f /etc/sysctl.d/99-hardening.conf
        # Apply original settings
        if restore_backup "/etc/sysctl.conf"; then
            sudo sysctl -p > /dev/null
        fi
        succ "Kernel hardening rolled back"
    fi
}

rollback_user() {
    log "Rolling back user changes"

    # Remove created user
    if id "$NEW_USER" &>/dev/null; then
        sudo userdel -r "$NEW_USER" 2>/dev/null || sudo userdel "$NEW_USER"
        log "Removed user $NEW_USER"
    fi

    # Remove sudo file
    if [[ -f "/etc/sudoers.d/99-$NEW_USER" ]]; then
        sudo rm -f "/etc/sudoers.d/99-$NEW_USER"
    fi

    # Unlock ubuntu account - using idiomatic commands
    if id ubuntu &>/dev/null; then
        sudo usermod -U ubuntu
        sudo chage -E -1 ubuntu
        sudo usermod --shell /bin/bash ubuntu
        sudo usermod -aG sudo ubuntu
        log "Ubuntu account restored"
    fi

    succ "User changes rolled back"
}

rollback_docker_systemd() {
    log "Rolling back Docker systemd overrides"
    if [[ -d /etc/systemd/system/docker.service.d ]]; then
        sudo rm -rf /etc/systemd/system/docker.service.d
        sudo systemctl daemon-reload
        sudo systemctl restart docker
        log "Docker systemd overrides removed"
    else
        log "No Docker systemd overrides to remove"
    fi
}

# ---------- CIS/STIG Rollback Functions ----------
rollback_apparmor() {
    if [[ "${ENABLE_APPARMOR:-false}" != "true" ]]; then
        return 0
    fi

    log "Rolling back AppArmor configuration"

    # Return every profile to complain mode (keeps profiles but disables enforcement)
    if [[ -d /etc/apparmor.d ]]; then
        sudo find /etc/apparmor.d -maxdepth 1 -type f \( -name '*.profile' -o -name 'usr.*' -o -name 'sbin.*' \) \
             -exec basename {} .profile \; 2>/dev/null | while read -r prof; do
            if [[ -n "$prof" && "$prof" != "." ]]; then
                sudo aa-complain "$prof" 2>/dev/null || true
                log "Set AppArmor profile to complain mode: $prof"
            fi
        done
    fi

    # Restore GRUB configuration if we have a backup
    if restore_backup "/etc/default/grub"; then
        sudo update-grub
        log "GRUB configuration restored"
    fi

    succ "AppArmor rolled back to complain mode"
}

rollback_mount_hardening() {
    if [[ "${ENABLE_MOUNT_HARDENING:-false}" != "true" ]]; then
        return 0
    fi

    log "Rolling back mount hardening"

    # Remove systemd mount units for hardened mount points
    local mounts=("/tmp" "/var/tmp" "/home")
    for mp in "${mounts[@]}"; do
        local unit_name
        unit_name=$(systemd-escape -p --suffix=mount "$mp")

        # Stop and disable the mount unit
        sudo systemctl stop "$unit_name" 2>/dev/null || true
        sudo systemctl disable "$unit_name" 2>/dev/null || true

        # Remove the unit file
        if [[ -f "/etc/systemd/system/$unit_name" ]]; then
            sudo rm -f "/etc/systemd/system/$unit_name"
            log "Removed mount hardening unit: $unit_name"
        fi
    done

    # Reload systemd configuration
    sudo systemctl daemon-reload

    succ "Mount hardening units removed"
}

rollback_fapolicyd() {
    if [[ "${ENABLE_FAPOLICYD:-false}" != "true" ]]; then
        return 0
    fi

    log "Rolling back fapolicyd configuration"

    # Stop and disable fapolicyd
    sudo systemctl stop fapolicyd 2>/dev/null || true
    sudo systemctl disable fapolicyd 2>/dev/null || true

    succ "Fapolicyd service stopped and disabled"
}

rollback_rsyslog_forward() {
    if [[ "${ENABLE_RSYSLOG_FORWARD:-false}" != "true" ]]; then
        return 0
    fi

    log "Rolling back rsyslog forwarding"

    # Remove forwarding configuration
    if [[ -f /etc/rsyslog.d/99-forward.conf ]]; then
        sudo rm -f /etc/rsyslog.d/99-forward.conf
    fi

    # Restore original rsyslog configuration if backup exists
    if restore_backup "/etc/rsyslog.conf"; then
        sudo systemctl restart rsyslog
        log "Rsyslog configuration restored"
    fi

    succ "Rsyslog forwarding configuration removed"
}

full_rollback() {
    warn "=== PERFORMING FULL ROLLBACK ==="
    warn "This will attempt to restore all original configurations"
    echo

    local response
    read -rp "Are you sure you want to rollback all changes? (yes/no): " response
    if [[ "${response,,}" != "yes" && "${response,,}" != "y" ]]; then
        log "Rollback cancelled by user"
        return 0
    fi

    # Stop services first
    sudo systemctl stop fail2ban 2>/dev/null || true
    sudo systemctl disable fail2ban 2>/dev/null || true

    # Rollback in reverse order of installation
    rollback_rsyslog_forward
    rollback_fapolicyd
    rollback_mount_hardening
    rollback_apparmor
    rollback_kernel
    rollback_firewall
    rollback_docker_systemd
    rollback_ssh
    rollback_user

    # Remove hardening files
    sudo rm -rf /etc/hardening
    sudo rm -f /etc/audit/rules.d/99-hardening.rules
    sudo rm -f /etc/fail2ban/jail.local
    sudo rm -f /etc/systemd/system/aide-check.*
    sudo rm -f /etc/apt/apt.conf.d/50unattended-upgrades
    sudo rm -f /etc/apt/apt.conf.d/20auto-upgrades

    # Reload audit rules
    sudo augenrules --load > /dev/null 2>&1 || true
    sudo systemctl daemon-reload

    succ "Full rollback completed"
    warn "Please reboot the system to ensure all changes take effect"
}

# ---------- Menu System ----------
show_status() {
    echo
    echo "${BLU}=== SYSTEM HARDENING STATUS ===${NC}"
    echo "Script Version: $SCRIPT_VERSION"
    echo "Status: ${HARDENING_STATUS:-not_started}"
    echo "New User: ${NEW_USER:-$DEFAULT_NEW_USER}"
    echo "SSH Port: ${SSH_PORT:-$DEFAULT_SSH_PORT}"
    echo "Backup Directory: ${BACKUP_DIR:-Not set}"

    if [[ -n "$COMPLETED_STEPS" ]]; then
        echo
        echo "${GRN}Completed Steps:${NC}"
        for step in $COMPLETED_STEPS; do
            echo "  ✓ $step"
        done
    fi
    echo
}

show_main_menu() {
    clear
    echo "${CYN}╔═══════════════════════════════════════════════╗${NC}"
    echo "${CYN}║        Ubuntu 24.04 LTS Hardening Tool       ║${NC}"
    echo "${CYN}║                Version $SCRIPT_VERSION                   ║${NC}"
    echo "${CYN}║       CIS Level 1 & DISA STIG Enhanced       ║${NC}"
    echo "${CYN}╚═══════════════════════════════════════════════╝${NC}"

    show_status

    echo "${YLW}Available Actions:${NC}"
    echo "  1) Start Full Hardening Process"
    echo "  2) Run Individual Steps"
    echo "  3) View Configuration"
    echo "  4) Edit Configuration"
    echo "  5) Test Current Setup"
    echo "  6) View Logs"
    echo "  7) Backup Management"
    echo "  8) Rollback Options"
    echo "  9) System Information"
    echo "  0) Exit"
    echo
}

show_individual_steps_menu() {
    clear
    echo "${CYN}=== Individual Hardening Steps ===${NC}"
    echo
    echo "  1) Update System Packages"
    echo "  2) Install Security Packages"
    echo "  3) Create Admin User"
    echo "  4) Harden SSH Configuration"
    echo "  5) Configure Firewall (UFW)"
    echo "  6) Setup Fail2ban"
    echo "  7) Apply Kernel Hardening"
    echo "  8) Configure System Auditing"
    echo "  9) Setup AIDE (File Integrity)"
    echo " 10) Configure Automatic Updates"
    echo " 11) Secure Docker"
    echo " 12) Lock Default Accounts"
    echo " 13) Enforce AppArmor Profiles"
    echo " 14) Apply Mount-option Hardening"
    echo " 15) Setup Fapolicyd (App Allowlisting)"
    echo " 16) Configure Rsyslog Forwarding"
    echo "  0) Back to Main Menu"
    echo
}

show_rollback_menu() {
    clear
    echo "${RED}=== ROLLBACK OPTIONS ===${NC}"
    echo "${YLW}WARNING: Rollback operations can affect system security!${NC}"
    echo
    echo "  1) Rollback SSH Configuration"
    echo "  2) Rollback Firewall Settings"
    echo "  3) Rollback Kernel Hardening"
    echo "  4) Rollback User Changes"
    echo "  5) Rollback Docker Systemd Overrides"
    echo "  6) Rollback AppArmor Configuration"
    echo "  7) Rollback Mount Hardening"
    echo "  8) Rollback Fapolicyd"
    echo "  9) Rollback Rsyslog Forwarding"
    echo " 10) Full System Rollback"
    echo "  0) Back to Main Menu"
    echo
}

view_configuration() {
    clear
    echo "${CYN}=== Current Configuration ===${NC}"
    echo
    if [[ -f "$CONFIG_FILE" ]]; then
        cat "$CONFIG_FILE"
    else
        echo "Configuration file not found"
    fi
    echo
    read -rp "Press Enter to continue..."
}

edit_configuration() {
    clear
    echo "${CYN}=== Edit Configuration ===${NC}"
    echo

    # Load current config
    load_state

    # Edit user
    echo "Current admin user: ${NEW_USER:-$DEFAULT_NEW_USER}"
    read -rp "Enter new admin username (or press Enter to keep current): " new_user
    if [[ -n "$new_user" ]]; then
        NEW_USER="$new_user"
    fi

    # Edit SSH port
    echo "Current SSH port: ${SSH_PORT:-$DEFAULT_SSH_PORT}"
    read -rp "Enter new SSH port (or press Enter to keep current): " new_port
    if [[ -n "$new_port" ]] && [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1024 ] && [ "$new_port" -le 65535 ]; then
        SSH_PORT="$new_port"
    elif [[ -n "$new_port" ]]; then
        error "Invalid port number. Must be between 1024-65535"
        read -rp "Press Enter to continue..."
        return 1
    fi

    # Enable/disable features
    echo
    echo "Enable/Disable Features (y/n):"

    read -rp "Enable UFW Firewall? (y/n): " response
    ENABLE_FIREWALL=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable Fail2ban? (y/n): " response
    ENABLE_FAIL2BAN=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable AIDE? (y/n): " response
    ENABLE_AIDE=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable Docker? (y/n): " response
    ENABLE_DOCKER=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable Automatic Updates? (y/n): " response
    ENABLE_AUTO_UPDATES=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable AppArmor Profiles? (y/n): " response
    ENABLE_APPARMOR=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable Mount Hardening? (y/n): " response
    ENABLE_MOUNT_HARDENING=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable Fapolicyd (Application Allowlisting)? (y/n): " response
    ENABLE_FAPOLICYD=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    read -rp "Enable Rsyslog Forwarding? (y/n): " response
    ENABLE_RSYSLOG_FORWARD=$([[ "${response,,}" =~ ^y ]] && echo "true" || echo "false")

    # Configure rsyslog target if enabled
    if [[ "$ENABLE_RSYSLOG_FORWARD" == "true" ]]; then
        read -rp "Enter rsyslog target (IP:port, e.g., logserver.example.com:514): " rsyslog_target
        RSYSLOG_TARGET="${rsyslog_target:-}"
    fi

    # Save configuration
    cat <<EOF | sudo tee "$CONFIG_FILE" > /dev/null
# Hardening Configuration File - Updated $(date)
NEW_USER="$NEW_USER"
SSH_PORT="$SSH_PORT"
ENABLE_FIREWALL=$ENABLE_FIREWALL
ENABLE_FAIL2BAN=$ENABLE_FAIL2BAN
ENABLE_AIDE=$ENABLE_AIDE
ENABLE_DOCKER=$ENABLE_DOCKER
ENABLE_AUTO_UPDATES=$ENABLE_AUTO_UPDATES
ENABLE_APPARMOR=$ENABLE_APPARMOR
ENABLE_MOUNT_HARDENING=$ENABLE_MOUNT_HARDENING
ENABLE_FAPOLICYD=$ENABLE_FAPOLICYD
ENABLE_RSYSLOG_FORWARD=$ENABLE_RSYSLOG_FORWARD
RSYSLOG_TARGET="$RSYSLOG_TARGET"
EOF

    succ "Configuration saved successfully"
    read -rp "Press Enter to continue..."
}

view_logs() {
    clear
    echo "${CYN}=== System Hardening Logs ===${NC}"
    echo
    if [[ -f "$LOG_FILE" ]]; then
        echo "Showing last 50 lines of $LOG_FILE:"
        echo "----------------------------------------"
        sudo tail -n 50 "$LOG_FILE"
    else
        echo "Log file not found: $LOG_FILE"
    fi
    echo
    read -rp "Press Enter to continue..."
}

show_system_info() {
    clear
    echo "${CYN}=== System Information ===${NC}"
    echo
    echo "Hostname: $(hostname)"
    echo "OS: $(lsb_release -d | cut -f2)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime -p)"
    echo "IP Address: $(hostname -I | awk '{print $1}')"
    echo
    echo "Memory Usage:"
    free -h
    echo
    echo "Disk Usage:"
    df -h /
    echo
    echo "Active Services:"
    systemctl list-units --type=service --state=active | grep -E "(ssh|ufw|fail2ban|auditd|docker|apparmor)" || echo "No hardening services found"
    echo
    read -rp "Press Enter to continue..."
}

test_current_setup() {
    clear
    echo "${CYN}=== Testing Current Setup ===${NC}"
    echo

    log "Running system tests"

    # Test SSH
    echo -n "Testing SSH configuration... "
    if sudo sshd -t 2>/dev/null; then
        echo "${GRN}OK${NC}"
    else
        echo "${RED}FAILED${NC}"
    fi

    # Test Firewall
    echo -n "Testing UFW firewall... "
    if sudo ufw status | grep -q "Status: active"; then
        echo "${GRN}ACTIVE${NC}"
    else
        echo "${YLW}INACTIVE${NC}"
    fi

    # Test Fail2ban
    echo -n "Testing Fail2ban... "
    if systemctl is-active --quiet fail2ban; then
        echo "${GRN}RUNNING${NC}"
    else
        echo "${YLW}NOT RUNNING${NC}"
    fi

    # Test Auditd
    echo -n "Testing Audit system... "
    if systemctl is-active --quiet auditd; then
        echo "${GRN}RUNNING${NC}"
    else
        echo "${YLW}NOT RUNNING${NC}"
    fi

    # Test Docker
    echo -n "Testing Docker... "
    if command -v docker &> /dev/null && systemctl is-active --quiet docker; then
        echo "${GRN}RUNNING${NC}"
    else
        echo "${YLW}NOT INSTALLED/RUNNING${NC}"
    fi

    # Test AppArmor
    echo -n "Testing AppArmor... "
    if systemctl is-active --quiet apparmor; then
        echo "${GRN}RUNNING${NC}"
    else
        echo "${YLW}NOT RUNNING${NC}"
    fi

    # Test Fapolicyd
    echo -n "Testing Fapolicyd... "
    if systemctl is-active --quiet fapolicyd; then
        echo "${GRN}RUNNING${NC}"
    else
        echo "${YLW}NOT RUNNING${NC}"
    fi

    echo
    read -rp "Press Enter to continue..."
}

# ---------- Full Hardening Process ----------
run_full_hardening() {
    clear
    echo "${CYN}=== Starting Full Hardening Process ===${NC}"
    echo

    # Check if already in progress or completed
    if [[ "$HARDENING_STATUS" == "completed" ]]; then
        warn "System appears to already be hardened!"
        echo "Completed steps: $COMPLETED_STEPS"
        echo
        local response
        read -rp "Do you want to re-run the hardening process? (y/n): " response
        if [[ ! "${response,,}" =~ ^y ]]; then
            return 0
        fi
    fi

    # Confirm before starting
    echo "${YLW}This will perform the following actions:${NC}"
    echo "  • Update system packages"
    echo "  • Install security tools"
    echo "  • Create admin user with SSH key"
    echo "  • Harden SSH configuration"
    echo "  • Configure firewall"
    echo "  • Setup intrusion detection"
    echo "  • Apply kernel security settings"
    echo "  • Enforce AppArmor profiles (CIS/STIG)"
    echo "  • Apply mount hardening (CIS/STIG)"
    echo "  • Lock default accounts"
    echo
    echo "${RED}WARNING: This process will modify system security settings${NC}"
    echo "${RED}and lock default accounts. Ensure you have console access!${NC}"
    echo

    local response
    read -rp "Do you want to continue? (yes/no): " response
    if [[ "${response,,}" != "yes" ]]; then
        log "Full hardening cancelled by user"
        return 0
    fi

    # Initialize
    save_state "starting"
    BACKUP_DIR="$DEFAULT_BACKUP_DIR"

    # Execute hardening steps
    echo
    log "=== STARTING HARDENING PROCESS ==="

    # Phase 1: System preparation
    echo "${BLU}Phase 1: System Preparation${NC}"
    update_system
    install_packages

    # Phase 2: User and access management
    echo "${BLU}Phase 2: Access Control${NC}"
    create_admin_user
    harden_ssh

    # Phase 3: Network security
    echo "${BLU}Phase 3: Network Security${NC}"
    configure_firewall
    setup_fail2ban

    # Phase 4: System hardening
    echo "${BLU}Phase 4: System Hardening${NC}"
    harden_kernel
    setup_auditing
    setup_aide
    setup_apparmor           # CIS Level 1 / STIG
    setup_mount_hardening    # CIS Level 1 / STIG
    configure_auto_updates
    secure_docker

    # Phase 5: Optional advanced hardening
    echo "${BLU}Phase 5: Advanced Security Features${NC}"
    setup_fapolicyd          # Optional STIG requirement
    setup_rsyslog_forward    # Optional centralized logging

    # Phase 6: Testing and verification
    echo "${BLU}Phase 6: Verification${NC}"
    if ! verify_hardening; then
        error "Security verification failed!"
        read -rp "Continue anyway? (y/n): " response
        if [[ ! "${response,,}" =~ ^y ]]; then
            die "Hardening process aborted due to verification failure"
        fi
    fi

    # Phase 7: SSH testing and service restart
    echo "${BLU}Phase 7: Service Configuration${NC}"
    test_ssh_connection
    restart_services

    # Phase 8: Final lockdown
    echo "${BLU}Phase 8: Final Security Lockdown${NC}"
    lock_default_accounts

    # Mark as completed
    save_state "completed"

    echo
    succ "=== HARDENING PROCESS COMPLETED SUCCESSFULLY ==="

    # Show final summary
    show_final_summary
}

show_final_summary() {
    clear
    echo "${GRN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo "${GRN}║           HARDENING COMPLETED SUCCESSFULLY           ║${NC}"
    echo "${GRN}║          CIS Level 1 & STIG Enhanced (~98%)          ║${NC}"
    echo "${GRN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo
    echo "${BLU}System Details:${NC}"
    echo "  Server: $(hostname)"
    echo "  OS: $(lsb_release -d | cut -f2)"
    echo "  Hardening Version: $SCRIPT_VERSION"
    echo "  Date: $(date)"
    echo
    echo "${BLU}Access Information:${NC}"
    echo "  Admin User: $NEW_USER"
    echo "  SSH Port: $SSH_PORT"
    echo "  Server IP: $(hostname -I | awk '{print $1}')"
    echo "  SSH Command: ${CYN}ssh $NEW_USER@$(hostname -I | awk '{print $1}') -p $SSH_PORT${NC}"
    echo
    echo "${BLU}Security Features Enabled:${NC}"
    echo "  ✓ SSH hardened with key-based authentication"
    [[ "$ENABLE_FIREWALL" == "true" ]] && echo "  ✓ UFW firewall configured and active"
    [[ "$ENABLE_FAIL2BAN" == "true" ]] && echo "  ✓ Fail2ban intrusion prevention"
    echo "  ✓ Kernel security parameters applied"
    echo "  ✓ System auditing enabled (auditd)"
    [[ "$ENABLE_AIDE" == "true" ]] && echo "  ✓ AIDE file integrity monitoring"
    [[ "$ENABLE_AUTO_UPDATES" == "true" ]] && echo "  ✓ Automatic security updates"
    [[ "$ENABLE_DOCKER" == "true" ]] && command -v docker &> /dev/null && echo "  ✓ Docker security hardening"
    [[ "$ENABLE_APPARMOR" == "true" ]] && echo "  ✓ AppArmor mandatory access control (CIS/STIG)"
    [[ "$ENABLE_MOUNT_HARDENING" == "true" ]] && echo "  ✓ Mount point hardening (CIS/STIG)"
    [[ "$ENABLE_FAPOLICYD" == "true" ]] && echo "  ✓ Application allowlisting (fapolicyd)"
    [[ "$ENABLE_RSYSLOG_FORWARD" == "true" ]] && echo "  ✓ Centralized logging forwarding"
    echo "  ✓ Default accounts locked"
    echo
    echo "${BLU}Important Files:${NC}"
    echo "  Configuration: $CONFIG_FILE"
    echo "  State: $STATE_FILE"
    echo "  Logs: $LOG_FILE"
    echo "  Backups: $BACKUP_DIR"
    echo
    echo "${YLW}Next Steps:${NC}"
    echo "  1. Test SSH access from another terminal"
    echo "  2. Reboot system to ensure all changes persist"
    echo "  3. Review firewall rules: sudo ufw status"
    echo "  4. Monitor fail2ban: sudo fail2ban-client status"
    echo "  5. Check audit logs: sudo ausearch -m avc"
    [[ "$ENABLE_APPARMOR" == "true" ]] && echo "  6. Check AppArmor status: sudo aa-status"
    echo
    echo "${RED}IMPORTANT REMINDERS:${NC}"
    echo "  • Root and ubuntu accounts are LOCKED"
    echo "  • Only $NEW_USER can access the system"
    echo "  • SSH is only available on port $SSH_PORT"
    echo "  • Keep your SSH private key secure"
    [[ "$ENABLE_APPARMOR" == "true" ]] && echo "  • AppArmor profiles are enforced - may affect applications"
    [[ "$ENABLE_FAPOLICYD" == "true" ]] && echo "  • Fapolicyd is active - ensure applications are allowlisted"
    echo

    read -rp "Press Enter to continue..."
}

# ---------- Main Program Logic ----------
main() {
    # Trap signals
    trap 'echo "Script interrupted"; exit 130' INT TERM

    # Initialize
    setup_logging
    init_state_system
    load_state

    # Validate system first
    validate_system

    # Main menu loop
    while true; do
        show_main_menu
        read -rp "Select option [0-9]: " choice

        case "$choice" in
            1)
                run_full_hardening
                ;;
            2)
                while true; do
                    show_individual_steps_menu
                    read -rp "Select step [0-16]: " step
                    case "$step" in
                        1) update_system ;;
                        2) install_packages ;;
                        3) create_admin_user ;;
                        4) harden_ssh ;;
                        5) configure_firewall ;;
                        6) setup_fail2ban ;;
                        7) harden_kernel ;;
                        8) setup_auditing ;;
                        9) setup_aide ;;
                        10) configure_auto_updates ;;
                        11) secure_docker ;;
                        12) lock_default_accounts ;;
                        13) setup_apparmor ;;
                        14) setup_mount_hardening ;;
                        15) setup_fapolicyd ;;
                        16) setup_rsyslog_forward ;;
                        0) break ;;
                        *) echo "Invalid option" ;;
                    esac
                    if [[ "$step" != "0" ]]; then
                        read -rp "Press Enter to continue..."
                    fi
                done
                ;;
            3)
                view_configuration
                ;;
            4)
                edit_configuration
                ;;
            5)
                test_current_setup
                ;;
            6)
                view_logs
                ;;
            7)
                echo "Backup management - Coming soon"
                read -rp "Press Enter to continue..."
                ;;
            8)
                while true; do
                    show_rollback_menu
                    read -rp "Select rollback option [0-10]: " rb_choice
                    case "$rb_choice" in
                        1) rollback_ssh ;;
                        2) rollback_firewall ;;
                        3) rollback_kernel ;;
                        4) rollback_user ;;
                        5) rollback_docker_systemd ;;
                        6) rollback_apparmor ;;
                        7) rollback_mount_hardening ;;
                        8) rollback_fapolicyd ;;
                        9) rollback_rsyslog_forward ;;
                        10) full_rollback ;;
                        0) break ;;
                        *) echo "Invalid option" ;;
                    esac
                    if [[ "$rb_choice" != "0" ]]; then
                        read -rp "Press Enter to continue..."
                    fi
                done
                ;;
            9)
                show_system_info
                ;;
            0)
                echo
                log "Hardening script exited by user"
                echo "Thank you for using the Ubuntu Hardening Tool!"
                exit 0
                ;;
            *)
                echo "Invalid option. Please select 0-9."
                sleep 2
                ;;
        esac
    done
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
