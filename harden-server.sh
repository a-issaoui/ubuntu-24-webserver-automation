#!/usr/bin/env bash
set -euo pipefail
################################################################################
# Ubuntu 25.x Hardening – Enhanced Edition
# Run as ubuntu user with password-less sudo
# Enhanced with better error handling, validation, and security practices
################################################################################

# ---------- Configuration ----------
readonly NEW_USER="deploy"
readonly SSH_PORT="2222"              # Non-standard port for security
readonly BACKUP_DIR="/root/harden-backup-$(date +%F_%H-%M)"
readonly LOG="/var/log/harden-$(date +%F_%H-%M).log"
readonly SCRIPT_VERSION="2.0"

# Logging setup with rotation protection
exec > >(tee -a "$LOG") 2>&1
trap 'echo "Script interrupted at line $LINENO"; exit 130' INT TERM

# ---------- Colors & Logging ----------
readonly RED=$'\e[31m' GRN=$'\e[32m' YLW=$'\e[33m' BLU=$'\e[34m' NC=$'\e[0m'

log()    { echo "${BLU}[$(date +'%H:%M:%S')]${NC} $*"; }
succ()   { echo "${GRN}[$(date +'%H:%M:%S')] ✓${NC} $*"; }
warn()   { echo "${YLW}[$(date +'%H:%M:%S')] ⚠${NC} $*"; }
error()  { echo "${RED}[$(date +'%H:%M:%S')] ✗${NC} $*" >&2; }
die()    { error "$*"; exit 1; }

# ---------- Validation Functions ----------
validate_prerequisites() {
    log "Validating prerequisites"
    
    # Check if running as ubuntu user
    [[ "$USER" == "ubuntu" ]] || die "Must run as 'ubuntu' user"
    
    # Check sudo access
    sudo -v || die "Need password-less sudo access"
    
    # Check if we're on Ubuntu
    [[ -f /etc/lsb-release ]] && grep -q "Ubuntu" /etc/lsb-release || die "This script is for Ubuntu only"
    
    # Check internet connectivity
    curl -s --connect-timeout 5 https://archive.ubuntu.com > /dev/null || die "No internet connectivity"
    
    # Warn if already hardened
    [[ -f "/etc/ssh/sshd_config.bak" ]] && warn "System appears already hardened (SSH backup exists)"
    
    succ "Prerequisites validated"
}

validate_ssh_key() {
    local ssh_key="$1"
    
    # Validate Ed25519 format
    [[ "$ssh_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/]{68}(\ .*)?$ ]] || die "Invalid Ed25519 key format"
    
    # Check key isn't too short/long
    local key_part=$(echo "$ssh_key" | cut -d' ' -f2)
    local key_len=${#key_part}
    [[ $key_len -eq 68 ]] || die "Ed25519 key length invalid ($key_len chars, expected 68)"
    
    succ "SSH key validated"
}

backup_configs() {
    log "Creating configuration backups"
    sudo mkdir -p "$BACKUP_DIR"
    
    # Backup critical configs
    local configs=(
        "/etc/ssh/sshd_config"
        "/etc/sudoers"
        "/etc/ufw/ufw.conf"
        "/etc/fail2ban/jail.conf"
        "/etc/sysctl.conf"
    )
    
    for config in "${configs[@]}"; do
        [[ -f "$config" ]] && sudo cp "$config" "$BACKUP_DIR/" 2>/dev/null || true
    done
    
    succ "Backups created in $BACKUP_DIR"
}

# ---------- Main Functions ----------
update_system() {
    log "Updating system packages"
    
    # Update package lists
    sudo apt update -qq || die "Failed to update package lists"
    
    # Check for available upgrades
    local upgrades=$(apt list --upgradable 2>/dev/null | wc -l)
    log "Found $((upgrades - 1)) package updates"
    
    # Perform upgrade with proper frontend
    sudo DEBIAN_FRONTEND=noninteractive apt -y dist-upgrade \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || die "System upgrade failed"
    
    # Clean up
    sudo apt autoremove -y -qq
    sudo apt autoclean -qq
    
    succ "System updated successfully"
}

install_packages() {
    log "Installing security packages"
    
    # Add Docker repository if not present
    if ! apt-cache policy | grep -q "docker"; then
        log "Adding Docker repository"
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
            sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt update -qq
    fi
    
    # Essential packages (removed problematic ones)
    local packages=(
        "curl" "git" "vim" "htop" "tree" "unattended-upgrades"
        "ufw" "fail2ban" "auditd" "aide" "chrony" "needrestart"
        "docker-ce" "docker-ce-cli" "containerd.io" "docker-compose-plugin"
    )
    
    # Optional security packages (install separately to avoid dependency issues)
    local optional_packages=(
        "rkhunter" "chkrootkit" "logwatch"
    )
    
    # Install essential packages first
    sudo DEBIAN_FRONTEND=noninteractive apt install -y "${packages[@]}" || die "Essential package installation failed"
    
    # Try to install optional packages (don't fail if they can't be installed)
    for package in "${optional_packages[@]}"; do
        if sudo DEBIAN_FRONTEND=noninteractive apt install -y "$package" 2>/dev/null; then
            log "Installed optional package: $package"
        else
            warn "Could not install optional package: $package"
        fi
    done
    
    succ "Packages installed successfully"
}

create_admin_user() {
    log "Setting up admin user: $NEW_USER"
    
    # Get SSH key with validation
    local ssh_key
    while true; do
        read -rp "Paste your Ed25519 public key: " ssh_key
        if validate_ssh_key "$ssh_key"; then
            break
        fi
        error "Invalid key format. Please provide a valid Ed25519 public key."
    done
    
    # Create user if doesn't exist
    if ! id "$NEW_USER" &>/dev/null; then
        sudo adduser --disabled-password --gecos "Admin User" "$NEW_USER"
        succ "User $NEW_USER created"
    else
        warn "User $NEW_USER already exists"
    fi
    
    # Setup SSH directory with proper permissions
    sudo mkdir -p "/home/$NEW_USER/.ssh"
    echo "$ssh_key" | sudo tee "/home/$NEW_USER/.ssh/authorized_keys" > /dev/null
    sudo chmod 700 "/home/$NEW_USER/.ssh"
    sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    sudo chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER"
    
    # Setup sudo with more restrictive permissions
    echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee "/etc/sudoers.d/99-$NEW_USER" > /dev/null
    sudo chmod 440 "/etc/sudoers.d/99-$NEW_USER"
    sudo visudo -c || die "Sudoers configuration invalid"
    
    succ "Admin user configured with SSH key access"
}

harden_ssh() {
    log "Hardening SSH configuration"
    
    # Check if port is available
    if netstat -tuln 2>/dev/null | grep -q ":$SSH_PORT "; then
        die "Port $SSH_PORT is already in use"
    fi
    
    # Generate fresh host keys
    sudo ssh-keygen -A
    
    # Create hardened SSH config
    cat <<EOF | sudo tee /etc/ssh/sshd_config > /dev/null
# Hardened SSH Configuration - Generated $(date)
Include /etc/ssh/sshd_config.d/*.conf

# Network
Port $SSH_PORT
AddressFamily any
ListenAddress 0.0.0.0

# Host Keys (prefer Ed25519)
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Ciphers and Algorithms (modern only)
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 2
MaxStartups 2:30:10

# Connection settings
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
TCPKeepAlive no

# Access control
AllowUsers $NEW_USER
DenyUsers root ubuntu
AllowGroups sudo

# Features
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
Compression no
UseDNS no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Banner
Banner /etc/issue.net

# Subsystems
Subsystem sftp /usr/lib/openssh/sftp-server -l INFO -f AUTH
EOF

    # Create login banner
    cat <<'EOF' | sudo tee /etc/issue.net > /dev/null
********************************************************************************
                        AUTHORIZED ACCESS ONLY
                     
This system is for authorized users only. All activity is monitored and logged.
Unauthorized access is prohibited and may result in criminal prosecution.
********************************************************************************
EOF

    # Test configuration
    sudo sshd -t || die "SSH configuration test failed"
    
    succ "SSH configuration hardened (port $SSH_PORT)"
}

configure_firewall() {
    log "Configuring UFW firewall"
    
    # Reset firewall
    sudo ufw --force reset > /dev/null
    
    # Set defaults
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw default deny forward
    
    # Essential services
    sudo ufw allow "$SSH_PORT/tcp" comment "SSH (hardened)"
    sudo ufw limit "$SSH_PORT/tcp"  # Rate limiting
    sudo ufw allow 80/tcp comment "HTTP"
    sudo ufw allow 443/tcp comment "HTTPS"
    
    # Optional: Allow from specific networks only
    # sudo ufw allow from 192.168.1.0/24 to any port $SSH_PORT
    
    # Enable firewall
    sudo ufw --force enable
    
    succ "Firewall configured and enabled"
}

setup_fail2ban() {
    log "Configuring fail2ban"
    
    # Main jail configuration
    cat <<EOF | sudo tee /etc/fail2ban/jail.local > /dev/null
[DEFAULT]
# Ban settings
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd

# Actions
banaction = ufw
action = %(action_mwl)s

# Ignore local networks (adjust as needed)
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

    sudo systemctl enable --now fail2ban
    
    succ "Fail2ban configured and started"
}

harden_kernel() {
    log "Applying kernel hardening"
    
    cat <<'EOF' | sudo tee /etc/sysctl.d/99-security-hardening.conf > /dev/null
# Network Security
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

# File System Security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

    # Apply settings
    sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf > /dev/null
    
    succ "Kernel security parameters applied"
}

setup_auditing() {
    log "Configuring system auditing"
    
    # Audit rules for security monitoring
    cat <<'EOF' | sudo tee /etc/audit/rules.d/99-security.rules > /dev/null
# Delete all previous rules
-D

# Buffer size
-b 8192

# Failure mode (0=silent 1=printk 2=panic)
-f 1

# Monitor important files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitor authentication
-w /var/log/auth.log -p wa -k auth
-w /var/log/lastlog -p wa -k logins

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Make rules immutable (require reboot to change)
-e 2
EOF

    # Load rules and start service
    sudo augenrules --load
    sudo systemctl enable --now auditd
    
    succ "Audit system configured"
}

setup_aide() {
    log "Initializing AIDE (file integrity monitoring)"
    
    # Initialize AIDE database (this takes time)
    sudo aideinit --yes --force &
    local aide_pid=$!
    
    # Show progress
    while kill -0 $aide_pid 2>/dev/null; do
        echo -n "."
        sleep 2
    done
    echo
    
    # Enable daily checks
    sudo systemctl enable aide-check.timer
    
    succ "AIDE initialized and scheduled"
}

configure_automatic_updates() {
    log "Configuring automatic security updates"
    
    cat <<'EOF' | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    cat <<'EOF' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    succ "Automatic security updates configured"
}

secure_docker() {
    log "Securing Docker installation"
    
    # Create docker group and add user
    sudo groupadd -f docker
    sudo usermod -aG docker "$NEW_USER"
    
    # Secure Docker daemon
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
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    }
}
EOF

    # Restart Docker with new config
    sudo systemctl restart docker
    sudo systemctl enable docker
    
    succ "Docker secured and configured"
}

final_verification() {
    log "Performing final security verification"
    
    # Test SSH configuration
    sudo sshd -t || die "SSH configuration test failed"
    
    # Check firewall status
    sudo ufw status | grep -q "Status: active" || die "Firewall not active"
    
    # Verify services
    local services=("ssh" "ufw" "fail2ban" "auditd" "docker")
    for service in "${services[@]}"; do
        sudo systemctl is-active --quiet "$service" || warn "Service $service not active"
    done
    
    # Check user creation
    id "$NEW_USER" &>/dev/null || die "Admin user not created properly"
    
    succ "Security verification completed"
}

test_ssh_access() {
    warn "=== CRITICAL: SSH ACCESS TEST ==="
    warn "SSH will restart on port $SSH_PORT"
    warn "Root and ubuntu accounts will be LOCKED after this point"
    echo
    warn "You MUST test SSH access before proceeding:"
    warn "1. Open a NEW terminal window"
    warn "2. Test: ssh $NEW_USER@\$(hostname -I | cut -d' ' -f1) -p $SSH_PORT"
    warn "3. Verify you can log in and run 'sudo -l'"
    echo
    
    local response
    while true; do
        read -rp "Have you successfully tested SSH access? (yes/no): " response
        case "${response,,}" in
            yes|y) break ;;
            no|n) die "Please test SSH access before continuing" ;;
            *) echo "Please answer 'yes' or 'no'" ;;
        esac
    done
    
    succ "SSH access confirmed by user"
}

restart_ssh() {
    log "Restarting SSH service"
    
    sudo systemctl restart sshd || die "Failed to restart SSH"
    sleep 2
    
    # Verify SSH is listening on new port
    if netstat -tuln | grep -q ":$SSH_PORT "; then
        succ "SSH restarted successfully on port $SSH_PORT"
    else
        die "SSH not listening on port $SSH_PORT"
    fi
}

lock_default_accounts() {
    log "Locking default accounts (final step)"
    
    # Lock ubuntu account
    if id ubuntu &>/dev/null; then
        sudo passwd -l ubuntu
        sudo usermod --expiredate 1970-01-01 ubuntu
        succ "Ubuntu account locked"
    fi
    
    # Lock root account  
    sudo passwd -l root
    sudo usermod --expiredate 1970-01-01 root
    succ "Root account locked"
    
    warn "Default accounts locked - use '$NEW_USER' for all access"
}

print_summary() {
    echo
    succ "=== HARDENING COMPLETE ==="
    echo "Version: $SCRIPT_VERSION"
    echo "Date: $(date)"
    echo "Log: $LOG"
    echo "Backup: $BACKUP_DIR"
    echo
    echo "Access Details:"
    echo "  User: $NEW_USER"
    echo "  SSH Port: $SSH_PORT"
    echo "  Command: ssh $NEW_USER@\$(hostname -I | cut -d' ' -f1) -p $SSH_PORT"
    echo
    echo "Security Features Enabled:"
    echo "  ✓ SSH hardened (Ed25519, key-only auth)"
    echo "  ✓ UFW firewall active"
    echo "  ✓ Fail2ban monitoring"
    echo "  ✓ Kernel hardening applied"
    echo "  ✓ Audit logging enabled"
    echo "  ✓ AIDE file integrity monitoring"
    echo "  ✓ Docker secured"
    echo "  ✓ Automatic security updates"
    echo "  ✓ Default accounts locked"
    echo
    warn "Reboot recommended to ensure all changes take effect"
    echo
}

# ---------- Main Execution ----------
main() {
    log "Starting Ubuntu $SCRIPT_VERSION hardening script"
    log "Target user: $NEW_USER | SSH port: $SSH_PORT"
    
    # Phase 1: Validation and preparation
    validate_prerequisites
    backup_configs
    
    # Phase 2: System updates and packages
    update_system
    install_packages
    
    # Phase 3: User and access management
    create_admin_user
    harden_ssh
    
    # Phase 4: Security configuration
    configure_firewall
    setup_fail2ban
    harden_kernel
    setup_auditing
    setup_aide
    configure_automatic_updates
    secure_docker
    
    # Phase 5: Verification and finalization
    final_verification
    test_ssh_access
    restart_ssh
    lock_default_accounts
    
    # Phase 6: Summary
    print_summary
}

# Execute main function
main "$@"
