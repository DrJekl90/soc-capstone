#!/bin/bash
# Linux Hardening Checker
# Runs a quick sweep of common security misconfigurations on a Linux host.
# No changes are made. Output goes to stdout and an optional report file.

set -euo pipefail

REPORT=""
PASS=0
WARN=0
FAIL=0

log_pass() { echo -e "  [PASS] $1"; ((PASS++)); }
log_warn() { echo -e "  [WARN] $1"; ((WARN++)); }
log_fail() { echo -e "  [FAIL] $1"; ((FAIL++)); }

echo "=============================="
echo " Linux Hardening Check"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo " Host: $(hostname)"
echo "=============================="
echo ""

# --- SSH Configuration ---
echo "[1] SSH Configuration"
SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    if grep -qi "^PermitRootLogin\s*no" "$SSHD_CONFIG" 2>/dev/null; then
        log_pass "Root login disabled"
    else
        log_fail "Root login may be permitted - check PermitRootLogin"
    fi

    if grep -qi "^PasswordAuthentication\s*no" "$SSHD_CONFIG" 2>/dev/null; then
        log_pass "Password authentication disabled (key-only)"
    else
        log_warn "Password authentication may be enabled"
    fi

    if grep -qi "^Protocol\s*2" "$SSHD_CONFIG" 2>/dev/null || ! grep -qi "^Protocol\s*1" "$SSHD_CONFIG" 2>/dev/null; then
        log_pass "SSH protocol 2 (default on modern systems)"
    else
        log_fail "SSH protocol 1 may be enabled"
    fi
else
    log_warn "sshd_config not found at $SSHD_CONFIG"
fi
echo ""

# --- File Permissions ---
echo "[2] Critical File Permissions"

check_perms() {
    local file=$1
    local expected=$2
    local desc=$3

    if [ -f "$file" ]; then
        actual=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null)
        if [ "$actual" = "$expected" ]; then
            log_pass "$desc ($file: $actual)"
        else
            log_fail "$desc ($file: $actual, expected $expected)"
        fi
    fi
}

check_perms "/etc/passwd" "644" "passwd permissions"
check_perms "/etc/shadow" "640" "shadow permissions"
check_perms "/etc/group" "644" "group permissions"
check_perms "/etc/gshadow" "640" "gshadow permissions"
echo ""

# --- SUID/SGID Binaries ---
echo "[3] SUID/SGID Binaries in Writable Directories"
suid_writable=$(find /tmp /var/tmp /dev/shm -perm -4000 -o -perm -2000 2>/dev/null | head -20)

if [ -z "$suid_writable" ]; then
    log_pass "No SUID/SGID binaries in /tmp, /var/tmp, /dev/shm"
else
    log_fail "SUID/SGID binaries found in writable directories:"
    echo "$suid_writable" | while read -r f; do echo "    $f"; done
fi
echo ""

# --- Unattended Upgrades ---
echo "[4] Automatic Security Updates"
if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    log_pass "unattended-upgrades package installed (Debian/Ubuntu)"
elif systemctl is-active --quiet dnf-automatic.timer 2>/dev/null; then
    log_pass "dnf-automatic timer active (RHEL/Fedora)"
else
    log_warn "No automatic update mechanism detected"
fi
echo ""

# --- Firewall ---
echo "[5] Firewall Status"
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi "active"; then
    log_pass "UFW firewall is active"
elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -qi "running"; then
    log_pass "firewalld is running"
elif iptables -L -n 2>/dev/null | grep -q "Chain INPUT"; then
    rules=$(iptables -L -n 2>/dev/null | grep -c "^[A-Z]")
    if [ "$rules" -gt 3 ]; then
        log_pass "iptables has active rules ($rules chains)"
    else
        log_warn "iptables loaded but rules may be too permissive"
    fi
else
    log_fail "No active firewall detected"
fi
echo ""

# --- Users with UID 0 ---
echo "[6] Users with UID 0 (root-equivalent)"
uid_zero=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
uid_zero_count=$(echo "$uid_zero" | wc -w)

if [ "$uid_zero_count" -eq 1 ] && echo "$uid_zero" | grep -q "root"; then
    log_pass "Only root has UID 0"
else
    log_fail "Multiple accounts with UID 0: $uid_zero"
fi
echo ""

# --- World-Writable Files ---
echo "[7] World-Writable Files (outside /tmp and /proc)"
ww_count=$(find / -xdev -type f -perm -0002 \
    -not -path "/tmp/*" \
    -not -path "/var/tmp/*" \
    -not -path "/proc/*" \
    -not -path "/sys/*" \
    2>/dev/null | wc -l)

if [ "$ww_count" -eq 0 ]; then
    log_pass "No world-writable files found"
elif [ "$ww_count" -le 5 ]; then
    log_warn "$ww_count world-writable file(s) found"
else
    log_fail "$ww_count world-writable files found - review needed"
fi
echo ""

# --- Cron Jobs ---
echo "[8] Cron Jobs for Non-Root Users"
cron_users=0
for user_dir in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    if [ -f "$user_dir" ] && [ "$(basename "$user_dir")" != "root" ]; then
        ((cron_users++))
        log_warn "Cron jobs found for: $(basename "$user_dir")"
    fi
done 2>/dev/null
if [ "$cron_users" -eq 0 ]; then
    log_pass "No non-root user cron jobs found"
fi
echo ""

# --- Summary ---
echo "=============================="
echo " Summary"
echo "=============================="
echo "  Passed:   $PASS"
echo "  Warnings: $WARN"
echo "  Failed:   $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "  Action needed - $FAIL finding(s) require remediation."
    exit 1
else
    echo "  No critical findings."
    exit 0
fi
