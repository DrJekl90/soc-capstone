#!/bin/bash
# Incident Response Log Collector
# Grabs key log files, system state, and network info from a Linux host
# and packages them into a timestamped tarball for offline analysis.
# Run as root for full coverage.

set -euo pipefail

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
HOSTNAME=$(hostname)
COLLECT_DIR="/tmp/ir-collect-${HOSTNAME}-${TIMESTAMP}"

mkdir -p "$COLLECT_DIR"/{logs,system,network,users,processes}

echo "=============================="
echo " IR Log Collector"
echo " Host: $HOSTNAME"
echo " Time: $TIMESTAMP"
echo " Output: $COLLECT_DIR"
echo "=============================="
echo ""

# --- System Info ---
echo "[1] Collecting system information..."
uname -a > "$COLLECT_DIR/system/uname.txt" 2>/dev/null
cat /etc/os-release > "$COLLECT_DIR/system/os-release.txt" 2>/dev/null || true
uptime > "$COLLECT_DIR/system/uptime.txt" 2>/dev/null
df -h > "$COLLECT_DIR/system/disk-usage.txt" 2>/dev/null
free -h > "$COLLECT_DIR/system/memory.txt" 2>/dev/null
last -50 > "$COLLECT_DIR/system/last-logins.txt" 2>/dev/null
lastb -20 > "$COLLECT_DIR/system/failed-logins.txt" 2>/dev/null || true

# --- User Info ---
echo "[2] Collecting user information..."
cp /etc/passwd "$COLLECT_DIR/users/passwd" 2>/dev/null
cp /etc/group "$COLLECT_DIR/users/group" 2>/dev/null
who > "$COLLECT_DIR/users/who.txt" 2>/dev/null
w > "$COLLECT_DIR/users/w.txt" 2>/dev/null
awk -F: '$3 == 0 {print}' /etc/passwd > "$COLLECT_DIR/users/uid-zero.txt" 2>/dev/null
awk -F: '$2 == "" {print $1}' /etc/shadow > "$COLLECT_DIR/users/no-password.txt" 2>/dev/null || true

# --- Process Info ---
echo "[3] Collecting process information..."
ps auxwwf > "$COLLECT_DIR/processes/ps-full.txt" 2>/dev/null
ps -eo pid,ppid,user,%cpu,%mem,stat,start,args --sort=-%cpu > "$COLLECT_DIR/processes/ps-sorted.txt" 2>/dev/null

# --- Network Info ---
echo "[4] Collecting network information..."
ip addr show > "$COLLECT_DIR/network/ip-addr.txt" 2>/dev/null || ifconfig -a > "$COLLECT_DIR/network/ifconfig.txt" 2>/dev/null
ss -tlnp > "$COLLECT_DIR/network/listening-tcp.txt" 2>/dev/null
ss -ulnp > "$COLLECT_DIR/network/listening-udp.txt" 2>/dev/null
ss -anp > "$COLLECT_DIR/network/all-connections.txt" 2>/dev/null
ip route show > "$COLLECT_DIR/network/routes.txt" 2>/dev/null
iptables -L -n -v > "$COLLECT_DIR/network/iptables.txt" 2>/dev/null || true
cat /etc/resolv.conf > "$COLLECT_DIR/network/resolv.conf" 2>/dev/null

# --- Log Files ---
echo "[5] Collecting log files..."
log_files=(
    "/var/log/auth.log"
    "/var/log/secure"
    "/var/log/syslog"
    "/var/log/messages"
    "/var/log/kern.log"
    "/var/log/cron"
    "/var/log/audit/audit.log"
    "/var/log/wtmp"
    "/var/log/btmp"
)

for logfile in "${log_files[@]}"; do
    if [ -f "$logfile" ]; then
        # Grab last 10k lines to keep the package manageable
        tail -10000 "$logfile" > "$COLLECT_DIR/logs/$(basename "$logfile")" 2>/dev/null
        echo "  Collected: $logfile"
    fi
done

# --- Cron Jobs ---
echo "[6] Collecting scheduled tasks..."
crontab -l > "$COLLECT_DIR/system/crontab-root.txt" 2>/dev/null || true
ls -la /etc/cron.d/ > "$COLLECT_DIR/system/cron-d-listing.txt" 2>/dev/null || true
cat /etc/crontab > "$COLLECT_DIR/system/etc-crontab.txt" 2>/dev/null || true

# --- Package into tarball ---
echo ""
echo "[7] Packaging..."
TARBALL="/tmp/ir-collect-${HOSTNAME}-${TIMESTAMP}.tar.gz"
tar -czf "$TARBALL" -C /tmp "ir-collect-${HOSTNAME}-${TIMESTAMP}" 2>/dev/null

# Clean up the temp directory
rm -rf "$COLLECT_DIR"

SIZE=$(du -sh "$TARBALL" | awk '{print $1}')
echo ""
echo "=============================="
echo " Collection complete"
echo " Archive: $TARBALL"
echo " Size: $SIZE"
echo "=============================="
