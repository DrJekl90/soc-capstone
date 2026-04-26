#!/bin/bash
# Suspicious Process Monitor
# Snapshots the current process list and flags anything running from
# writable directories, processes with deleted binaries, or known
# suspicious parent-child relationships. Meant for quick host triage.

set -euo pipefail

echo "=============================="
echo " Process Monitor Snapshot"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo " Host: $(hostname)"
echo "=============================="
echo ""

SUSPICIOUS_DIRS=("/tmp" "/var/tmp" "/dev/shm" "/run/user")
ALERT_COUNT=0

flag() {
    echo "  [!] $1"
    ((ALERT_COUNT++))
}

# --- Processes running from writable directories ---
echo "[1] Processes in Writable Directories"
found=0
while IFS= read -r line; do
    pid=$(echo "$line" | awk '{print $1}')
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")

    for dir in "${SUSPICIOUS_DIRS[@]}"; do
        if [[ "$exe" == "$dir"* ]]; then
            user=$(ps -o user= -p "$pid" 2>/dev/null || echo "?")
            cmd=$(ps -o args= -p "$pid" 2>/dev/null | head -c 120 || echo "?")
            flag "PID $pid | User: $user | Path: $exe"
            echo "      Cmd: $cmd"
            found=1
        fi
    done
done < <(ps -eo pid= 2>/dev/null)

if [ "$found" -eq 0 ]; then
    echo "  [OK] None found"
fi
echo ""

# --- Processes with deleted binaries ---
echo "[2] Processes with Deleted Binaries"
found=0
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    exe_link=$(readlink "$pid_dir/exe" 2>/dev/null || continue)

    if [[ "$exe_link" == *"(deleted)"* ]]; then
        user=$(ps -o user= -p "$pid" 2>/dev/null || echo "?")
        cmd=$(ps -o args= -p "$pid" 2>/dev/null | head -c 120 || echo "?")
        flag "PID $pid | User: $user | Deleted binary: $exe_link"
        echo "      Cmd: $cmd"
        found=1
    fi
done

if [ "$found" -eq 0 ]; then
    echo "  [OK] None found"
fi
echo ""

# --- Processes listening on unexpected ports ---
echo "[3] Listening Processes (non-standard ports)"
expected_ports="22 53 80 443 8080"
while IFS= read -r line; do
    port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    proto=$(echo "$line" | awk '{print $1}')
    pid_prog=$(echo "$line" | awk '{print $NF}')

    if ! echo "$expected_ports" | grep -qw "$port"; then
        flag "Port $port ($proto) - $pid_prog"
    fi
done < <(ss -tlnp 2>/dev/null | tail -n +2)
echo ""

# --- High CPU processes ---
echo "[4] Top 5 CPU Consumers"
ps aux --sort=-%cpu 2>/dev/null | head -6 | tail -5 | while IFS= read -r line; do
    cpu=$(echo "$line" | awk '{print $3}')
    user=$(echo "$line" | awk '{print $1}')
    cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ",$i; print ""}' | head -c 80)
    echo "  $cpu% | $user | $cmd"
done
echo ""

# --- Summary ---
echo "=============================="
if [ "$ALERT_COUNT" -gt 0 ]; then
    echo "  $ALERT_COUNT suspicious finding(s) - investigate further."
else
    echo "  No suspicious processes detected."
fi
echo "=============================="
