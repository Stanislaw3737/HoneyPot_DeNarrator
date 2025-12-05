#!/usr/bin/env bash
# DeNarrator bash honeypot (Linux-flavoured)
#
# This is designed to be run on a Linux system (or WSL) with bash.
# It does NOT hook the global shell; instead, you start a wrapped
# shell session that returns fake data for common recon commands.

set -o errexit
set -o pipefail
set -o nounset

BASE_DIR="$(cd ""$(dirname "${BASH_SOURCE[0]}")"" && pwd)"
LOGS_DIR="$BASE_DIR/logs"
KEY_FILE="$BASE_DIR/key.txt"
FAKE_LOG="$LOGS_DIR/fake_system.log"

ACTIVE=0
LOG_PID=""

# --- fake identity ---
FAKE_HOSTNAME="lab-gateway-01"
FAKE_USER="svc_backup"
FAKE_DOMAIN="lab-segment"
FAKE_DISTRO="Ubuntu 20.04.6 LTS"
FAKE_KERNEL="5.4.0-148-generic"
FAKE_ARCH="x86_64"
FAKE_IP="10.13.37.42"
FAKE_MAC="00:15:5d:ab:cd:ef"
FAKE_UPTIME_DAYS=19
FAKE_TOTAL_MEM_MB=16054
FAKE_FREE_MEM_MB=2341

# --- key handling ---
load_or_create_key() {
  if [[ ! -f "$KEY_FILE" ]]; then
    mkdir -p "$BASE_DIR"
    # 32-hex char key
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$KEY_FILE"
  fi
  tr -d '\n' <"$KEY_FILE"
}

# --- log generation ---
log_worker() {
  mkdir -p "$LOGS_DIR"
  if [[ ! -f "$FAKE_LOG" ]]; then
    printf '\n=== DeNarrator fake system log started: %s ===\n' "$(date -Iseconds)" >>"$FAKE_LOG"
  fi
  while true; do
    case $((RANDOM % 8)) in
      0) EVENT="INFO  backupd       Completed incremental backup to nas-01" ;;
      1) EVENT="WARN  smartd        High latency detected on /dev/sdb" ;;
      2) EVENT="INFO  systemd       Started Daily apt upgrade and clean activities" ;;
      3) EVENT="WARN  sshd          Failed password for invalid user temp_admin from 203.0.113.45 port 58214 ssh2" ;;
      4) EVENT="INFO  cron          (svc_backup) CMD (/usr/local/bin/archive-job 4921)" ;;
      5) EVENT="WARN  kernel        eth0: transmit queue 0 timed out" ;;
      6) EVENT="INFO  unattended-upgrades  Packages were kept back because of held packages" ;;
      7) EVENT="WARN  apparmor      profile 'usr.sbin.smbd' skipped update (not in enforce mode)" ;;
    esac
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$EVENT" >>"$FAKE_LOG"
    sleep $((20 + RANDOM % 40))
  done
}

start_logs() {
  if [[ -n "$LOG_PID" ]] && kill -0 "$LOG_PID" 2>/dev/null; then
    return
  fi
  mkdir -p "$LOGS_DIR"
  log_worker &
  LOG_PID=$!
}

stop_logs() {
  if [[ -n "$LOG_PID" ]] && kill -0 "$LOG_PID" 2>/dev/null; then
    kill "$LOG_PID" 2>/dev/null || true
    wait "$LOG_PID" 2>/dev/null || true
  fi
  LOG_PID=""
}

# --- fake outputs ---
fake_uname() {
  case "$1" in
    -a)
      printf 'Linux %s %s %s GNU/Linux\n' "$FAKE_HOSTNAME" "$FAKE_KERNEL" "$FAKE_ARCH" ;;
    -r)
      printf '%s\n' "$FAKE_KERNEL" ;;
    -n)
      printf '%s\n' "$FAKE_HOSTNAME" ;;
    -m)
      printf '%s\n' "$FAKE_ARCH" ;;
    *)
      printf 'Linux\n' ;;
  esac
}

fake_hostname() {
  printf '%s\n' "$FAKE_HOSTNAME"
}

fake_whoami() {
  printf '%s\n' "$FAKE_USER"
}

fake_ip_a() {
  cat <<EOF
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether $FAKE_MAC brd ff:ff:ff:ff:ff:ff
    inet $FAKE_IP/24 brd 10.13.37.255 scope global eth0
       valid_lft forever preferred_lft forever
EOF
}

fake_etc_os_release() {
  cat <<EOF
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="$FAKE_DISTRO"
VERSION_ID="20.04"
EOF
}

fake_uptime() {
  printf ' %02d:%02d:%02d up %d days,  2:17,  1 user,  load average: 0.06, 0.03, 0.01\n' \
    "$((RANDOM % 24))" "$((RANDOM % 60))" "$((RANDOM % 60))" "$FAKE_UPTIME_DAYS"
}

fake_free_h() {
  cat <<EOF
              total        used        free      shared  buff/cache   available
Mem:        ${FAKE_TOTAL_MEM_MB}M     $((FAKE_TOTAL_MEM_MB-FAKE_FREE_MEM_MB-1024))M      ${FAKE_FREE_MEM_MB}M        120M       1300M     $((FAKE_FREE_MEM_MB+900))M
Swap:       2047M        128M       1919M
EOF
}

fake_logs_tail() {
  local n=${1:-40}
  if [[ ! -f "$FAKE_LOG" ]]; then
    printf '(no events)\n'
    return
  fi
  tail -n "$n" "$FAKE_LOG"
}

# --- interactive shell ---
wrapped_shell() {
  start_logs
  echo "[DeNarrator] Linux honeypot shell. Type 'help' for commands, 'exit' to quit." >&2
  while true; do
    read -rp "denarrator> " line || { echo; break; }

    [[ -z "$line" ]] && continue

    case "$line" in
      exit|quit)
        break
        ;;
      help)
        cat <<EOF
Available commands:
  uname [-a|-r|-n|-m]  - fake kernel/system info
  hostname             - fake hostname
  whoami               - fake user
  ip a                 - fake interface/IP output
  cat /etc/os-release  - fake distro info
  uptime               - fake uptime
  free -h              - fake memory usage
  logs                 - show tail of fake logs
  real <command>       - run a real command (use with care)
  exit / quit          - leave this shell
EOF
        ;;
      uname*)
        fake_uname ${line#uname}
        ;;
      hostname)
        fake_hostname
        ;;
      whoami)
        fake_whoami
        ;;
      "ip a"|"ip addr"|"ip address")
        fake_ip_a
        ;;
      "cat /etc/os-release")
        fake_etc_os_release
        ;;
      uptime)
        fake_uptime
        ;;
      "free -h")
        fake_free_h
        ;;
      logs)
        fake_logs_tail 40
        ;;
      real\ *)
        local real_cmd=${line#real }
        if [[ -z "$real_cmd" ]]; then
          echo "Usage: real <command>" >&2
        else
          bash -c "$real_cmd"
        fi
        ;;
      *)
        echo "Command not recognized or not supported in this environment." >&2
        ;;
    esac
  done
  stop_logs
  echo "[DeNarrator] Shell terminated." >&2
}

use_key() {
  local key_in="$1"; shift
  local disable="$1"
  local real_key
  real_key="$(load_or_create_key)"

  if [[ "$key_in" != "$real_key" ]]; then
    echo "[DeNarrator] Invalid key." >&2
    return 1
  fi

  if [[ "$disable" == "1" ]]; then
    if [[ "$ACTIVE" -eq 1 ]]; then
      stop_logs
      ACTIVE=0
      echo "[DeNarrator] Honeypot deactivated." >&2
    else
      echo "[DeNarrator] Honeypot already inactive." >&2
    fi
  else
    if [[ "$ACTIVE" -eq 0 ]]; then
      start_logs
      ACTIVE=1
      echo "[DeNarrator] Honeypot activated (background logs running). Use wrapped shell to interact." >&2
    else
      echo "[DeNarrator] Honeypot already active." >&2
    fi
  fi
}

# --- CLI ---
show_usage() {
  cat <<EOF
Usage: $0 [--shell] [--activate --key KEY] [--deactivate --key KEY]

  --shell              Start the DeNarrator wrapped shell (default if no args).
  --activate --key K   Start background fake log generation (key required).
  --deactivate --key K Stop background fake log generation (key required).
EOF
}

main() {
  local shell_mode=0
  local activate=0
  local deactivate=0
  local key=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --shell)
        shell_mode=1; shift ;;
      --activate)
        activate=1; shift ;;
      --deactivate)
        deactivate=1; shift ;;
      --key)
        key=${2:-}; shift 2 ;;
      -h|--help)
        show_usage; exit 0 ;;
      *)
        echo "Unknown argument: $1" >&2
        show_usage; exit 1 ;;
    esac
  done

  if [[ $activate -eq 1 || $deactivate -eq 1 ]]; then
    if [[ -z "$key" ]]; then
      echo "[DeNarrator] --key is required for activate/deactivate." >&2
      exit 1
    fi
    local disable=0
    [[ $deactivate -eq 1 ]] && disable=1
    use_key "$key" "$disable"
    exit $?
  fi

  # default behavior: shell
  if [[ $shell_mode -eq 1 || ( $activate -eq 0 && $deactivate -eq 0 ) ]]; then
    # force key creation for parity with other implementations
    load_or_create_key >/dev/null 2>&1 || true
    wrapped_shell
  fi
}

main "$@"
