#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

log_level_to_num() {
  case "${1^^}" in
    NONE) printf '0\n' ;;
    ERROR) printf '1\n' ;;
    WARN|WARNING) printf '2\n' ;;
    INFO) printf '3\n' ;;
    DEBUG) printf '4\n' ;;
    *) printf '3\n' ;;
  esac
}

current_log_level_num() {
  local level="${BLUESNIFFER_LOG_LEVEL:-INFO}"
  if [[ "${BLUESNIFFER_QUIET:-0}" == "1" ]]; then
    level="ERROR"
  fi
  log_level_to_num "$level"
}

should_log() {
  local msg_level="$1"
  local current_num
  local msg_num
  current_num="$(current_log_level_num)"
  msg_num="$(log_level_to_num "$msg_level")"
  [[ "$current_num" -ge "$msg_num" ]]
}

log() {
  if should_log INFO; then
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
  fi
}

debug() {
  if should_log DEBUG; then
    printf '[%s] DEBUG: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
  fi
}

warn() {
  if should_log WARN; then
    printf '[%s] WARN: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
  fi
}

err() {
  if should_log ERROR; then
    printf '[%s] ERROR: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_ubuntu_like() {
  [[ -f /etc/os-release ]] && grep -Eq '^ID(_LIKE)?=.*(ubuntu|debian)' /etc/os-release
}

is_package_installed() {
  local pkg="$1"
  dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q 'install ok installed'
}

in_group() {
  local grp="$1"
  id -nG "$USER" | tr ' ' '\n' | grep -qx "$grp"
}

require_not_root() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    err "Do not run as root. Run as your normal user; sudo is used internally."
    exit 1
  fi
}

require_sudo() {
  if sudo -n true >/dev/null 2>&1; then
    return
  fi

  log "Sudo permission check requires a password prompt."
  if ! sudo -v; then
    err "Sudo access is required for package/group setup but is not available."
    exit 1
  fi
}

wireshark_personal_extcap_dir() {
  if have_cmd wireshark; then
    local dir
    dir="$(wireshark -G folders 2>/dev/null | awk -F': ' '/Personal extcap path/{print $2; exit}')"
    if [[ -n "$dir" ]]; then
      printf '%s\n' "$dir"
      return
    fi
  fi
  printf '%s\n' "$HOME/.local/lib/wireshark/extcap"
}

print_section() {
  printf '\n== %s ==\n' "$1"
}

first_serial_port() {
  local candidate
  local ports=()
  shopt -s nullglob
  for candidate in /dev/ttyUSB* /dev/ttyACM*; do
    ports+=("$candidate")
  done
  shopt -u nullglob
  if [[ ${#ports[@]} -gt 0 ]]; then
    printf '%s\n' "${ports[0]}"
    return 0
  fi
  return 1
}
