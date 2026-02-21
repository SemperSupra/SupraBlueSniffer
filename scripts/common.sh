#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

warn() {
  printf '[%s] WARN: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

err() {
  printf '[%s] ERROR: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
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
