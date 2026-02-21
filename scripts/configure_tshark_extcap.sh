#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Configure tshark to see nRF Sniffer extcap by syncing personal extcap into global extcap.
Idempotent: no changes if tshark already lists nRF Sniffer.

Options:
  --log-level LEVEL   Set shell log level: NONE, ERROR, WARN, INFO, DEBUG
  --quiet             Equivalent to error-only logs
  -h, --help          Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log-level)
      BLUESNIFFER_LOG_LEVEL="$2"
      export BLUESNIFFER_LOG_LEVEL
      shift 2
      ;;
    --quiet)
      BLUESNIFFER_QUIET=1
      export BLUESNIFFER_QUIET
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
done

require_not_root
require_sudo

personal_extcap="$(wireshark_personal_extcap_dir)"
if [[ ! -d "$personal_extcap" ]]; then
  err "Personal extcap directory not found: $personal_extcap"
  exit 1
fi
if [[ ! -f "$personal_extcap/nrf_sniffer_ble.py" ]]; then
  err "nrf_sniffer_ble.py not found in $personal_extcap"
  exit 1
fi

if tshark -D 2>/dev/null | rg -qi 'nRF Sniffer for Bluetooth LE'; then
  log "tshark already sees nRF Sniffer extcap"
  exit 0
fi

global_extcap="/usr/lib/x86_64-linux-gnu/wireshark/extcap"
if [[ ! -d "$global_extcap" ]]; then
  if [[ -d "/usr/lib/wireshark/extcap" ]]; then
    global_extcap="/usr/lib/wireshark/extcap"
  else
    sudo mkdir -p "$global_extcap"
  fi
fi

log "Syncing extcap from $personal_extcap to $global_extcap"
if have_cmd rsync; then
  sudo rsync -a "$personal_extcap/" "$global_extcap/"
else
  sudo cp -a "$personal_extcap"/. "$global_extcap"/
fi
sudo chmod +x "$global_extcap/nrf_sniffer_ble.py"

if tshark -D 2>/dev/null | rg -qi 'nRF Sniffer for Bluetooth LE'; then
  log "tshark extcap configuration complete"
  exit 0
fi

warn "tshark still does not list nRF Sniffer extcap after sync"
exit 1
