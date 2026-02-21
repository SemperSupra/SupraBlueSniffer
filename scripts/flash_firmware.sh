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

Automatically flash selected sniffer firmware when needed.

Options:
  --firmware-hex PATH    Firmware hex file (default: ~/.local/share/bluesniffer/firmware/current.hex)
  --serial-port PORT     Sniffer serial port (default: auto-detect or last_port.txt)
  --force                Flash even if sniffer appears operational
  --best-effort          Do not fail if no supported flashing backend is available
  --log-level LEVEL      Set shell log level: NONE, ERROR, WARN, INFO, DEBUG
  --quiet                Equivalent to error-only logs
  -h, --help             Show help
USAGE
}

FIRMWARE_HEX="${HOME}/.local/share/bluesniffer/firmware/current.hex"
SERIAL_PORT=""
FORCE=0
BEST_EFFORT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --firmware-hex)
      FIRMWARE_HEX="$2"
      shift 2
      ;;
    --serial-port)
      SERIAL_PORT="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --best-effort)
      BEST_EFFORT=1
      shift
      ;;
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

auto_detect_serial_port() {
  local cache="${HOME}/.local/share/bluesniffer/firmware/last_port.txt"
  if [[ -z "$SERIAL_PORT" && -f "$cache" ]]; then
    local cached
    cached="$(cat "$cache")"
    if [[ -n "$cached" && -e "$cached" ]]; then
      printf '%s\n' "$cached"
      return 0
    fi
  fi

  first_serial_port
}

sniffer_operational() {
  local port="$1"
  local line
  local firmware_state=""
  local state
  state="$("$SCRIPT_DIR/check_sniffer_state.sh" --serial-port "$port" 2>/dev/null || true)"
  if [[ -z "$state" ]]; then
    return 1
  fi
  while IFS= read -r line; do
    case "$line" in
      FIRMWARE_STATE=*)
        firmware_state="${line#FIRMWARE_STATE=}"
        ;;
    esac
  done <<< "$state"
  [[ "$firmware_state" == "capture-capable" ]]
}

flash_with_nrfjprog() {
  local hex="$1"
  local ids
  ids="$(nrfjprog --ids 2>/dev/null || true)"
  if [[ -z "$ids" ]]; then
    return 1
  fi

  local snr
  snr="$(printf '%s\n' "$ids" | head -n 1)"
  log "Flashing with nrfjprog on probe SNR $snr"
  nrfjprog --snr "$snr" --eraseall
  nrfjprog --snr "$snr" --program "$hex" --verify
  nrfjprog --snr "$snr" --reset
  return 0
}

flash_with_pyocd() {
  local hex="$1"
  if ! have_cmd pyocd; then
    return 1
  fi

  log "Flashing with pyOCD (target nrf51)"
  pyocd flash "$hex" --target nrf51
}

main() {
  local port="$SERIAL_PORT"
  if [[ -z "$port" ]]; then
    port="$(auto_detect_serial_port || true)"
  fi

  if [[ ! -L "$FIRMWARE_HEX" && ! -f "$FIRMWARE_HEX" ]]; then
    err "Firmware hex not found: $FIRMWARE_HEX"
    exit 1
  fi

  local resolved_hex
  resolved_hex="$(readlink -f "$FIRMWARE_HEX" 2>/dev/null || echo "$FIRMWARE_HEX")"
  log "Firmware selected for flash: $resolved_hex"

  if [[ -n "$port" && $FORCE -eq 0 ]]; then
    if sniffer_operational "$port"; then
      log "Sniffer already operational on $port; skipping flash (idempotent)"
      exit 0
    fi
    log "Sniffer not responding on $port; flashing will be attempted"
  fi

  if flash_with_nrfjprog "$resolved_hex"; then
    log "Firmware flash completed via nrfjprog"
    exit 0
  fi

  if flash_with_pyocd "$resolved_hex"; then
    log "Firmware flash completed via pyOCD"
    exit 0
  fi

  if [[ $BEST_EFFORT -eq 1 ]]; then
    warn "No supported flashing backend found (nrfjprog/pyocd). Skipping flash."
    return 0
  fi

  err "No supported flashing backend found. Install nrfjprog (preferred) or pyocd."
  err "Automatic flashing requires a SWD debug probe connected to the target nRF device."
  return 1
}

main "$@"
