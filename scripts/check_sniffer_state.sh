#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

SERIAL_PORT=""
OUTPUT_FORMAT="env"

usage() {
  cat <<USAGE
Usage: $0 [options]

Detect whether the connected sniffer is capture-capable for Wireshark/tshark.

Options:
  --serial-port PORT    Serial port to inspect (default: auto-detect)
  --format env|text     Output format (default: env)
  -h, --help            Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial-port)
      SERIAL_PORT="$2"
      shift 2
      ;;
    --format)
      OUTPUT_FORMAT="$2"
      shift 2
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
  local candidate
  for candidate in /dev/ttyUSB0 /dev/ttyACM0; do
    [[ -e "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
  done
  candidate="$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | head -n 1 || true)"
  [[ -n "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
  return 1
}

to_yesno() {
  if [[ "$1" -eq 1 ]]; then
    printf 'yes\n'
  else
    printf 'no\n'
  fi
}

main() {
  local port="$SERIAL_PORT"
  if [[ -z "$port" ]]; then
    port="$(auto_detect_serial_port || true)"
  fi

  local usb_present=0
  local wireshark_extcap_ready=0
  local sniffer_interface_visible=0
  local tshark_extcap_ready=0

  if [[ -n "$port" && -e "$port" ]]; then
    usb_present=1
  fi

  local extcap_py=""
  for candidate in \
    "$HOME/.local/lib/wireshark/extcap/nrf_sniffer_ble.py" \
    "/usr/lib/x86_64-linux-gnu/wireshark/extcap/nrf_sniffer_ble.py" \
    "/usr/lib/wireshark/extcap/nrf_sniffer_ble.py"; do
    if [[ -x "$candidate" ]]; then
      extcap_py="$candidate"
      break
    fi
  done

  if [[ -n "$extcap_py" ]]; then
    wireshark_extcap_ready=1
    local extcap_out
    extcap_out="$(python3 "$extcap_py" --extcap-interfaces 2>/dev/null || true)"
    if [[ -n "$port" ]] && printf '%s\n' "$extcap_out" | rg -q "interface \{value=${port}-"; then
      sniffer_interface_visible=1
    fi
  fi

  if have_cmd tshark; then
    local tshark_list
    tshark_list="$(tshark -D 2>/dev/null || true)"
    if printf '%s\n' "$tshark_list" | rg -qi 'nRF Sniffer for Bluetooth LE'; then
      tshark_extcap_ready=1
    fi
  fi

  local capture_ready=0
  if [[ $usb_present -eq 1 && $sniffer_interface_visible -eq 1 && $tshark_extcap_ready -eq 1 ]]; then
    capture_ready=1
  fi

  local firmware_state="unknown"
  if [[ $sniffer_interface_visible -eq 1 ]]; then
    firmware_state="capture-capable"
  elif [[ $usb_present -eq 1 ]]; then
    firmware_state="usb-present-but-not-capture-capable"
  else
    firmware_state="device-not-detected"
  fi

  if [[ "$OUTPUT_FORMAT" == "text" ]]; then
    echo "serial_port=${port:-none}"
    echo "usb_present=$(to_yesno "$usb_present")"
    echo "wireshark_extcap_ready=$(to_yesno "$wireshark_extcap_ready")"
    echo "tshark_extcap_ready=$(to_yesno "$tshark_extcap_ready")"
    echo "sniffer_interface_visible=$(to_yesno "$sniffer_interface_visible")"
    echo "capture_ready=$(to_yesno "$capture_ready")"
    echo "firmware_state=$firmware_state"
    return
  fi

  cat <<ENV
SERIAL_PORT=${port}
USB_PRESENT=$(to_yesno "$usb_present")
WIRESHARK_EXTCAP_READY=$(to_yesno "$wireshark_extcap_ready")
TSHARK_EXTCAP_READY=$(to_yesno "$tshark_extcap_ready")
SNIFFER_INTERFACE_VISIBLE=$(to_yesno "$sniffer_interface_visible")
CAPTURE_READY=$(to_yesno "$capture_ready")
FIRMWARE_STATE=${firmware_state}
ENV
}

main
