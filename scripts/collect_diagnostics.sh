#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

OUT_DIR="${1:-diagnostics}"
mkdir -p "$OUT_DIR"
TS="$(date '+%Y%m%d_%H%M%S')"
REPORT="$OUT_DIR/host-diagnostics-$TS.txt"

collect_usb_serial_details() {
  local tty
  shopt -s nullglob
  for tty in /dev/ttyUSB* /dev/ttyACM*; do
    echo "- device: $tty"
    local base
    base="$(basename "$tty")"
    if [[ -d "/sys/class/tty/$base/device" ]]; then
      local dev_dir
      dev_dir="$(readlink -f "/sys/class/tty/$base/device")"
      local vendor product manufacturer product_name serial
      vendor="$(cat "$dev_dir/idVendor" 2>/dev/null || true)"
      product="$(cat "$dev_dir/idProduct" 2>/dev/null || true)"
      manufacturer="$(cat "$dev_dir/manufacturer" 2>/dev/null || true)"
      product_name="$(cat "$dev_dir/product" 2>/dev/null || true)"
      serial="$(cat "$dev_dir/serial" 2>/dev/null || true)"
      [[ -n "$vendor" ]] && echo "  idVendor: $vendor"
      [[ -n "$product" ]] && echo "  idProduct: $product"
      [[ -n "$manufacturer" ]] && echo "  manufacturer: $manufacturer"
      [[ -n "$product_name" ]] && echo "  product: $product_name"
      [[ -n "$serial" ]] && echo "  serial: $serial"
    fi
  done
  shopt -u nullglob
}

{
  echo "BlueSniffer Host Diagnostics"
  echo "Generated: $(date --iso-8601=seconds)"

  print_section "Host"
  uname -a
  if [[ -f /etc/os-release ]]; then
    echo "os-release:"
    sed 's/^/  /' /etc/os-release
  fi

  print_section "User & Permissions"
  echo "user: $USER"
  id
  echo "groups: $(id -nG)"
  for group in dialout wireshark; do
    if in_group "$group"; then
      echo "group:$group=present"
    else
      echo "group:$group=missing"
    fi
  done

  print_section "Packages"
  for pkg in wireshark python3 python3-pip python3-serial usbutils unzip curl; do
    if is_package_installed "$pkg"; then
      echo "$pkg: installed"
    else
      echo "$pkg: missing"
    fi
  done

  print_section "Commands"
  for cmd in wireshark tshark python3 pip3 lsusb udevadm nrfjprog pyocd; do
    if have_cmd "$cmd"; then
      echo "$cmd: $(command -v "$cmd")"
    else
      echo "$cmd: missing"
    fi
  done

  print_section "USB Serial Devices"
  if ls /dev/ttyUSB* /dev/ttyACM* >/dev/null 2>&1; then
    ls -l /dev/ttyUSB* /dev/ttyACM* 2>/dev/null
    collect_usb_serial_details
  else
    echo "No /dev/ttyUSB* or /dev/ttyACM* devices found"
  fi

  print_section "lsusb"
  if have_cmd lsusb; then
    lsusb || echo "lsusb failed in this environment"
  else
    echo "lsusb not installed"
  fi

  print_section "brltty"
  if is_package_installed brltty; then
    echo "package: installed"
  else
    echo "package: not installed"
  fi
  systemctl is-enabled brltty.service 2>/dev/null || true
  systemctl is-active brltty.service 2>/dev/null || true

  print_section "Wireshark Extcap"
  EXTCAP_DIR="$(wireshark_personal_extcap_dir)"
  echo "personal_extcap_dir: $EXTCAP_DIR"
  if [[ -d "$EXTCAP_DIR" ]]; then
    ls -la "$EXTCAP_DIR"
    if [[ -x "$EXTCAP_DIR/nrf_sniffer_ble.py" ]]; then
      echo "nrf_sniffer_ble.py: executable"
      python3 "$EXTCAP_DIR/nrf_sniffer_ble.py" --extcap-interfaces 2>&1 || true
    elif [[ -f "$EXTCAP_DIR/nrf_sniffer_ble.py" ]]; then
      echo "nrf_sniffer_ble.py: present but not executable"
    else
      echo "nrf_sniffer_ble.py: missing"
    fi
    if [[ -f "$EXTCAP_DIR/requirements.txt" ]]; then
      echo "requirements.txt: present"
      sed 's/^/  req: /' "$EXTCAP_DIR/requirements.txt"
    fi
  else
    echo "extcap directory missing"
  fi

  print_section "tshark Interfaces"
  if have_cmd tshark; then
    tshark -D 2>/dev/null | sed 's/^/  /' || true
  else
    echo "tshark not installed"
  fi

  print_section "Local Firmware Cache"
  for fw_root in "$HOME/.local/share/bluesniffer/firmware" "$PWD/state/firmware"; do
    if [[ -d "$fw_root" ]]; then
      echo "firmware_root: $fw_root"
      find "$fw_root" -maxdepth 3 -type f | sed 's/^/  /'
      if [[ -L "$fw_root/current.hex" ]]; then
        echo "current.hex -> $(readlink -f "$fw_root/current.hex")"
      fi
    fi
  done

  print_section "Flashing Capability"
  if have_cmd nrfjprog; then
    echo "nrfjprog_ids:"
    nrfjprog --ids 2>&1 | sed 's/^/  /' || true
  else
    echo "nrfjprog: unavailable"
  fi
  if have_cmd pyocd; then
    echo "pyocd_probes:"
    pyocd list 2>&1 | sed 's/^/  /' || true
  else
    echo "pyocd: unavailable"
  fi

  print_section "Sniffer Readiness"
  if [[ -x "$SCRIPT_DIR/check_sniffer_state.sh" ]]; then
    "$SCRIPT_DIR/check_sniffer_state.sh" --format text | sed 's/^/  /'
  else
    echo "check_sniffer_state.sh missing"
  fi
} | tee "$REPORT"

log "Diagnostics report written to $REPORT"
