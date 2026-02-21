#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Idempotent host bootstrap for Adafruit/nRF BLE sniffer workflows.

Options:
  --extcap-zip PATH        Install extcap files from a local zip
  --extcap-url URL         Download zip from URL and install extcap files
  --try-known-urls         Try known Nordic release URLs if extcap is missing
  --flash-firmware         Attempt firmware flash via nrf_sniffer_ble.py --flash
  --auto-firmware          Auto-detect and download matching Nordic firmware package
  --auto-flash             Auto-flash selected firmware when needed
  --configure-tshark       Configure tshark global extcap integration
  --flash-force            Force flashing even if sniffer already responds
  --firmware-force         Force firmware download even if sniffer is already capture-capable
  --serial-port PORT       Serial port to use for flash (default: auto-detect)
  --skip-brltty-removal    Do not remove brltty package
  --skip-apt               Skip apt package installation
  -h, --help               Show this help
USAGE
}

EXTCAP_ZIP=""
EXTCAP_URL=""
TRY_KNOWN_URLS=0
FLASH_FIRMWARE=0
AUTO_FIRMWARE=0
AUTO_FLASH=0
FLASH_FORCE=0
FIRMWARE_FORCE=0
CONFIGURE_TSHARK=0
SERIAL_PORT=""
SKIP_BRLTTY_REMOVAL=0
SKIP_APT=0

KNOWN_URLS=(
  "https://nssc-prod-media.nordicsemi.com/software-and-other-downloads/desktop-software/nrf-sniffer-for-bluetooth-le/nrf-sniffer-for-bluetooth-le-4.1.1.zip"
  "https://nssc-prod-media.nordicsemi.com/software-and-other-downloads/desktop-software/nrf-sniffer-for-bluetooth-le/nrf-sniffer-for-bluetooth-le-4.1.0.zip"
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --extcap-zip)
      EXTCAP_ZIP="$2"
      shift 2
      ;;
    --extcap-url)
      EXTCAP_URL="$2"
      shift 2
      ;;
    --try-known-urls)
      TRY_KNOWN_URLS=1
      shift
      ;;
    --flash-firmware)
      FLASH_FIRMWARE=1
      shift
      ;;
    --auto-firmware)
      AUTO_FIRMWARE=1
      shift
      ;;
    --auto-flash)
      AUTO_FLASH=1
      shift
      ;;
    --configure-tshark)
      CONFIGURE_TSHARK=1
      shift
      ;;
    --flash-force)
      FLASH_FORCE=1
      shift
      ;;
    --firmware-force)
      FIRMWARE_FORCE=1
      shift
      ;;
    --serial-port)
      SERIAL_PORT="$2"
      shift 2
      ;;
    --skip-brltty-removal)
      SKIP_BRLTTY_REMOVAL=1
      shift
      ;;
    --skip-apt)
      SKIP_APT=1
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

install_missing_packages() {
  local pkgs=(wireshark python3-pip python3-serial unzip curl usbutils)
  local missing=()
  local pkg
  for pkg in "${pkgs[@]}"; do
    if ! is_package_installed "$pkg"; then
      missing+=("$pkg")
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    log "All required apt packages are already installed"
    return
  fi

  log "Installing missing apt packages: ${missing[*]}"
  sudo apt-get update
  sudo apt-get install -y "${missing[@]}"
}

ensure_groups() {
  local changed=0
  local grp
  for grp in dialout wireshark; do
    if in_group "$grp"; then
      log "User is already in group: $grp"
    else
      log "Adding $USER to group: $grp"
      sudo usermod -aG "$grp" "$USER"
      changed=1
    fi
  done

  if [[ $changed -eq 1 ]]; then
    warn "Group membership changed. Log out and log back in before sniffing."
  fi
}

remove_brltty_if_present() {
  if [[ $SKIP_BRLTTY_REMOVAL -eq 1 ]]; then
    log "Skipping brltty removal by request"
    return
  fi

  if is_package_installed brltty; then
    log "Removing brltty to avoid USB serial device conflicts"
    sudo apt-get remove -y brltty
  else
    log "brltty is not installed"
  fi
}

install_extcap_from_zip() {
  local zip_path="$1"
  if [[ ! -f "$zip_path" ]]; then
    err "Zip file not found: $zip_path"
    return 1
  fi

  local extcap_dir
  extcap_dir="$(wireshark_personal_extcap_dir)"
  mkdir -p "$extcap_dir"

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  unzip -q "$zip_path" -d "$tmpdir"

  local source_extcap=""
  if [[ -d "$tmpdir/extcap" ]]; then
    source_extcap="$tmpdir/extcap"
  else
    source_extcap="$(find "$tmpdir" -type d -name extcap | head -n 1 || true)"
  fi

  if [[ -z "$source_extcap" || ! -d "$source_extcap" ]]; then
    err "Could not find extcap directory inside: $zip_path"
    return 1
  fi

  log "Installing extcap files into: $extcap_dir"
  cp -a "$source_extcap"/. "$extcap_dir"/

  if [[ -f "$extcap_dir/nrf_sniffer_ble.py" ]]; then
    chmod +x "$extcap_dir/nrf_sniffer_ble.py"
  fi
  if [[ -f "$extcap_dir/nrf_sniffer_ble.sh" ]]; then
    chmod +x "$extcap_dir/nrf_sniffer_ble.sh"
  fi

  if [[ -f "$extcap_dir/requirements.txt" ]]; then
    log "Installing Python requirements for extcap"
    pip3 install --user -r "$extcap_dir/requirements.txt"
  fi

  log "extcap install complete"
}

download_to_temp_zip() {
  local url="$1"
  local out="$2"
  if have_cmd curl; then
    curl -fsSL "$url" -o "$out"
  else
    wget -q "$url" -O "$out"
  fi
}

try_known_urls() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN

  local url
  for url in "${KNOWN_URLS[@]}"; do
    local zip="$tmpdir/sniffer.zip"
    log "Trying Nordic package URL: $url"
    if download_to_temp_zip "$url" "$zip"; then
      if unzip -tq "$zip" >/dev/null 2>&1; then
        install_extcap_from_zip "$zip"
        log "Installed from known URL: $url"
        return 0
      fi
      warn "Downloaded artifact is not a valid zip from: $url"
    else
      warn "Download failed: $url"
    fi
  done

  return 1
}

auto_detect_serial_port() {
  local candidate
  for candidate in /dev/ttyUSB0 /dev/ttyACM0; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  candidate="$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null | head -n 1 || true)"
  if [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  return 1
}

try_flash_firmware() {
  local extcap_dir
  extcap_dir="$(wireshark_personal_extcap_dir)"
  local sniffer_py="$extcap_dir/nrf_sniffer_ble.py"

  if [[ ! -f "$sniffer_py" ]]; then
    warn "Cannot flash firmware: $sniffer_py not found"
    return 1
  fi

  if ! python3 "$sniffer_py" --help 2>&1 | grep -q -- '--flash'; then
    warn "This nrf_sniffer_ble.py does not expose --flash; skipping firmware step"
    return 1
  fi

  local port="$SERIAL_PORT"
  if [[ -z "$port" ]]; then
    port="$(auto_detect_serial_port || true)"
  fi

  if [[ -z "$port" ]]; then
    warn "Could not auto-detect serial port for firmware flashing"
    return 1
  fi

  log "Attempting firmware flash on $port"
  python3 "$sniffer_py" --flash --device "$port"
}

validate_runtime() {
  if ! is_ubuntu_like; then
    warn "Non-Ubuntu/Debian host detected; apt workflow may not apply"
  fi
}

main() {
  validate_runtime

  if [[ $SKIP_APT -eq 0 ]]; then
    install_missing_packages
  else
    log "Skipping apt package installation by request"
  fi

  ensure_groups
  remove_brltty_if_present

  local extcap_dir
  extcap_dir="$(wireshark_personal_extcap_dir)"
  mkdir -p "$extcap_dir"
  log "Personal extcap directory: $extcap_dir"

  if [[ -n "$EXTCAP_ZIP" ]]; then
    install_extcap_from_zip "$EXTCAP_ZIP"
  fi

  if [[ -n "$EXTCAP_URL" ]]; then
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN
    local zip="$tmpdir/sniffer.zip"
    log "Downloading extcap zip from URL"
    download_to_temp_zip "$EXTCAP_URL" "$zip"
    install_extcap_from_zip "$zip"
  fi

  if [[ $TRY_KNOWN_URLS -eq 1 ]]; then
    if ! try_known_urls; then
      warn "Known URLs did not work. Provide --extcap-zip PATH to install from a local download."
    fi
  fi

  if [[ $CONFIGURE_TSHARK -eq 1 ]]; then
    log "Configuring tshark extcap integration"
    "$SCRIPT_DIR/configure_tshark_extcap.sh" || warn "tshark extcap configuration step did not complete cleanly"
  fi

  local state_env
  local state_args=()
  if [[ -n "$SERIAL_PORT" ]]; then
    state_args+=(--serial-port "$SERIAL_PORT")
  fi
  state_env="$("$SCRIPT_DIR/check_sniffer_state.sh" "${state_args[@]}")"
  eval "$state_env"
  log "Sniffer state: firmware=${FIRMWARE_STATE} capture_ready=${CAPTURE_READY}"

  if [[ $AUTO_FIRMWARE -eq 1 ]]; then
    if [[ "$FIRMWARE_STATE" == "capture-capable" && $FIRMWARE_FORCE -eq 0 ]]; then
      log "Skipping firmware download: sniffer already capture-capable"
    else
      log "Auto firmware download requested"
      local fw_args=()
      if [[ -n "$SERIAL_PORT" ]]; then
        fw_args+=(--serial-port "$SERIAL_PORT")
      fi
      "$SCRIPT_DIR/fetch_nordic_firmware.sh" "${fw_args[@]}"
    fi
  fi

  if [[ $AUTO_FLASH -eq 1 ]]; then
    if [[ "$FIRMWARE_STATE" == "capture-capable" && $FLASH_FORCE -eq 0 ]]; then
      log "Skipping flash: sniffer already capture-capable"
    else
      log "Auto flash requested"
      local fl_args=(--best-effort)
      if [[ -n "$SERIAL_PORT" ]]; then
        fl_args+=(--serial-port "$SERIAL_PORT")
      fi
      if [[ $FLASH_FORCE -eq 1 ]]; then
        fl_args+=(--force)
      fi
      "$SCRIPT_DIR/flash_firmware.sh" "${fl_args[@]}"
    fi
  fi

  if [[ $FLASH_FIRMWARE -eq 1 ]]; then
    try_flash_firmware || true
  fi

  log "Host setup completed"
}

main "$@"
