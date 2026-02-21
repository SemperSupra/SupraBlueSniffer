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

Detect sniffer hardware and download/extract the matching Nordic nRF Sniffer package.

Options:
  --serial-port PORT         Serial port to inspect (default: auto-detect)
  --firmware-dir DIR         Destination root (default: ~/.local/share/bluesniffer/firmware)
  --force-download           Re-download even if package already exists
  --print-selection-only     Only print detected target/package info
  --log-level LEVEL          Set shell log level: NONE, ERROR, WARN, INFO, DEBUG
  --quiet                    Equivalent to error-only logs
  -h, --help                 Show help
USAGE
}

SERIAL_PORT=""
FIRMWARE_DIR="${HOME}/.local/share/bluesniffer/firmware"
FORCE_DOWNLOAD=0
PRINT_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial-port)
      SERIAL_PORT="$2"
      shift 2
      ;;
    --firmware-dir)
      FIRMWARE_DIR="$2"
      shift 2
      ;;
    --force-download)
      FORCE_DOWNLOAD=1
      shift
      ;;
    --print-selection-only)
      PRINT_ONLY=1
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
  first_serial_port
}

get_udev_prop() {
  local port="$1"
  local key="$2"
  udevadm info -q property -n "$port" 2>/dev/null | awk -F= -v key="$key" '$1==key {print $2; exit}'
}

# Emits: package_line|zip_name|sha256|target_pattern
select_package_for_device() {
  local vendor="$1"
  local product="$2"
  local model="$3"

  # Inference based on USB bridge and Nordic supported HW families.
  if [[ "$vendor" == "10c4" && "$product" == "ea60" ]]; then
    # CP210x USB-UART bridges are typical for older nRF51-based sniffers.
    printf '%s\n' "3.1.0|nrf_sniffer_for_bluetooth_le_3.1.0_7cc811f.zip|9baa952e30ae736a5fd99ff8765934d5a2c10a328c022ae5b432aa589fe89495|sniffer_nrf51dongle*.hex"
    return
  fi

  if [[ "$vendor" == "1915" ]]; then
    # Nordic USB devices (e.g. nRF52840 dongle) -> current v4 line.
    printf '%s\n' "4.1.1|nrf_sniffer_for_bluetooth_le_4.1.1.zip|26502447742346cd0b0c597564b12a621859ffd4ad05c029069c4fa22deddd40|sniffer_nrf52840dongle*.hex"
    return
  fi

  # Generic fallback for unknown hardware: newest package line.
  printf '%s\n' "4.1.1|nrf_sniffer_for_bluetooth_le_4.1.1.zip|26502447742346cd0b0c597564b12a621859ffd4ad05c029069c4fa22deddd40|sniffer_*.hex"
}

url_candidates_for_zip() {
  local zip_name="$1"
  local -a names=("$zip_name")
  case "$zip_name" in
    nrf_sniffer_for_bluetooth_le_3.1.0_7cc811f.zip)
      names+=(
        "nrfsnifferforbluetoothle3107cc811f.zip"
        "nrf_sniffer_for_bluetooth_le_3.1.0.zip"
      )
      ;;
    nrf_sniffer_for_bluetooth_le_2.0.0_c87e17d.zip)
      names+=(
        "nrfsnifferforbluetoothle200c87e17d.zip"
        "nrf_sniffer_for_bluetooth_le_2.0.0.zip"
      )
      ;;
  esac

  local name
  for name in "${names[@]}"; do
    cat <<URLS
https://nsscprodmedia.blob.core.windows.net/prod/software-and-other-downloads/desktop-software/nrf-sniffer/sw/${name}
https://nssc-prod-media.nordicsemi.com/software-and-other-downloads/desktop-software/nrf-sniffer-for-bluetooth-le/${name}
https://nssc-prod-media-nordicsemi-com.s3.amazonaws.com/software-and-other-downloads/desktop-software/nrf-sniffer-for-bluetooth-le/${name}
https://nssc-prod-media-nordicsemi-com.s3.amazonaws.com/software/ble/nrf-sniffer/${name}
URLS
  done
}

sha256_file() {
  if have_cmd sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

download_zip() {
  local zip_name="$1"
  local out_zip="$2"
  local tmp_zip="$out_zip.tmp"
  local url

  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    log "Trying download URL: $url"
    if curl -fL --retry 3 --retry-delay 1 --retry-all-errors --connect-timeout 10 "$url" -o "$tmp_zip"; then
      if unzip -tq "$tmp_zip" >/dev/null 2>&1; then
        mv "$tmp_zip" "$out_zip"
        return 0
      fi
      warn "Downloaded file is not a valid zip from $url"
    fi
  done < <(url_candidates_for_zip "$zip_name")

  rm -f "$tmp_zip"
  return 1
}

main() {
  if ! mkdir -p "$FIRMWARE_DIR" 2>/dev/null; then
    FIRMWARE_DIR="$PWD/state/firmware"
    mkdir -p "$FIRMWARE_DIR"
    warn "Default firmware dir under HOME is not writable; using $FIRMWARE_DIR"
  fi

  local port="$SERIAL_PORT"
  if [[ -z "$port" ]]; then
    port="$(auto_detect_serial_port || true)"
  fi

  if [[ -z "$port" ]]; then
    err "No serial sniffer device found (/dev/ttyUSB* or /dev/ttyACM*)"
    exit 1
  fi

  local vendor product model
  vendor="$(get_udev_prop "$port" ID_VENDOR_ID || true)"
  product="$(get_udev_prop "$port" ID_MODEL_ID || true)"
  model="$(get_udev_prop "$port" ID_MODEL || true)"

  local selection package_line zip_name sha256_expected target_pattern
  selection="$(select_package_for_device "$vendor" "$product" "$model")"
  package_line="${selection%%|*}"
  selection="${selection#*|}"
  zip_name="${selection%%|*}"
  selection="${selection#*|}"
  sha256_expected="${selection%%|*}"
  target_pattern="${selection#*|}"

  log "Detected device: port=$port vendor=${vendor:-unknown} product=${product:-unknown} model=${model:-unknown}"
  log "Selected Nordic package line: $package_line"
  log "Selected package file: $zip_name"
  log "Selected firmware pattern: $target_pattern"

  if [[ $PRINT_ONLY -eq 1 ]]; then
    exit 0
  fi

  if [[ $FORCE_DOWNLOAD -eq 0 && -x "$SCRIPT_DIR/check_sniffer_state.sh" ]]; then
    local state
    state="$("$SCRIPT_DIR/check_sniffer_state.sh" --serial-port "$port" 2>/dev/null || true)"
    if [[ -n "$state" ]]; then
      eval "$state"
      if [[ "${FIRMWARE_STATE:-unknown}" == "capture-capable" ]]; then
        log "Skipping download: device already capture-capable for Wireshark/tshark"
        exit 0
      fi
    fi
  fi

  local package_dir="$FIRMWARE_DIR/packages"
  local extract_dir="$FIRMWARE_DIR/extracted/$package_line"
  mkdir -p "$package_dir" "$extract_dir"

  local zip_path="$package_dir/$zip_name"

  if [[ -f "$zip_path" && $FORCE_DOWNLOAD -eq 0 ]]; then
    log "Using cached package: $zip_path"
  else
    log "Downloading Nordic package to: $zip_path"
    if ! download_zip "$zip_name" "$zip_path"; then
      err "Failed to download package $zip_name from known Nordic URL patterns."
      err "Download manually from https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE/Download and rerun with cache in place."
      exit 1
    fi
  fi

  local sha256_actual
  sha256_actual="$(sha256_file "$zip_path")"
  if [[ -n "$sha256_expected" && "$sha256_actual" != "$sha256_expected" ]]; then
    err "SHA256 mismatch for $zip_path"
    err "Expected: $sha256_expected"
    err "Actual:   $sha256_actual"
    exit 1
  fi
  log "SHA256 verified"

  local marker="$extract_dir/.installed_from_sha256"
  if [[ -f "$marker" ]] && grep -qx "$sha256_actual" "$marker"; then
    log "Firmware package already extracted for this checksum"
  else
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    unzip -q "$zip_path" -d "$extract_dir"
    printf '%s\n' "$sha256_actual" > "$marker"
    log "Package extracted to $extract_dir"
  fi

  local hex_root
  hex_root="$(find "$extract_dir" -type d -name hex | head -n 1 || true)"
  if [[ -z "$hex_root" ]]; then
    err "No hex directory found in extracted package"
    exit 1
  fi

  local chosen_hex
  chosen_hex="$(find "$hex_root" -maxdepth 1 -type f -name "$target_pattern" | head -n 1 || true)"
  if [[ -z "$chosen_hex" ]]; then
    chosen_hex="$(find "$hex_root" -maxdepth 1 -type f -name 'sniffer_*.hex' | head -n 1 || true)"
  fi

  if [[ -z "$chosen_hex" ]]; then
    err "No suitable firmware hex found in $hex_root"
    exit 1
  fi

  mkdir -p "$FIRMWARE_DIR"
  ln -sfn "$chosen_hex" "$FIRMWARE_DIR/current.hex"
  printf '%s\n' "$port" > "$FIRMWARE_DIR/last_port.txt"

  log "Selected firmware hex: $chosen_hex"
  log "Symlink updated: $FIRMWARE_DIR/current.hex"
  log "Ready for flash using your preferred programmer (nRF Connect Programmer/nrfjprog)."
}

main "$@"
