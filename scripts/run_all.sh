#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $0 [options] [-- setup_host_args...]

Run host setup and then collect diagnostics.

Options:
  --log-level LEVEL   Set shell log level: NONE, ERROR, WARN, INFO, DEBUG
  --quiet             Equivalent to error-only logs
  -h, --help          Show help
USAGE
}

FORWARD_ARGS=()
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
    --)
      shift
      FORWARD_ARGS+=("$@")
      break
      ;;
    *)
      FORWARD_ARGS+=("$1")
      shift
      ;;
  esac
done

AUTO_FW_FLAG=()
if [[ "${BLUESNIFFER_AUTO_FIRMWARE:-1}" == "1" ]]; then
  AUTO_FW_FLAG=(--auto-firmware)
fi

AUTO_FLASH_FLAG=()
if [[ "${BLUESNIFFER_AUTO_FLASH:-1}" == "1" ]]; then
  AUTO_FLASH_FLAG=(--auto-flash)
fi

TSHARK_CFG_FLAG=()
if [[ "${BLUESNIFFER_CONFIGURE_TSHARK:-1}" == "1" ]]; then
  TSHARK_CFG_FLAG=(--configure-tshark)
fi

"$SCRIPT_DIR/setup_host.sh" "${AUTO_FW_FLAG[@]}" "${AUTO_FLASH_FLAG[@]}" "${TSHARK_CFG_FLAG[@]}" "${FORWARD_ARGS[@]}"
"$SCRIPT_DIR/collect_diagnostics.sh"
