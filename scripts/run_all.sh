#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

"$SCRIPT_DIR/setup_host.sh" "${AUTO_FW_FLAG[@]}" "${AUTO_FLASH_FLAG[@]}" "${TSHARK_CFG_FLAG[@]}" "$@"
"$SCRIPT_DIR/collect_diagnostics.sh"
