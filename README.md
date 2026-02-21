# BlueSniffer

Idempotent host bootstrap, diagnostics, and capture tooling for Nordic/Adafruit BLE sniffer workflows on Ubuntu.

## Scripts

- `scripts/run_all.sh`
  - End-to-end runner: setup, optional firmware actions, diagnostics.
- `scripts/setup_host.sh`
  - Installs missing dependencies
  - Ensures permissions/groups (`dialout`, `wireshark`)
  - Removes `brltty` conflict
  - Installs Wireshark extcap (optional zip/url)
  - Configures tshark extcap integration (optional)
  - Uses sniffer state detection to skip unnecessary firmware download/flash
- `scripts/check_sniffer_state.sh`
  - Single source of truth for readiness:
  - USB serial present, Wireshark extcap ready, tshark extcap ready, capture readiness, firmware state
- `scripts/configure_tshark_extcap.sh`
  - Idempotently syncs personal extcap into tshark global extcap path
- `scripts/fetch_nordic_firmware.sh`
  - Detects device class from udev metadata
  - Chooses firmware package and `.hex`
  - Downloads, checksum-verifies, extracts, stages `current.hex`
  - Skips download if device is already capture-capable (unless forced)
- `scripts/flash_firmware.sh`
  - Idempotent flashing orchestration
  - Skips flash when sniffer is already capture-capable (unless forced)
  - Uses `nrfjprog` first, `pyocd` fallback
- `scripts/collect_diagnostics.sh`
  - Generates timestamped report in `diagnostics/`

## Quick Start

Run full setup + diagnostics:

```bash
./scripts/run_all.sh
```

Check current readiness:

```bash
./scripts/check_sniffer_state.sh --format text
```

## Common Commands

Configure tshark extcap:

```bash
./scripts/configure_tshark_extcap.sh
```

Download/stage firmware:

```bash
./scripts/fetch_nordic_firmware.sh
```

Force firmware redownload:

```bash
./scripts/fetch_nordic_firmware.sh --force-download
```

Auto-flash (best effort):

```bash
./scripts/setup_host.sh --auto-flash
```

Force flash even when already capture-capable:

```bash
./scripts/setup_host.sh --auto-flash --flash-force
```

## Productive tshark Capture Examples

Assume your sniffer interface is:

```bash
IFACE="/dev/ttyUSB0-3.6"
```

List available tshark interfaces and confirm sniffer entry:

```bash
tshark -D | grep -i nrf
```

1-minute baseline capture (good starting point):

```bash
tshark -i "$IFACE" -a duration:60 -w captures/baseline-60s.pcapng
```

See which BLE advertising addresses are most active:

```bash
tshark -r captures/baseline-60s.pcapng -T fields -e btle.advertising_address \
  | grep -v '^$' | sort | uniq -c | sort -nr | head -30
```

Break down advertising/scan/connect mode usage by PDU type:

```bash
tshark -r captures/baseline-60s.pcapng -T fields -e btle.advertising_header.pdu_type \
  | grep -v '^$' | sort | uniq -c | sort -nr
```

Quickly check for connection attempts:

```bash
tshark -r captures/baseline-60s.pcapng -Y "btle.advertising_header.pdu_type==5" \
  -T fields -e frame.number -e frame.time -e btle.initiator_address -e btle.advertising_address
```

Follow one specific device address (replace target MAC):

```bash
TARGET="cd:93:51:a3:0d:59"
tshark -i "$IFACE" -Y "btle.advertising_address==$TARGET || btle.initiator_address==$TARGET || btle.advertising_address_resolved==$TARGET" \
  -a duration:90 -w "captures/target-${TARGET//:/}.pcapng"
```

Check if ATT/GATT application traffic is present:

```bash
tshark -r captures/baseline-60s.pcapng -Y btatt -T fields -e frame.number -e btatt.opcode -e btatt.handle | head
```

Live decoded ATT view (when connection traffic exists):

```bash
tshark -i "$IFACE" -Y btatt -V
```

Helpful workflow:
1. Capture baseline traffic.
2. Rank top advertiser addresses.
3. Pick a target MAC and run focused capture while triggering actions in the companion app/device.
4. Re-check for `btatt` frames to identify command/data exchanges.

## Scapy Lookup Cross-Check Script

Use this script to collect a sample capture, parse packet examples with Scapy, run device/vendor lookups, and cross-check what each source reports:

- Bluetooth SIG Company Identifiers
- IEEE OUI registry
- macvendors API
- maclookup API
- iplocation API

Prerequisite:

```bash
pip3 install --user scapy
```

Run with live capture (auto-detects nRF interface):

```bash
./scripts/capture_scapy_lookup_crosscheck.py --duration 60
```

Run against an existing capture file:

```bash
./scripts/capture_scapy_lookup_crosscheck.py --capture ../captures/baseline-60s.pcapng
```

Write report to a specific path:

```bash
./scripts/capture_scapy_lookup_crosscheck.py --duration 60 --output-json diagnostics/lookup-report.json
```

## Discovery-Mode Lifecycle Tracker

Detect when BLE devices enter discovery mode (connectable advertising), then track scan, connect, ATT, and termination lifecycle events.

Analyze live traffic:

```bash
./scripts/track_ble_lifecycle.py --duration 60
```

Track a specific device only:

```bash
./scripts/track_ble_lifecycle.py --duration 90 --target cd:93:51:a3:0d:59
```

Analyze an existing capture:

```bash
./scripts/track_ble_lifecycle.py --capture captures/lookup-sample-20260221_165843.pcapng --output-json diagnostics/lifecycle-report.json
```

## Idempotency Behavior

- Package installs run only for missing packages.
- Group membership changes only when needed.
- tshark extcap sync is skipped when tshark already lists nRF Sniffer.
- Firmware download and flash are skipped when sniffer is already capture-capable, unless force flags are used.

## Reflashing Requirements

See `docs/REFLASH_GUIDE.md` for hardware/software prerequisites and Adafruit-specific constraints.

Adafruit references:
- https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/faqs
- https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/usb-driver-install

## Session Review

See `docs/SESSION_REVIEW.md` for a retrospective and concrete recommendations.
