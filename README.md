# SupraBlueSniffer

Idempotent host bootstrap, diagnostics, and capture tooling for Nordic/Adafruit BLE sniffer workflows on Ubuntu.

## What This Project Is

SupraBlueSniffer is an operations-focused helper project for getting an Adafruit/Nordic BLE sniffer host into a known-good state quickly and repeatably. It focuses on:

- Host setup and dependency checks
- Wireshark/tshark extcap readiness
- Firmware package selection/staging
- Flash orchestration checks
- Repeatable diagnostics and capture tooling

## Real-World Open Source Projects Using This Device Class

- Adafruit BLE Sniffer Python API: https://github.com/adafruit/Adafruit_BLESniffer_Python
  - Python capture workflow for Adafruit Bluefruit LE Sniffer with PCAP output.
- Raccoon BLE Sniffer: https://github.com/bluekitchen/raccoon
  - Open-source BLE sniffer firmware + host tooling for Nordic/compatible devices.
- Bsniffhub: https://github.com/homewsn/bsniffhub
  - Multi-sniffer BLE capture/decryption bridge for Wireshark/PCAP pipelines.

More detail: `docs/OPEN_SOURCE_ECOSYSTEM.md`
Quick chooser table: `docs/OPEN_SOURCE_ECOSYSTEM.md` (Which Project Should I Use?)

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

Collect diagnostics with redaction for safer sharing:

```bash
./scripts/collect_diagnostics.sh diagnostics --redact
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

## Logging Controls

Shell scripts support both environment and CLI-based log controls:

```bash
BLUESNIFFER_LOG_LEVEL=DEBUG ./scripts/run_all.sh
BLUESNIFFER_QUIET=1 ./scripts/run_all.sh
./scripts/run_all.sh --log-level DEBUG
./scripts/setup_host.sh --quiet
```

Python capture tools support CLI log controls:

```bash
./scripts/capture_scapy_lookup_crosscheck.py --log-level DEBUG
./scripts/track_ble_lifecycle.py --quiet
```

## Runtime Paths

Project-managed runtime data uses non-hidden directories:

- `captures/` for capture files
- `diagnostics/` for report output
- `state/cache/` for cached remote registry data
- `state/locks/` for capture lock coordination
- `state/firmware/` fallback firmware state when home cache is unavailable

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

Recommended stability flags for busy environments:

```bash
./scripts/capture_scapy_lookup_crosscheck.py --duration 60 --heartbeat-sec 5 --lock-timeout 30 --max-scapy-packets 5000 --lookup-workers 6 --max-unique-devices 2000 --display-filter "btle || btatt"
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

Use bounded timeline and explicit parse timeout controls:

```bash
./scripts/track_ble_lifecycle.py --duration 60 --max-events-per-device 2000 --parse-timeout-sec 180 --heartbeat-sec 5 --display-filter "btle || btatt"
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
- https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer
- https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/using-with-sniffer-v2-and-python3
- https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/python-api

## Session Review

See `docs/SESSION_REVIEW.md` for a retrospective and concrete recommendations.

## Backlog

See `docs/BACKLOG.md` for deferred correctness/operability work items.
