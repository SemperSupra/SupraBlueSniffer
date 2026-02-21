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
