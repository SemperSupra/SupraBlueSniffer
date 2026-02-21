# Reflash Guide (Adafruit BLE Sniffer)

This project supports automatic firmware download and staging, but actual flashing depends on hardware.

## Which firmware to use

For Adafruit Bluefruit LE Sniffer units that enumerate as `CP2104`/`CP210x` (`VID:PID 10c4:ea60`), use the Nordic nRF Sniffer for Bluetooth LE `3.1.0` package and the `nrf51dongle` hex:

- `sniffer_nrf51dongle_nrf51422_7cc811f.hex`

The automation in `scripts/fetch_nordic_firmware.sh` selects this automatically for CP210x devices.

## Why USB alone is not enough for reflashing

Adafruit documents that the sniffer firmware is distributed as a single `.hex` and the board does not provide a fail-safe USB DFU flow for this firmware path. Practically, flashing requires SWD programming access.

Adafruit also notes for newer black-board revisions (v1.3) that the SWD header was removed; SWD is still possible through breakout pads.

References:
- https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/faqs
- https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/usb-driver-install

## Hardware needed for reflashing

1. SWD programmer/debug probe
- Recommended: SEGGER J-Link (works with `nrfjprog`)
- Alternative: CMSIS-DAP probe (works with `pyocd`)

2. Physical SWD access to the sniffer board
- `SWDIO`
- `SWCLK`
- `GND`
- `VTref` (3.3V reference)
- Optional: `RESET`

3. Software backend on host
- Preferred: `nrfjprog`
- Fallback: `pyocd`

## What is already automated

- Download and verify firmware package
- Extract and select matching `.hex`
- Stage selected firmware at `state/firmware/current.hex`
- Flash orchestration (`scripts/flash_firmware.sh`) with idempotent skip when capture already works

## Limitations

Without SWD hardware, scripts can stage firmware but cannot program the chip.
