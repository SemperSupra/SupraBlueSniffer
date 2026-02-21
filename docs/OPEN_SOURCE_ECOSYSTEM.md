# Open Source Ecosystem Using This Device Class

This project targets the Adafruit Bluefruit LE Sniffer hardware class (notably CP2104 + Nordic BLE sniffer firmware workflows) and compatible Nordic nRF BLE sniffer tooling.

## Which Project Should I Use?

| Goal | Best Starting Project | Why |
|---|---|---|
| Quick BLE packet capture into Wireshark with minimal custom coding | `adafruit/Adafruit_BLESniffer_Python` | Purpose-built wrapper for Adafruit sniffer workflow and PCAP output. |
| Open-source firmware/tooling experimentation on Nordic-compatible hardware | `bluekitchen/raccoon` | End-to-end sniffer firmware + host tooling for deeper control. |
| Multi-sniffer and advanced bridge/decryption workflows | `homewsn/bsniffhub` | Aggregates sniffer data for larger/advanced analysis pipelines. |

## Projects

### 1. Adafruit BLE Sniffer Python API
- Project: `adafruit/Adafruit_BLESniffer_Python`
- Link: https://github.com/adafruit/Adafruit_BLESniffer_Python
- Brief: Python API/wrapper for Adafruit's Bluefruit LE Sniffer. It scans for BLE devices, captures traffic, and writes PCAP output for Wireshark analysis.

### 2. Raccoon BLE Sniffer
- Project: `bluekitchen/raccoon`
- Link: https://github.com/bluekitchen/raccoon
- Brief: Open-source BLE sniffer firmware + Python CLI for Nordic nRF5x targets. It supports advanced workflows such as following connection requests across advertising channels and explicitly lists Adafruit Bluefruit LE Friend (nRF51822) among tested devices.

### 3. Bsniffhub
- Project: `homewsn/bsniffhub`
- Link: https://github.com/homewsn/bsniffhub
- Brief: Utility layer for multiple BLE sniffers (including Nordic nRF Sniffer) that feeds Wireshark/PCAP pipelines and supports decryption workflows when key material is available.

## Adafruit Device References (Specific Device Family)

### 1. Introducing the Adafruit Bluefruit LE Sniffer
- Link: https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer
- Brief: Official device guide and setup overview, including BLE-only limitations and capture caveats.

### 2. USB Driver Install
- Link: https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/usb-driver-install
- Brief: Driver requirements by board revision (CP2104 for newer black boards, FTDI for older boards).

### 3. Using with Sniffer V2 and Python3
- Link: https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/using-with-sniffer-v2-and-python3
- Brief: End-to-end setup flow for Wireshark + Nordic plugin package for current V2/Python3 workflows.

### 4. V1 Python API (Legacy)
- Link: https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/python-api
- Brief: Legacy V1 page describing earlier Python-based capture flow and PCAP output handling.
