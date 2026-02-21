#!/usr/bin/env python3
"""
Capture BLE samples, parse packet examples with Scapy, and cross-check device lookup
results across multiple public sources.

Sources used:
- Bluetooth SIG company identifiers (official YAML mirror)
- IEEE OUI text registry (official)
- macvendors.com API
- maclookup.app API
- iplocation.net API (queried for completeness; may not return MAC vendor data)
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# Optional dependency, required by user request.
try:
    from scapy.layers.bluetooth4LE import BTLE  # type: ignore
    from scapy.utils import RawPcapNgReader  # type: ignore
except Exception as exc:  # pragma: no cover
    BTLE = None  # type: ignore
    RawPcapNgReader = None  # type: ignore
    _SCAPY_IMPORT_ERROR = exc
else:
    _SCAPY_IMPORT_ERROR = None


SIG_COMPANY_YAML_URL = (
    "https://bitbucket.org/bluetooth-SIG/public/raw/main/"
    "assigned_numbers/company_identifiers/company_identifiers.yaml"
)
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
MACVENDORS_URL = "https://api.macvendors.com/{mac}"
MACLOOKUP_URL = "https://api.maclookup.app/v2/macs/{mac}"
IPLOCATION_URL = "https://api.iplocation.net/?cmd=mac&mac={mac}"


def run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def ensure_scapy() -> None:
    if BTLE is None or RawPcapNgReader is None:
        raise SystemExit(
            "Scapy is required but not installed/importable. "
            f"Install with: pip3 install --user scapy\nImport error: {_SCAPY_IMPORT_ERROR}"
        )


def detect_nrf_interface() -> Optional[str]:
    cp = run(["tshark", "-D"], check=False)
    if cp.returncode != 0:
        return None
    for line in cp.stdout.splitlines():
        if "nRF Sniffer for Bluetooth LE" in line:
            # Format: '19. /dev/ttyUSB0-3.6 (nRF Sniffer for Bluetooth LE)'
            m = re.search(r"\d+\.\s+([^\s]+)\s+\(nRF Sniffer for Bluetooth LE\)", line)
            if m:
                return m.group(1)
    return None


def capture_samples(interface: str, duration: int, capture_path: Path) -> None:
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "tshark",
        "-i",
        interface,
        "-a",
        f"duration:{duration}",
        "-w",
        str(capture_path),
    ]
    cp = run(cmd, check=False)
    if cp.returncode != 0:
        raise SystemExit(
            "Capture failed.\n"
            f"Command: {' '.join(cmd)}\n"
            f"stderr:\n{cp.stderr}"
        )


def extract_device_rows(capture_path: Path) -> List[Dict[str, str]]:
    # Extract key fields, tab-delimited to avoid CSV quoting issues from tshark output.
    fields = [
        "frame.number",
        "frame.time_epoch",
        "btle.advertising_address",
        "btle.initiator_address",
        "btcommon.eir_ad.entry.company_id",
        "btle.advertising_header.pdu_type",
    ]
    cmd = ["tshark", "-r", str(capture_path), "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd.extend(["-e", f])

    cp = run(cmd, check=False)
    if cp.returncode != 0:
        raise SystemExit(f"tshark field extraction failed:\n{cp.stderr}")

    rows: List[Dict[str, str]] = []
    for line in cp.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(fields) - len(parts))
        row = dict(zip(fields, parts))
        if row["btle.advertising_address"] or row["btle.initiator_address"]:
            rows.append(row)
    return rows


def parse_company_ids(value: str) -> List[int]:
    # tshark may emit single or comma-separated hex values like: 0x004c,0x004c
    out: List[int] = []
    for token in re.split(r"[,; ]+", value.strip()):
        if not token:
            continue
        token = token.lower()
        try:
            if token.startswith("0x"):
                out.append(int(token, 16))
            else:
                out.append(int(token, 10))
        except ValueError:
            continue
    return out


def normalize_mac(mac: str) -> Optional[str]:
    m = re.findall(r"[0-9a-fA-F]{2}", mac)
    if len(m) != 6:
        return None
    return ":".join(x.lower() for x in m)


def load_url(url: str, cache_path: Path, timeout: int = 10, force_refresh: bool = False) -> str:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists() and not force_refresh:
        return cache_path.read_text(encoding="utf-8", errors="replace")

    req = urllib.request.Request(url, headers={"User-Agent": "BlueSnifferLookup/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    cache_path.write_text(body, encoding="utf-8")
    return body


def load_ieee_oui_map(cache_dir: Path, timeout: int, force_refresh: bool) -> Dict[str, str]:
    txt = load_url(IEEE_OUI_URL, cache_dir / "ieee_oui.txt", timeout=timeout, force_refresh=force_refresh)
    out: Dict[str, str] = {}
    pat = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$")
    for line in txt.splitlines():
        m = pat.match(line)
        if not m:
            continue
        prefix = m.group(1).replace("-", ":").lower()
        vendor = m.group(2).strip()
        out[prefix] = vendor
    return out


def load_sig_company_map(cache_dir: Path, timeout: int, force_refresh: bool) -> Dict[int, str]:
    text = load_url(
        SIG_COMPANY_YAML_URL,
        cache_dir / "sig_company_identifiers.yaml",
        timeout=timeout,
        force_refresh=force_refresh,
    )
    out: Dict[int, str] = {}
    current_value: Optional[int] = None
    for line in text.splitlines():
        vm = re.match(r"\s*-\s*value:\s*0x([0-9a-fA-F]{1,4})", line)
        if vm:
            current_value = int(vm.group(1), 16)
            continue
        nm = re.match(r"\s*name:\s*'?(.*?)'?\s*$", line)
        if nm and current_value is not None:
            out[current_value] = nm.group(1)
            current_value = None
    return out


def http_text(url: str, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlueSnifferLookup/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace").strip()
        return text, None
    except Exception as exc:
        return None, str(exc)


def lookup_macvendors(mac: str, timeout: int) -> Dict[str, Optional[str]]:
    text, err = http_text(MACVENDORS_URL.format(mac=urllib.parse.quote(mac)), timeout)
    return {"vendor": text if text and "errors" not in text.lower() else None, "error": err}


def lookup_maclookup(mac: str, timeout: int) -> Dict[str, Optional[str]]:
    text, err = http_text(MACLOOKUP_URL.format(mac=urllib.parse.quote(mac)), timeout)
    if err:
        return {"vendor": None, "error": err}
    try:
        obj = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        return {"vendor": None, "error": str(exc)}
    return {"vendor": obj.get("company") if obj.get("found") else None, "error": None}


def lookup_iplocation(mac: str, timeout: int) -> Dict[str, Optional[str]]:
    text, err = http_text(IPLOCATION_URL.format(mac=urllib.parse.quote(mac)), timeout)
    if err:
        return {"vendor": None, "error": err}
    try:
        obj = json.loads(text or "{}")
    except json.JSONDecodeError:
        return {"vendor": None, "error": "Non-JSON response"}
    if obj is None or not isinstance(obj, dict):
        return {"vendor": None, "error": "Null/invalid JSON payload"}

    # This service commonly returns null/400 for MAC lookups.
    vendor = obj.get("company") or obj.get("isp") or None
    if not vendor:
        msg = obj.get("response_message") or "No MAC vendor data returned"
        return {"vendor": None, "error": str(msg)}
    return {"vendor": vendor, "error": None}


def parse_with_scapy(capture_path: Path, max_packets: int = 5000) -> Dict[str, object]:
    ensure_scapy()

    parsed = 0
    btle_decoded = 0
    pdu_types: Counter[str] = Counter()

    # Nordic extcap wraps BLE payload; scan for advertising Access Address bytes.
    aa_adv = b"\xd6\xbe\x89\x8e"

    reader = RawPcapNgReader(str(capture_path))
    try:
        for i, (raw, _meta) in enumerate(reader):
            if i >= max_packets:
                break
            parsed += 1
            idx = raw.find(aa_adv)
            if idx < 0:
                continue
            chunk = raw[idx:]
            try:
                pkt = BTLE(chunk)
            except Exception:
                continue
            btle_decoded += 1
            try:
                pdu_name = pkt.payload.__class__.__name__
                pdu_types[pdu_name] += 1
            except Exception:
                pdu_types["unknown"] += 1
    finally:
        reader.close()

    return {
        "packets_scanned": parsed,
        "btle_decoded": btle_decoded,
        "decoded_ratio": round((btle_decoded / parsed), 4) if parsed else 0.0,
        "scapy_top_pdu_types": pdu_types.most_common(10),
    }


def simplified(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def crosscheck_row(vendors: Dict[str, Optional[str]]) -> Dict[str, object]:
    normalized = {k: simplified(v) for k, v in vendors.items() if v}
    counts: Counter[str] = Counter(v for v in normalized.values() if v)
    consensus = counts.most_common(1)[0][0] if counts else None

    agreement = {}
    for src, val in normalized.items():
        agreement[src] = (consensus is not None and val == consensus)

    return {
        "consensus_normalized": consensus,
        "consensus_votes": counts[consensus] if consensus else 0,
        "source_agreement": agreement,
    }


def build_device_index(rows: Iterable[Dict[str, str]], max_devices: int) -> Dict[str, Dict[str, object]]:
    devices: Dict[str, Dict[str, object]] = {}

    def ensure(mac: str) -> Dict[str, object]:
        if mac not in devices:
            devices[mac] = {
                "mac": mac,
                "samples": 0,
                "pdu_types": Counter(),
                "company_ids": Counter(),
            }
        return devices[mac]

    for row in rows:
        addrs = [normalize_mac(row.get("btle.advertising_address", "")), normalize_mac(row.get("btle.initiator_address", ""))]
        addrs = [a for a in addrs if a]
        if not addrs:
            continue

        for addr in addrs:
            entry = ensure(addr)
            entry["samples"] = int(entry["samples"]) + 1
            pdu = row.get("btle.advertising_header.pdu_type", "")
            if pdu:
                entry["pdu_types"][pdu] += 1
            for cid in parse_company_ids(row.get("btcommon.eir_ad.entry.company_id", "")):
                entry["company_ids"][cid] += 1

    # Keep only most active devices.
    sorted_macs = sorted(devices.keys(), key=lambda m: int(devices[m]["samples"]), reverse=True)
    keep = set(sorted_macs[:max_devices])
    return {k: v for k, v in devices.items() if k in keep}


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture BLE samples, parse with Scapy, and cross-check MAC/company lookups")
    parser.add_argument("--interface", default=None, help="tshark interface (default: auto-detect nRF Sniffer)")
    parser.add_argument("--duration", type=int, default=60, help="capture duration in seconds (default: 60)")
    parser.add_argument("--capture", default=None, help="reuse existing capture file instead of collecting a new one")
    parser.add_argument("--max-devices", type=int, default=15, help="maximum devices to lookup (default: 15)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds for lookups (default: 10)")
    parser.add_argument("--force-refresh", action="store_true", help="refresh cached registry downloads")
    parser.add_argument("--output-json", default=None, help="output JSON path")
    args = parser.parse_args()

    ensure_scapy()

    workspace = Path(__file__).resolve().parents[1]
    cache_dir = workspace / ".cache" / "lookups"
    captures_dir = workspace / "captures"
    diagnostics_dir = workspace / "diagnostics"
    captures_dir.mkdir(parents=True, exist_ok=True)
    diagnostics_dir.mkdir(parents=True, exist_ok=True)

    if args.capture:
        capture_path = Path(args.capture).resolve()
        if not capture_path.exists():
            raise SystemExit(f"Capture file not found: {capture_path}")
    else:
        iface = args.interface or detect_nrf_interface()
        if not iface:
            raise SystemExit("Could not auto-detect nRF interface. Pass --interface explicitly.")
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        capture_path = captures_dir / f"lookup-sample-{ts}.pcapng"
        print(f"[+] Capturing {args.duration}s on {iface} -> {capture_path}")
        capture_samples(iface, args.duration, capture_path)

    print(f"[+] Parsing capture rows from {capture_path}")
    rows = extract_device_rows(capture_path)
    devices = build_device_index(rows, max_devices=args.max_devices)
    print(f"[+] Candidate devices for lookup: {len(devices)}")

    print("[+] Running Scapy packet parsing")
    scapy_stats = parse_with_scapy(capture_path)

    print("[+] Loading reference registries")
    source_errors: Dict[str, str] = {}
    try:
        ieee_map = load_ieee_oui_map(cache_dir, timeout=args.timeout, force_refresh=args.force_refresh)
    except Exception as exc:
        ieee_map = {}
        source_errors["ieee_oui"] = str(exc)
    try:
        sig_map = load_sig_company_map(cache_dir, timeout=args.timeout, force_refresh=args.force_refresh)
    except Exception as exc:
        sig_map = {}
        source_errors["bluetooth_sig_company_identifiers"] = str(exc)

    report_devices = []
    for mac, entry in sorted(devices.items(), key=lambda kv: int(kv[1]["samples"]), reverse=True):
        prefix = ":".join(mac.split(":")[:3])
        ieee_vendor = ieee_map.get(prefix)

        company_ids = sorted(entry["company_ids"].keys())
        sig_vendor = None
        if company_ids:
            # Use the most frequent company ID observed for this device.
            top_cid = max(company_ids, key=lambda cid: entry["company_ids"][cid])
            sig_vendor = sig_map.get(int(top_cid))

        macvendors = lookup_macvendors(mac, timeout=args.timeout)
        maclookup = lookup_maclookup(mac, timeout=args.timeout)
        iplocation = lookup_iplocation(mac, timeout=args.timeout)

        vendors = {
            "ieee_oui": ieee_vendor,
            "macvendors": macvendors.get("vendor"),
            "maclookup": maclookup.get("vendor"),
            "iplocation": iplocation.get("vendor"),
            "bluetooth_sig_company_id": sig_vendor,
        }

        cross = crosscheck_row(vendors)

        report_devices.append(
            {
                "mac": mac,
                "samples": entry["samples"],
                "pdu_types": dict(entry["pdu_types"].most_common()),
                "company_ids": {f"0x{cid:04x}": int(cnt) for cid, cnt in entry["company_ids"].items()},
                "lookups": {
                    "ieee_oui": {"vendor": ieee_vendor, "error": None},
                    "macvendors": macvendors,
                    "maclookup": maclookup,
                    "iplocation": iplocation,
                    "bluetooth_sig_company_id": {
                        "vendor": sig_vendor,
                        "error": None if sig_vendor else "No company ID mapped from sample",
                    },
                },
                "crosscheck": cross,
            }
        )

    report = {
        "generated_at": dt.datetime.now().isoformat(),
        "capture_path": str(capture_path),
        "device_count": len(report_devices),
        "scapy_stats": scapy_stats,
        "sources": {
            "bluetooth_sig_company_identifiers": SIG_COMPANY_YAML_URL,
            "ieee_oui": IEEE_OUI_URL,
            "macvendors": "https://api.macvendors.com/{mac}",
            "maclookup": "https://api.maclookup.app/v2/macs/{mac}",
            "iplocation": "https://api.iplocation.net/?cmd=mac&mac={mac}",
        },
        "source_errors": source_errors,
        "devices": report_devices,
    }

    out_json = Path(args.output_json).resolve() if args.output_json else diagnostics_dir / f"lookup-crosscheck-{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n=== Cross-check summary ===")
    for d in report_devices[:10]:
        vendors = d["lookups"]
        print(f"- {d['mac']} samples={d['samples']} consensus_votes={d['crosscheck']['consensus_votes']}")
        print(
            f"  IEEE={vendors['ieee_oui']['vendor']!r} | "
            f"macvendors={vendors['macvendors']['vendor']!r} | "
            f"maclookup={vendors['maclookup']['vendor']!r} | "
            f"SIG={vendors['bluetooth_sig_company_id']['vendor']!r}"
        )

    print(f"\n[+] Report written: {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
