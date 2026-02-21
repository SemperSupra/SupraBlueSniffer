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
import concurrent.futures
import datetime as dt
import fcntl
import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, deque
from contextlib import contextmanager
from pathlib import Path
from typing import Deque, Dict, Iterator, List, Optional, Tuple

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
LOGGER = logging.getLogger("bluesniffer.crosscheck")

STATE_DIR_NAME = "state"
CACHE_SUBDIR = "cache/lookups"
LOCKS_SUBDIR = "locks"
DEFAULT_DISPLAY_FILTER = "btle || btatt"
STDERR_RING_MAX = 200
CAPTURE_TIMEOUT_GRACE_SEC = 30
FIELD_EXTRACTION_WAIT_TIMEOUT_SEC = 120
DEFAULT_MAX_UNIQUE_DEVICES = 2000
DEFAULT_MAX_ROWS = 200000
DEFAULT_LOOKUP_WORKERS = 6


def configure_logging(level: str, quiet: bool) -> None:
    chosen = "ERROR" if quiet else level.upper()
    numeric = getattr(logging, chosen, logging.INFO)
    logging.basicConfig(level=numeric, format="%(message)s")


def run(cmd: List[str], check: bool = True, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
        timeout=timeout,
    )


def _start_stream_drain(stream: Optional[object]) -> Tuple[Deque[str], Optional[threading.Thread]]:
    lines: Deque[str] = deque(maxlen=STDERR_RING_MAX)
    if stream is None:
        return lines, None

    def _drain() -> None:
        for line in stream:  # type: ignore[operator]
            lines.append(str(line).rstrip("\n"))

    t = threading.Thread(target=_drain, daemon=True)
    t.start()
    return lines, t


@contextmanager
def capture_lock(workspace: Path, interface: str, lock_timeout: int, heartbeat_sec: int) -> Iterator[None]:
    locks_dir = workspace / STATE_DIR_NAME / LOCKS_SUBDIR
    locks_dir.mkdir(parents=True, exist_ok=True)
    key = re.sub(r"[^A-Za-z0-9_.-]", "_", interface)
    lock_path = locks_dir / f"capture-{key}.lock"

    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    start = time.monotonic()
    last = start - max(1, heartbeat_sec)
    acquired = False
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            os.ftruncate(fd, 0)
            os.write(fd, f"pid={os.getpid()} interface={interface}\n".encode("utf-8"))
            os.fsync(fd)
            break
        except BlockingIOError:
            now = time.monotonic()
            if now - start >= lock_timeout:
                os.close(fd)
                raise SystemExit(
                    f"Timed out after {lock_timeout}s waiting for capture lock on {interface}. "
                    "Another capture process may be using the sniffer."
                )
            if heartbeat_sec > 0 and now - last >= heartbeat_sec:
                waited = int(now - start)
                LOGGER.info("[~] Waiting for capture lock on %s (%ss elapsed)", interface, waited)
                last = now
            time.sleep(1)
    try:
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def ensure_scapy() -> None:
    if BTLE is None or RawPcapNgReader is None:
        raise SystemExit(
            "Scapy is required but not installed/importable. "
            f"Install with: pip3 install --user scapy\nImport error: {_SCAPY_IMPORT_ERROR}"
        )


def detect_nrf_interface() -> Optional[str]:
    cp = run(["tshark", "-D"], check=False, timeout=15)
    if cp.returncode != 0:
        return None
    for line in cp.stdout.splitlines():
        if "nRF Sniffer for Bluetooth LE" in line:
            m = re.search(r"\d+\.\s+([^\s]+)\s+\(nRF Sniffer for Bluetooth LE\)", line)
            if m:
                return m.group(1)
    return None


def capture_samples(interface: str, duration: int, capture_path: Path, heartbeat_sec: int = 5) -> None:
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
    proc = subprocess.Popen(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _stdout_lines, stdout_thread = _start_stream_drain(proc.stdout)
    stderr_lines, stderr_thread = _start_stream_drain(proc.stderr)
    timeout_sec = duration + CAPTURE_TIMEOUT_GRACE_SEC
    start = time.monotonic()
    last = start - max(1, heartbeat_sec)

    while True:
        rc = proc.poll()
        if rc is not None:
            break
        now = time.monotonic()
        if heartbeat_sec > 0 and now - last >= heartbeat_sec:
            LOGGER.info("[~] Capture running: %ss elapsed", int(now - start))
            last = now
        if now - start > timeout_sec:
            proc.kill()
            proc.wait(timeout=10)
            raise SystemExit(f"Capture timed out after {timeout_sec}s: {' '.join(cmd)}")
        time.sleep(0.2)

    if stdout_thread:
        stdout_thread.join(timeout=2)
    if stderr_thread:
        stderr_thread.join(timeout=2)
    if proc.returncode != 0:
        stderr_text = "\n".join(stderr_lines)
        raise SystemExit(
            "Capture failed.\n"
            f"Command: {' '.join(cmd)}\n"
            f"stderr:\n{stderr_text}"
        )


def parse_company_ids(value: str) -> List[int]:
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


def stream_device_index(
    capture_path: Path,
    max_rows: int,
    max_devices: int,
    max_unique_devices: int,
    heartbeat_sec: int,
    display_filter: str,
) -> Tuple[Dict[str, Dict[str, object]], int]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "btle.advertising_address",
        "btle.initiator_address",
        "btcommon.eir_ad.entry.company_id",
        "btle.advertising_header.pdu_type",
    ]
    cmd = ["tshark", "-r", str(capture_path), "-T", "fields", "-E", "separator=\t"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for field in fields:
        cmd.extend(["-e", field])

    devices: Dict[str, Dict[str, object]] = {}
    dropped_new_devices = 0

    def ensure(mac: str) -> Optional[Dict[str, object]]:
        nonlocal dropped_new_devices
        if mac not in devices:
            if max_unique_devices > 0 and len(devices) >= max_unique_devices:
                dropped_new_devices += 1
                return None
            devices[mac] = {
                "mac": mac,
                "samples": 0,
                "pdu_types": Counter(),
                "company_ids": Counter(),
            }
        return devices[mac]

    proc = subprocess.Popen(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stderr_lines, stderr_thread = _start_stream_drain(proc.stderr)
    assert proc.stdout is not None

    rows_seen = 0
    last = time.monotonic() - max(1, heartbeat_sec)
    for line in proc.stdout:
        rows_seen += 1
        parts = line.rstrip("\n").split("\t")
        parts += [""] * (len(fields) - len(parts))
        row = dict(zip(fields, parts))

        addrs = [normalize_mac(row.get("btle.advertising_address", "")), normalize_mac(row.get("btle.initiator_address", ""))]
        addrs = [a for a in addrs if a]
        if not addrs:
            continue

        pdu = row.get("btle.advertising_header.pdu_type", "")
        company_ids = parse_company_ids(row.get("btcommon.eir_ad.entry.company_id", ""))
        for addr in addrs:
            entry = ensure(addr)
            if entry is None:
                continue
            entry["samples"] = int(entry["samples"]) + 1
            if pdu:
                entry["pdu_types"][pdu] += 1
            for cid in company_ids:
                entry["company_ids"][cid] += 1

        if rows_seen >= max_rows:
            break

        now = time.monotonic()
        if heartbeat_sec > 0 and now - last >= heartbeat_sec:
            LOGGER.info("[~] Parsed %s rows (%s unique devices)", rows_seen, len(devices))
            last = now

    if proc.stdout:
        proc.stdout.close()
    try:
        rc = proc.wait(timeout=FIELD_EXTRACTION_WAIT_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
        rc = -1
        stderr_lines.append("Timed out while waiting for tshark field extraction")
    if stderr_thread:
        stderr_thread.join(timeout=2)
    stderr = "\n".join(stderr_lines)
    if rc != 0:
        raise SystemExit(f"tshark field extraction failed:\n{stderr}")

    sorted_macs = sorted(devices.keys(), key=lambda m: int(devices[m]["samples"]), reverse=True)
    keep = set(sorted_macs[:max_devices])
    return {k: v for k, v in devices.items() if k in keep}, dropped_new_devices


def load_url(url: str, cache_path: Path, timeout: int = 10, force_refresh: bool = False) -> str:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists() and not force_refresh:
        return cache_path.read_text(encoding="utf-8", errors="replace")

    req = urllib.request.Request(url, headers={"User-Agent": "SupraBlueSnifferLookup/1.0"})
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
        req = urllib.request.Request(url, headers={"User-Agent": "SupraBlueSnifferLookup/1.0"})
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


def resolve_device_lookups(mac: str, timeout: int) -> Dict[str, Dict[str, Optional[str]]]:
    return {
        "macvendors": lookup_macvendors(mac, timeout=timeout),
        "maclookup": lookup_maclookup(mac, timeout=timeout),
        "iplocation": lookup_iplocation(mac, timeout=timeout),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture BLE samples, parse with Scapy, and cross-check MAC/company lookups")
    parser.add_argument("--interface", default=None, help="tshark interface (default: auto-detect nRF Sniffer)")
    parser.add_argument("--duration", type=int, default=60, help="capture duration in seconds (default: 60)")
    parser.add_argument("--capture", default=None, help="reuse existing capture file instead of collecting a new one")
    parser.add_argument("--max-devices", type=int, default=15, help="maximum devices to lookup (default: 15)")
    parser.add_argument(
        "--max-unique-devices",
        type=int,
        default=DEFAULT_MAX_UNIQUE_DEVICES,
        help=f"cap unique devices tracked during parse; 0 disables (default: {DEFAULT_MAX_UNIQUE_DEVICES})",
    )
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds for lookups (default: 10)")
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS, help=f"cap extracted tshark rows to bound memory (default: {DEFAULT_MAX_ROWS})")
    parser.add_argument("--max-scapy-packets", type=int, default=5000, help="max packets Scapy will decode (default: 5000)")
    parser.add_argument("--lookup-workers", type=int, default=DEFAULT_LOOKUP_WORKERS, help=f"max parallel workers for external lookup APIs (default: {DEFAULT_LOOKUP_WORKERS})")
    parser.add_argument("--display-filter", default=DEFAULT_DISPLAY_FILTER, help="tshark display filter used during row extraction")
    parser.add_argument("--heartbeat-sec", type=int, default=5, help="heartbeat interval for long-running steps; 0 disables")
    parser.add_argument("--lock-timeout", type=int, default=30, help="seconds to wait for sniffer capture lock (default: 30)")
    parser.add_argument("--force-refresh", action="store_true", help="refresh cached registry downloads")
    parser.add_argument("--log-level", default=os.environ.get("BLUESNIFFER_LOG_LEVEL", "INFO"), help="log level: DEBUG, INFO, WARNING, ERROR (default: INFO)")
    parser.add_argument("--quiet", action="store_true", help="suppress non-error logging")
    parser.add_argument("--output-json", default=None, help="output JSON path")
    args = parser.parse_args()
    configure_logging(args.log_level, args.quiet)
    if args.max_unique_devices > 0 and args.max_unique_devices < args.max_devices:
        raise SystemExit("--max-unique-devices must be >= --max-devices (or set to 0 to disable)")

    ensure_scapy()

    workspace = Path(__file__).resolve().parents[1]
    cache_dir = workspace / STATE_DIR_NAME / CACHE_SUBDIR
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
        LOGGER.info("[+] Capturing %ss on %s -> %s", args.duration, iface, capture_path)
        with capture_lock(workspace, iface, lock_timeout=args.lock_timeout, heartbeat_sec=args.heartbeat_sec):
            capture_samples(iface, args.duration, capture_path, heartbeat_sec=args.heartbeat_sec)

    LOGGER.info("[+] Parsing capture rows from %s", capture_path)
    devices, dropped_new_devices = stream_device_index(
        capture_path,
        max_rows=args.max_rows,
        max_devices=args.max_devices,
        max_unique_devices=args.max_unique_devices,
        heartbeat_sec=args.heartbeat_sec,
        display_filter=args.display_filter,
    )
    LOGGER.info("[+] Candidate devices for lookup: %s", len(devices))
    if dropped_new_devices > 0:
        LOGGER.warning("[~] Unique-device cap reached; ignored %s new device observations", dropped_new_devices)

    LOGGER.info("[+] Running Scapy packet parsing")
    scapy_stats = parse_with_scapy(capture_path, max_packets=args.max_scapy_packets)

    LOGGER.info("[+] Loading reference registries")
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

    sorted_devices = sorted(devices.items(), key=lambda kv: int(kv[1]["samples"]), reverse=True)
    lookup_results: Dict[str, Dict[str, Dict[str, Optional[str]]]] = {}
    workers = max(1, args.lookup_workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_mac = {pool.submit(resolve_device_lookups, mac, args.timeout): mac for mac, _entry in sorted_devices}
        for future in concurrent.futures.as_completed(future_to_mac):
            mac = future_to_mac[future]
            try:
                lookup_results[mac] = future.result()
            except Exception as exc:
                err = str(exc)
                lookup_results[mac] = {
                    "macvendors": {"vendor": None, "error": err},
                    "maclookup": {"vendor": None, "error": err},
                    "iplocation": {"vendor": None, "error": err},
                }

    report_devices = []
    for mac, entry in sorted_devices:
        prefix = ":".join(mac.split(":")[:3])
        ieee_vendor = ieee_map.get(prefix)

        company_ids = sorted(entry["company_ids"].keys())
        sig_vendor = None
        if company_ids:
            top_cid = max(company_ids, key=lambda cid: entry["company_ids"][cid])
            sig_vendor = sig_map.get(int(top_cid))

        macvendors = lookup_results[mac]["macvendors"]
        maclookup = lookup_results[mac]["maclookup"]
        iplocation = lookup_results[mac]["iplocation"]

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
        "parse_limits": {
            "max_rows": args.max_rows,
            "max_devices": args.max_devices,
            "max_unique_devices": args.max_unique_devices,
            "dropped_new_devices": dropped_new_devices,
            "display_filter": args.display_filter,
        },
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

    LOGGER.info("\n=== Cross-check summary ===")
    for dev in report_devices[:10]:
        lookups = dev["lookups"]
        LOGGER.info("- %s samples=%s consensus_votes=%s", dev["mac"], dev["samples"], dev["crosscheck"]["consensus_votes"])
        LOGGER.info(
            "  IEEE=%r | macvendors=%r | maclookup=%r | SIG=%r",
            lookups["ieee_oui"]["vendor"],
            lookups["macvendors"]["vendor"],
            lookups["maclookup"]["vendor"],
            lookups["bluetooth_sig_company_id"]["vendor"],
        )

    LOGGER.info("\n[+] Report written: %s", out_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
