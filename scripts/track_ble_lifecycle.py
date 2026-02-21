#!/usr/bin/env python3
"""
Detect BLE discovery-mode devices and track lifecycle events from tshark output.

Lifecycle signals used:
- Discovery mode start: first connectable advertising PDU from a device
- Scan interaction: SCAN_REQ / SCAN_RSP
- Connection request: CONNECT_IND / AUX_CONNECT_REQ
- Connected traffic: first LL data/control after connect request
- ATT activity: btatt frames while session active
- Termination: LL_TERMINATE_IND control opcode
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import logging
import os
import re
import subprocess
import threading
import time
from collections import deque
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Deque, Dict, Iterable, Iterator, List, Optional, Tuple

ADV_PDU_NAMES = {
    "0x00": "ADV_IND",
    "0x01": "ADV_DIRECT_IND",
    "0x02": "ADV_NONCONN_IND",
    "0x03": "SCAN_REQ",
    "0x04": "SCAN_RSP",
    "0x05": "CONNECT_IND",
    "0x06": "ADV_SCAN_IND",
    "0x07": "ADV_EXT_IND",
    "0x08": "AUX_CONNECT_REQ",
}

CONNECTABLE_ADV_PDUS = {"0x00", "0x01", "0x06", "0x07"}
CONNECT_REQ_PDUS = {"0x05", "0x08"}
LL_TERMINATE_IND = "0x02"
LOGGER = logging.getLogger("bluesniffer.lifecycle")
STATE_DIR_NAME = "state"
LOCKS_SUBDIR = "locks"
DEFAULT_DISPLAY_FILTER = "btle || btatt"
STDERR_RING_MAX = 200
CAPTURE_TIMEOUT_GRACE_SEC = 30
OFFLINE_MIN_WAIT_TIMEOUT_SEC = 300
ONLINE_MIN_WAIT_TIMEOUT_SEC = 30
DEFAULT_MAX_ROWS = 300000
DEFAULT_MAX_EVENTS_PER_DEVICE = 2000


def configure_logging(level: str, quiet: bool) -> None:
    chosen = "ERROR" if quiet else level.upper()
    numeric = getattr(logging, chosen, logging.INFO)
    logging.basicConfig(level=numeric, format="%(message)s")


class Session:
    def __init__(self, mac: str, frame: int, ts: float, initiator: Optional[str]):
        self.mac = mac
        self.connect_req_frame = frame
        self.connect_req_ts = ts
        self.initiator = initiator
        self.connected_data_started = False
        self.att_packets = 0
        self.terminated = False
        self.terminate_frame: Optional[int] = None
        self.terminate_ts: Optional[float] = None


class DeviceState:
    def __init__(self, mac: str, max_events: int):
        self.mac = mac
        self.max_events = max_events
        self.dropped_events = 0
        self.discovery_started = False
        self.discovery_frame: Optional[int] = None
        self.discovery_ts: Optional[float] = None
        self.last_seen_ts: Optional[float] = None
        self.scan_req_count = 0
        self.scan_rsp_count = 0
        self.connect_req_count = 0
        self.sessions: List[Session] = []
        self.timeline: List[Dict[str, object]] = []


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


def normalize_mac(s: str) -> Optional[str]:
    if not s:
        return None
    m = re.findall(r"[0-9a-fA-F]{2}", s)
    if len(m) != 6:
        return None
    return ":".join(x.lower() for x in m)


def first_token(val: str) -> str:
    if not val:
        return ""
    return re.split(r"[,;\s]+", val.strip())[0]


def parse_rows(
    capture: Optional[Path],
    interface: Optional[str],
    duration: int,
    max_rows: int = DEFAULT_MAX_ROWS,
    parse_timeout_sec: int = 0,
    no_parse_timeout: bool = False,
    heartbeat_sec: int = 5,
    display_filter: str = DEFAULT_DISPLAY_FILTER,
) -> Iterable[Dict[str, str]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "btle.advertising_header.pdu_type",
        "btle.advertising_address",
        "btle.initiator_address",
        "btle.data_header.llid",
        "btle.control_opcode",
        "btatt.opcode",
        "btatt.handle",
    ]
    cmd = ["tshark", "-l", "-n"]
    if capture:
        cmd += ["-r", str(capture)]
    else:
        if not interface:
            raise SystemExit("No interface provided and auto-detection failed")
        cmd += ["-i", interface, "-a", f"duration:{duration}"]
    if display_filter:
        cmd += ["-Y", display_filter]

    cmd += ["-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]

    proc = subprocess.Popen(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stderr_lines, stderr_thread = _start_stream_drain(proc.stderr)
    assert proc.stdout is not None
    seen = 0
    last = time.monotonic() - max(1, heartbeat_sec)
    for line in proc.stdout:
        parts = line.rstrip("\n").split("\t")
        parts += [""] * (len(fields) - len(parts))
        row = dict(zip(fields, parts))
        yield row
        seen += 1
        if seen >= max_rows:
            break
        now = time.monotonic()
        if heartbeat_sec > 0 and now - last >= heartbeat_sec:
            LOGGER.info("[~] Lifecycle parser processed %s rows", seen)
            last = now

    if proc.stdout:
        proc.stdout.close()
    wait_timeout: Optional[int]
    if no_parse_timeout:
        wait_timeout = None
    elif parse_timeout_sec > 0:
        wait_timeout = parse_timeout_sec
    elif capture:
        wait_timeout = max(OFFLINE_MIN_WAIT_TIMEOUT_SEC, duration + CAPTURE_TIMEOUT_GRACE_SEC)
    else:
        wait_timeout = max(ONLINE_MIN_WAIT_TIMEOUT_SEC, duration + CAPTURE_TIMEOUT_GRACE_SEC)

    try:
        rc = proc.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
        rc = -1
        stderr_lines.append(f"Timed out waiting for tshark completion after {wait_timeout}s")
    if stderr_thread:
        stderr_thread.join(timeout=2)
    stderr = "\n".join(stderr_lines)
    if rc != 0:
        raise SystemExit(f"tshark failed:\n{stderr}")


def add_event(device: DeviceState, ts: float, frame: int, event: str, details: Dict[str, object]) -> None:
    payload = {
        "time": dt.datetime.fromtimestamp(ts).isoformat(),
        "frame": frame,
        "event": event,
        "details": details,
    }
    if len(device.timeline) < device.max_events:
        device.timeline.append(payload)
    else:
        device.dropped_events += 1


def track(rows: Iterable[Dict[str, str]], target_mac: Optional[str], max_events_per_device: int) -> Dict[str, DeviceState]:
    devices: Dict[str, DeviceState] = {}
    active_sessions: List[Session] = []

    def get_device(mac: str) -> DeviceState:
        if mac not in devices:
            devices[mac] = DeviceState(mac, max_events=max_events_per_device)
        return devices[mac]

    for row in rows:
        try:
            frame = int(first_token(row.get("frame.number", "0") or "0"))
        except ValueError:
            continue
        try:
            ts = float(first_token(row.get("frame.time_epoch", "0") or "0"))
        except ValueError:
            continue

        pdu = first_token((row.get("btle.advertising_header.pdu_type") or "").lower())
        adv = normalize_mac(first_token(row.get("btle.advertising_address", "")))
        init = normalize_mac(first_token(row.get("btle.initiator_address", "")))
        llid = first_token((row.get("btle.data_header.llid") or "").lower())
        ctrl = first_token((row.get("btle.control_opcode") or "").lower())
        att_opcode = first_token((row.get("btatt.opcode") or "").lower())

        if adv:
            if target_mac and adv != target_mac:
                pass
            else:
                d = get_device(adv)
                d.last_seen_ts = ts

                if pdu in CONNECTABLE_ADV_PDUS and not d.discovery_started:
                    d.discovery_started = True
                    d.discovery_frame = frame
                    d.discovery_ts = ts
                    add_event(
                        d,
                        ts,
                        frame,
                        "DISCOVERY_MODE_START",
                        {"pdu": ADV_PDU_NAMES.get(pdu, pdu)},
                    )

                if pdu == "0x03":
                    d.scan_req_count += 1
                    add_event(d, ts, frame, "SCAN_REQ", {"initiator": init})

                if pdu == "0x04":
                    d.scan_rsp_count += 1
                    add_event(d, ts, frame, "SCAN_RSP", {})

                if pdu in CONNECT_REQ_PDUS:
                    d.connect_req_count += 1
                    s = Session(adv, frame, ts, init)
                    d.sessions.append(s)
                    active_sessions.append(s)
                    add_event(
                        d,
                        ts,
                        frame,
                        "CONNECT_REQUEST",
                        {"pdu": ADV_PDU_NAMES.get(pdu, pdu), "initiator": init},
                    )

        # Map LL/ATT lifecycle only when session ownership is unambiguous.
        if llid or ctrl or att_opcode:
            candidates = [s for s in active_sessions if (not target_mac or s.mac == target_mac)]
            if len(candidates) == 1:
                s = candidates[0]
                d = get_device(s.mac)

                if not s.connected_data_started and (llid or ctrl):
                    s.connected_data_started = True
                    add_event(d, ts, frame, "CONNECTED_DATA_START", {"llid": llid or None, "control_opcode": ctrl or None})

                if att_opcode:
                    s.att_packets += 1
                    add_event(d, ts, frame, "ATT_ACTIVITY", {"att_opcode": att_opcode})

                if ctrl == LL_TERMINATE_IND and not s.terminated:
                    s.terminated = True
                    s.terminate_frame = frame
                    s.terminate_ts = ts
                    add_event(d, ts, frame, "TERMINATED", {"control_opcode": ctrl})
                    active_sessions.remove(s)

    # Close still-open sessions at end-of-capture.
    for mac, d in devices.items():
        for s in d.sessions:
            if not s.terminated:
                add_event(
                    d,
                    d.last_seen_ts or s.connect_req_ts,
                    s.connect_req_frame,
                    "CAPTURE_END_WITH_ACTIVE_SESSION",
                    {"initiator": s.initiator, "att_packets": s.att_packets},
                )

    return devices


def summarize(devices: Dict[str, DeviceState]) -> Dict[str, object]:
    out = []
    for mac, d in sorted(devices.items(), key=lambda kv: (kv[1].discovery_ts or 0.0), reverse=False):
        sessions_total = len(d.sessions)
        sessions_terminated = sum(1 for s in d.sessions if s.terminated)
        att_total = sum(s.att_packets for s in d.sessions)

        out.append(
            {
                "mac": mac,
                "discovery_started": d.discovery_started,
                "discovery_time": dt.datetime.fromtimestamp(d.discovery_ts).isoformat() if d.discovery_ts else None,
                "scan_req_count": d.scan_req_count,
                "scan_rsp_count": d.scan_rsp_count,
                "connect_req_count": d.connect_req_count,
                "sessions_total": sessions_total,
                "sessions_terminated": sessions_terminated,
                "att_packets": att_total,
                "timeline_truncated_events": d.dropped_events,
                "timeline": sorted(d.timeline, key=lambda e: (e["time"], e["frame"])),
            }
        )
    return {"devices": out, "device_count": len(out)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect BLE discovery mode and track lifecycle")
    parser.add_argument("--interface", default=None, help="tshark interface (default auto-detect nRF)")
    parser.add_argument("--duration", type=int, default=60, help="live capture duration (seconds)")
    parser.add_argument("--capture", default=None, help="offline capture file to analyze")
    parser.add_argument("--target", default=None, help="target device MAC (optional)")
    parser.add_argument("--output-json", default=None, help="write JSON report path")
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS, help=f"cap processed tshark rows to bound memory (default: {DEFAULT_MAX_ROWS})")
    parser.add_argument(
        "--max-events-per-device",
        type=int,
        default=DEFAULT_MAX_EVENTS_PER_DEVICE,
        help=f"cap stored timeline events per device (default: {DEFAULT_MAX_EVENTS_PER_DEVICE})",
    )
    parser.add_argument("--parse-timeout-sec", type=int, default=0, help="timeout waiting for tshark completion; 0 = auto")
    parser.add_argument("--no-parse-timeout", action="store_true", help="disable tshark completion timeout")
    parser.add_argument("--display-filter", default=DEFAULT_DISPLAY_FILTER, help="tshark display filter for lifecycle extraction")
    parser.add_argument("--heartbeat-sec", type=int, default=5, help="heartbeat interval for long-running steps; 0 disables")
    parser.add_argument("--lock-timeout", type=int, default=30, help="seconds to wait for sniffer capture lock (default: 30)")
    parser.add_argument("--log-level", default=os.environ.get("BLUESNIFFER_LOG_LEVEL", "INFO"), help="log level: DEBUG, INFO, WARNING, ERROR (default: INFO)")
    parser.add_argument("--quiet", action="store_true", help="suppress non-error logging")
    args = parser.parse_args()
    configure_logging(args.log_level, args.quiet)

    target = normalize_mac(args.target) if args.target else None

    capture_path = Path(args.capture).resolve() if args.capture else None
    if capture_path and not capture_path.exists():
        raise SystemExit(f"Capture file not found: {capture_path}")

    interface = args.interface
    if not capture_path and not interface:
        interface = detect_nrf_interface()
        if not interface:
            raise SystemExit("Could not auto-detect nRF interface. Pass --interface.")
    workspace = Path(__file__).resolve().parents[1]
    lock_cm = nullcontext()
    if not capture_path and interface:
        lock_cm = capture_lock(workspace, interface, lock_timeout=args.lock_timeout, heartbeat_sec=args.heartbeat_sec)

    with lock_cm:
        rows = parse_rows(
            capture_path,
            interface,
            args.duration,
            max_rows=args.max_rows,
            parse_timeout_sec=args.parse_timeout_sec,
            no_parse_timeout=args.no_parse_timeout,
            heartbeat_sec=args.heartbeat_sec,
            display_filter=args.display_filter,
        )
        devices = track(rows, target, max_events_per_device=args.max_events_per_device)
    report = summarize(devices)

    LOGGER.info("=== BLE Lifecycle Summary ===")
    for d in report["devices"]:
        LOGGER.info(
            "- %s discovery=%s scan_req=%s scan_rsp=%s connect_req=%s sessions=%s terminated=%s att=%s",
            d["mac"],
            d["discovery_started"],
            d["scan_req_count"],
            d["scan_rsp_count"],
            d["connect_req_count"],
            d["sessions_total"],
            d["sessions_terminated"],
            d["att_packets"],
        )

    if args.output_json:
        out = Path(args.output_json).resolve()
    else:
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path("workspace/diagnostics") / f"lifecycle-{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    LOGGER.info("[+] Report written: %s", out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
