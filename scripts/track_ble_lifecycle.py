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
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

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
    def __init__(self, mac: str):
        self.mac = mac
        self.discovery_started = False
        self.discovery_frame: Optional[int] = None
        self.discovery_ts: Optional[float] = None
        self.last_seen_ts: Optional[float] = None
        self.scan_req_count = 0
        self.scan_rsp_count = 0
        self.connect_req_count = 0
        self.sessions: List[Session] = []
        self.timeline: List[Dict[str, object]] = []


def run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def detect_nrf_interface() -> Optional[str]:
    cp = run(["tshark", "-D"], check=False)
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


def parse_rows(capture: Optional[Path], interface: Optional[str], duration: int) -> List[Dict[str, str]]:
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

    cmd += ["-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]

    cp = run(cmd, check=False)
    if cp.returncode != 0:
        raise SystemExit(f"tshark failed:\n{cp.stderr}")

    rows = []
    for line in cp.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(fields) - len(parts))
        row = dict(zip(fields, parts))
        rows.append(row)
    return rows


def add_event(device: DeviceState, ts: float, frame: int, event: str, details: Dict[str, object]) -> None:
    payload = {
        "time": dt.datetime.fromtimestamp(ts).isoformat(),
        "frame": frame,
        "event": event,
        "details": details,
    }
    device.timeline.append(payload)


def track(rows: List[Dict[str, str]], target_mac: Optional[str]) -> Dict[str, DeviceState]:
    devices: Dict[str, DeviceState] = {}
    active_sessions: List[Session] = []

    def get_device(mac: str) -> DeviceState:
        if mac not in devices:
            devices[mac] = DeviceState(mac)
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

        # Map LL/ATT lifecycle to latest active session(s).
        if llid or ctrl or att_opcode:
            for s in list(active_sessions):
                d = get_device(s.mac)
                if target_mac and d.mac != target_mac:
                    continue

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
    args = parser.parse_args()

    target = normalize_mac(args.target) if args.target else None

    capture_path = Path(args.capture).resolve() if args.capture else None
    if capture_path and not capture_path.exists():
        raise SystemExit(f"Capture file not found: {capture_path}")

    interface = args.interface
    if not capture_path and not interface:
        interface = detect_nrf_interface()
        if not interface:
            raise SystemExit("Could not auto-detect nRF interface. Pass --interface.")

    rows = parse_rows(capture_path, interface, args.duration)
    devices = track(rows, target)
    report = summarize(devices)

    print("=== BLE Lifecycle Summary ===")
    for d in report["devices"]:
        print(
            f"- {d['mac']} discovery={d['discovery_started']} scan_req={d['scan_req_count']} "
            f"scan_rsp={d['scan_rsp_count']} connect_req={d['connect_req_count']} "
            f"sessions={d['sessions_total']} terminated={d['sessions_terminated']} att={d['att_packets']}"
        )

    if args.output_json:
        out = Path(args.output_json).resolve()
    else:
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path("workspace/diagnostics") / f"lifecycle-{ts}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Report written: {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
