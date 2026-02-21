# Backlog

Open correctness and operability items deferred from the latest hardening pass.

## 1. Capture File Size Guardrails
- Status: deferred
- Priority: medium
- Area: `scripts/capture_scapy_lookup_crosscheck.py`, `scripts/track_ble_lifecycle.py`
- Problem: live capture is bounded by duration but not output size.
- Recommendation: add `--max-filesize-kb` and pass tshark autostop filesize limit.
- Benefit: prevents unexpected disk growth on very chatty channels.

## 2. Retry Backoff + Jitter For Vendor Lookup APIs
- Status: deferred
- Priority: medium
- Area: `scripts/capture_scapy_lookup_crosscheck.py`
- Problem: API lookups use single attempts with fixed timeout.
- Recommendation: add bounded retries with exponential backoff and jitter.
- Benefit: fewer transient failures/rate-limit artifacts.

## 3. Adjustable Network Timing For Shell Download/Install Paths
- Status: deferred
- Priority: medium
- Area: `scripts/fetch_nordic_firmware.sh`, `scripts/setup_host.sh`
- Problem: curl/apt timing and retry behavior are mostly hardcoded.
- Recommendation: expose env-configurable timeout/retry controls with safe defaults.
- Benefit: better behavior on slow/flaky networks without code edits.

## 4. Stronger Atomic Update + Rollback Strategy
- Status: deferred
- Priority: medium
- Area: `scripts/fetch_nordic_firmware.sh`, `scripts/configure_tshark_extcap.sh`, `scripts/setup_host.sh`
- Problem: interrupted updates can leave partial extracted/synced state.
- Recommendation: stage to temp dirs and perform atomic swap/rename, with cleanup and rollback on failure.
- Benefit: reduces partial-install risk during interruptions.

## 5. Dataclass + Slots For Hot State Objects
- Status: deferred
- Priority: low
- Area: `scripts/track_ble_lifecycle.py`
- Problem: mutable session/device state uses regular classes with higher per-instance overhead.
- Recommendation: convert to `@dataclass(slots=True)` for `Session` and `DeviceState`.
- Benefit: lower memory overhead while preserving readability.

## 6. Avoid Re-Sorting Timeline When Already Monotonic
- Status: deferred
- Priority: low
- Area: `scripts/track_ble_lifecycle.py`
- Problem: report currently sorts each device timeline even though events are appended in frame/time order.
- Recommendation: make sort optional or skip when monotonic ordering is guaranteed.
- Benefit: lower CPU for very large timelines.

## 7. Cache Normalization Helpers In Parse Hot Paths
- Status: deferred
- Priority: low
- Area: `scripts/capture_scapy_lookup_crosscheck.py`, `scripts/track_ble_lifecycle.py`
- Problem: repeated MAC/token normalization performs duplicate regex work.
- Recommendation: add small `functools.lru_cache` wrappers around stable normalization helpers.
- Benefit: modest CPU savings on large repeated-address captures.

## 8. Centralized Runtime Profiles For Bounds/Timeouts
- Status: deferred
- Priority: low
- Area: capture + lifecycle scripts
- Problem: many tuning flags are script-specific and must be repeated per invocation.
- Recommendation: support profile/env defaults for workers, filters, limits, and timeouts.
- Benefit: easier ops tuning across hosts and automation contexts.
