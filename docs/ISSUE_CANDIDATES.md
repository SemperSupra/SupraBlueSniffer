# Issue Candidates

Ready-to-file issues for future work once this workspace is connected to a GitHub remote.

## Security

### 1. Remove `eval` from firmware state parsing
- Category: `security`
- Priority: high
- Area: `scripts/fetch_nordic_firmware.sh`
- Problem: script still uses `eval "$state"` when reading state output.
- Why it matters: `eval` can execute unexpected content if upstream output is malformed or tampered with.
- Proposed fix:
  - Replace with strict key/value parsing loop (same pattern used elsewhere).
  - Ignore unknown keys and treat malformed lines as errors.
- Acceptance criteria:
  - No `eval` usage remains in project scripts.
  - Existing behavior preserved for normal state output.
  - Lint/tests pass.

### 2. Harden firmware/extcap download trust model
- Category: `security`
- Priority: high
- Areas: `scripts/fetch_nordic_firmware.sh`, `scripts/setup_host.sh`
- Problem: URL patterns and checksums are partly hardcoded, but there is no strict trust policy mode.
- Why it matters: supply-chain integrity and tamper resistance.
- Proposed fix:
  - Add strict mode requiring known checksums and allowlisted hosts.
  - Add explicit failure mode for unknown artifacts.
- Acceptance criteria:
  - Strict mode blocks unknown URL/hash combinations.
  - Non-strict mode remains available for usability.
  - Docs explain trade-offs.

### 3. Add diagnostics redaction mode
- Category: `security`
- Priority: medium
- Area: `scripts/collect_diagnostics.sh`
- Problem: diagnostics may include serials/user/environment details.
- Why it matters: safer log sharing.
- Proposed fix:
  - Add `--redact` option to mask usernames, serial numbers, and local paths.
- Acceptance criteria:
  - Redacted report still useful for debugging.
  - Default behavior unchanged.

## Reliability

### 4. Atomic staged install + rollback for firmware/extcap
- Category: `reliability`
- Priority: high
- Areas: `scripts/fetch_nordic_firmware.sh`, `scripts/configure_tshark_extcap.sh`, `scripts/setup_host.sh`
- Problem: interrupted updates can leave partial state.
- Why it matters: failed installs should not leave broken runtime.
- Proposed fix:
  - Stage in temp directories.
  - Verify before swap.
  - Use atomic rename/symlink swap and cleanup on failure.
- Acceptance criteria:
  - Simulated interruption does not corrupt active install.
  - Repeat runs recover cleanly.

### 5. Add explicit interface-busy preflight for capture scripts
- Category: `reliability`
- Priority: medium
- Areas: capture/lifecycle scripts
- Problem: locking exists, but preflight messaging can be clearer across all entry points.
- Why it matters: faster diagnosis of contention.
- Proposed fix:
  - Centralize lock + preflight helper and consistent error output.
- Acceptance criteria:
  - All capture paths fail fast with clear busy guidance.

## Testing

### 6. Add Python unit tests for parsers and reducers
- Category: `testing`
- Priority: high
- Areas: `scripts/capture_scapy_lookup_crosscheck.py`, `scripts/track_ble_lifecycle.py`
- Problem: core logic is not currently unit-tested with fixtures.
- Why it matters: parser/regression confidence.
- Proposed fix:
  - Add fixture-based tests for row parsing, aggregation, timeline, and crosscheck logic.
- Acceptance criteria:
  - Deterministic tests pass without hardware.
  - Edge cases (malformed rows, empty capture) covered.

### 7. Add shell integration tests with mocked commands
- Category: `testing`
- Priority: high
- Areas: shell scripts under `scripts/`
- Problem: shell workflows are validated mostly manually.
- Why it matters: protect idempotency and failure-path behavior.
- Proposed fix:
  - Add a lightweight harness with stubs for `curl`, `tshark`, `udevadm`, `nrfjprog`, etc.
- Acceptance criteria:
  - Key branches (happy path + failures) exercised in CI-friendly mode.

### 8. Add lock contention and timeout regression tests
- Category: `testing`
- Priority: medium
- Areas: capture/lifecycle scripts
- Problem: concurrency/timeout behavior currently verified manually.
- Why it matters: avoid regressions in liveness and lock handling.
- Proposed fix:
  - Add tests that spawn competing processes and assert timeout/error semantics.
- Acceptance criteria:
  - Deterministic pass/fail in local/CI environments.

## Performance

### 9. Add capture filesize guardrails
- Category: `performance`
- Priority: medium
- Areas: capture/lifecycle scripts
- Problem: duration is bounded, filesize is not.
- Why it matters: disk usage predictability under noisy RF environments.
- Proposed fix:
  - Add `--max-filesize-kb` and wire to tshark autostop.
- Acceptance criteria:
  - Capture stops at whichever limit is hit first (duration/filesize).

### 10. Add retry backoff+jitter for external lookup APIs
- Category: `performance`
- Priority: medium
- Area: crosscheck script
- Problem: single-shot lookups fail on transient network/rate-limit events.
- Why it matters: runtime stability and fewer false-negative results.
- Proposed fix:
  - Add bounded retries with exponential backoff and jitter.
- Acceptance criteria:
  - Retries are configurable and bounded.
  - Error reporting remains clear and source-specific.

## Ops / Maintainability

### 11. Add centralized runtime profile support
- Category: `ops`
- Priority: low
- Areas: capture/lifecycle scripts
- Problem: many tuning flags must be repeated manually.
- Why it matters: consistent behavior across machines/automation.
- Proposed fix:
  - Support profile/env defaults for limits/timeouts/workers/filters.
- Acceptance criteria:
  - CLI flags still override profile values.
  - Profile file format documented.
