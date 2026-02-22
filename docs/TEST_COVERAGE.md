# Rustorrent Test Coverage and Scope

## Objective
This document defines what the automated test suite currently validates for production readiness, which risks are covered by those tests, and what is intentionally left out.

The suite is designed to be deterministic and local-first: no dependency on public trackers, public DHT bootstrap nodes, or consumer-router-specific behavior.

## Current Suite Snapshot
Latest full run:

```bash
cargo test --all-features
```

Result at update time:
- `139` passed,
- `1` ignored (`soak_swarm` long-running scenario),
- `0` failed.

Total defined tests: `140`.

Breakdown:
- `127` unit tests in `src/main.rs` (including per-module test modules),
- `6` process-level adversarial integration tests in `tests/process_release_gate.rs`,
- `7` tests in `tests/soak_swarm.rs` (`1` soak ignored by default, `6` uTP helper/protocol tests).

## Hardening Implemented in This Phase
Before adding the new stress tests, runtime behavior was strengthened in three high-risk areas.

1. UI DoS hardening (`src/ui.rs`)
- Per-connection read/write timeouts.
- Absolute header/body parse deadlines to prevent slowloris byte-drip stalls.
- Maximum active UI connection slots with overload rejection (`503`).
- Stricter malformed request handling (`invalid content-length`, truncated body, invalid request line/path).

2. Inbound peer storm hardening (`src/main.rs`)
- Global inbound handler slot cap shared by TCP + uTP inbound paths.
- Capacity-based early drop under handshake/churn storms instead of unbounded per-connection thread growth.
- Limit derives from peer settings and is clamped for safety.

3. Restart/recovery hardening (`src/main.rs`)
- Session writes moved to atomic write+rename flow.
- Resume writes unified on atomic write path.
- Primary-file `.bak` sidecar creation on overwrite.
- Startup/load recovery falls back to backup for session and resume data when primary is corrupt, with restore-to-primary behavior.

## Coverage Summary by Area

| Area | Coverage Highlights |
|---|---|
| Parsing and protocol safety | bencode, torrent metainfo, peer wire messages, HTTP parser, tracker body/compact peers, uTP packet decode, MSE helpers |
| Storage and filesystem safety | multi-file offset correctness, path sanitization, out-of-bounds IO rejection, cache flush semantics, safe delete boundaries |
| Scheduler and transfer core | piece selection (rarest/sequential), priority handling, reservation/duplication behavior, block completion checks |
| UI/API behavior and auth | origin/token authorization, mutating action rejection, query parsing, status mapping, escaping/formatting invariants |
| Local deterministic fixtures | HTTP tracker fixture, UDP tracker fixture, local peer handshake fixture, local DHT fixture-node workflow |
| Adversarial process resilience | truncated/oversized frame handling, malformed extension payload handling, corrupt session/resume startup recovery |
| Newly added DoS/restart stress | slowloris-style UI request pressure, high-connection churn + malformed encrypted-handshake storm, repeated kill/restart loops with state-file validity checks |
| Fuzz entry points | `bencode::parse`, `peer::decode_message`, HTTP/tracker parser surfaces |

## Test Inventory by Module Prefix
From `cargo test --all-features -- --list` grouping:

| Prefix | Count |
|---|---:|
| `bencode` | 9 |
| `core_helpers_tests` | 15 |
| `dht` | 5 |
| `http` | 7 |
| `ip_filter` | 4 |
| `local_harness_tests` | 4 |
| `lpd` | 3 |
| `mse` | 5 |
| `natpmp` | 3 |
| `parsing_tests` | 7 |
| `peer` | 6 |
| `peer_stream` | 2 |
| `piece` | 9 |
| `sha1` | 3 |
| `storage` | 6 |
| `torrent` | 6 |
| `tracker` | 9 |
| `udp_tracker` | 3 |
| `ui` | 9 |
| `ui_progress_tests` | 2 |
| `upnp` | 4 |
| `utp` | 12 |
| Process integration tests (`tests/process_release_gate.rs`) | 6 |
| Soak integration tests (`tests/soak_swarm.rs`) | 7 |

## Security/Resilience Scenarios Added
Process-level additions in `tests/process_release_gate.rs`:

1. `process_survives_slowloris_ui_requests_and_stays_responsive`
- Holds many partial UI requests open (slowloris-style header stalls).
- Verifies `/status` remains available under pressure.

2. `process_survives_connection_churn_and_encrypted_handshake_storm`
- High-rate connect/disconnect churn.
- Mix of truncated plaintext handshake, malformed encrypted handshake prelude, and oversized post-handshake frame writes.
- Verifies process and UI remain alive.

3. `process_restart_recovery_loops_preserve_session_and_resume_files`
- Repeated forced kill/restart loops while peer churn is active.
- Validates session/resume files remain parseable bencode after abrupt termination cycles.
- Validates backup artifacts when present.

## What Is Still Left Out
The suite is broad for deterministic CI gating, but these gaps remain:

1. True end-to-end interop with public ecosystem
- Real public tracker variance, real DHT internet routing behavior, third-party client compatibility matrix.

2. Real network hardware behavior
- Router-specific UPnP/NAT-PMP behavior across consumer gateway implementations.

3. Long-duration reliability and performance characterization
- Multi-hour soak and trend baselines for memory, CPU, throughput, reconnect rates, and queue latency.

4. Full continuous fuzzing program
- Current fuzz targets exist, but long-running corpus growth/minimization and nightly fuzz infrastructure are not yet enforced as a hard gate.

5. Full data-plane restart correctness under active piece transfer
- Current restart stress validates state-file integrity under abrupt process death with active peer churn.
- It does not yet run a deterministic local seeder/leecher data-transfer loop that asserts piece-level correctness across repeated crash boundaries.

## Release-Gating Recommendations (Remaining Work)
High-value additions still recommended for a strict production gate:

1. Add deterministic transfer-grade restart harness
- Local tracker + deterministic seeder fixture that guarantees active piece flow.
- Kill/restart at randomized transfer checkpoints and assert resumed piece/accounting correctness.

2. Extend adversarial security matrix
- Add per-IP abuse scenarios (UI and inbound peer side) and verify fairness under mixed benign/malicious load.
- Add malformed extension payload families beyond current single-case probes.

3. Promote fuzzing to scheduled CI
- Persist corpus artifacts and run bounded-time fuzz jobs on every PR or nightly schedule.

4. Expand soak stage duration tiers
- Keep short CI soak, add periodic 30m/2h soak jobs with memory/error-rate thresholds and trend checks.

5. Expand platform/compiler matrix
- Keep Linux/macOS feature matrix and add compiler/channel breadth (stable/beta) when CI budget permits.

## Validation Commands
Core:

```bash
cargo test --all-features
```

Process adversarial gate only:

```bash
cargo test --all-features --test process_release_gate -- --nocapture
```

Optional soak run:

```bash
RUSTORRENT_SOAK_SECS=300 cargo test --all-features --test soak_swarm -- --ignored --nocapture
```
