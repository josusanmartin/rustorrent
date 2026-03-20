# Deep Audit Report

Date: 2026-03-20

Branch audited: `codex/macos-standalone-ui`

Baseline compared against: `origin/master` at the start of the audit.

## Scope

This audit focused on the current working tree plus the large branch delta already present on `codex/macos-standalone-ui`, with emphasis on:

- launcher and packaged macOS startup
- peer protocol and encryption handshake correctness
- transfer scheduling and UI rate reporting
- search runtime startup, plugin install, and query flow
- broad regression validation through the existing unit/process/soak suites

## Validation Performed

Rust validation:

- `cargo test --all-features --quiet -- --test-threads=1`
  - result: pass
  - totals observed: 210 unit tests passed, 6 process tests passed, 11 non-ignored higher-level tests passed, 1 ignored

Focused validation:

- `cargo test --all-features mse::tests::mse_initiate_accept_roundtrip_over_tcp -- --nocapture`
  - result: pass
- `cargo test --all-features search -- --nocapture`
  - result: pass
- `cargo test --all-features ui::tests::search -- --nocapture`
  - result: pass

macOS validation:

- `xcrun --sdk macosx swiftc -parse-as-library -O macos/Launcher.swift -o /tmp/rustorrent-launcher-audit-final`
  - result: pass
- `bash macos/package_app.sh --dmg`
  - result: pass

End-to-end search validation:

- fresh UI startup against a temporary download dir
- live catalog fetch via `/search/catalog?refresh=1`
- plugin install via `/search/install-url`
- live query execution via `/search/run`
  - result: pass

Packaged-app validation:

- mounted DMG binary (`rustorrent-bin`) launched directly from `/Volumes/Rustorrent/...`
  - result: pass
  - UI port bound and `/api-token` responded
- mounted DMG app (`Rustorrent.app`) launched via Swift launcher
  - result: fail
  - launcher-only startup issue remains open

## Findings

### Fixed

P1: MSE initiator/responder dropped already-read encrypted bytes.

- Files: [src/mse.rs](/Users/josu/dev/rust/rustorrent/src/mse.rs), [src/peer_stream.rs](/Users/josu/dev/rust/rustorrent/src/peer_stream.rs), [src/main.rs](/Users/josu/dev/rust/rustorrent/src/main.rs)
- Impact: encrypted peer sessions could deadlock or corrupt framing when handshake and follow-up payload bytes arrived in the same read.
- Evidence: `mse::tests::mse_initiate_accept_roundtrip_over_tcp` was hanging before the fix.
- Resolution: preserved buffered bytes on both accept and initiate paths and threaded buffered plaintext through `PeerStream`.

P1: Branch no longer compiled because `peer::Message` grew BEP 6 variants and debug summary handling was non-exhaustive.

- File: [src/main.rs](/Users/josu/dev/rust/rustorrent/src/main.rs)
- Impact: `cargo test --all-features` failed immediately.
- Resolution: added coverage for `SuggestPiece`, `HaveAll`, `HaveNone`, `RejectRequest`, and `AllowedFast`.

P2: Search startup became vulnerable to a misleading empty/uninitialized-looking state after moving initialization off the main path.

- Files: [src/search.rs](/Users/josu/dev/rust/rustorrent/src/search.rs), [src/main.rs](/Users/josu/dev/rust/rustorrent/src/main.rs), [src/ui.rs](/Users/josu/dev/rust/rustorrent/src/ui.rs)
- Impact: search could appear “broken” because the UI would come up before plugin refresh and show an empty panel with weak messaging.
- Resolution: split search into synchronous `prepare()` plus background plugin refresh, and improved the UI’s empty-plugin messaging.

P2: Session transfer card and graph were exaggerating rate spikes compared with actual per-torrent rates.

- File: [src/main.rs](/Users/josu/dev/rust/rustorrent/src/main.rs)
- Impact: operator perception of throughput was noisier than the worker-level rate state.
- Resolution: session-level graph/rates now aggregate smoothed per-torrent rates.

P2: Delete action in the embedded macOS app relied on JavaScript dialogs that the launcher did not implement.

- File: [macos/Launcher.swift](/Users/josu/dev/rust/rustorrent/macos/Launcher.swift)
- Impact: delete confirmation could fail silently inside the embedded `WKWebView`.
- Resolution: implemented native `WKUIDelegate` alert/confirm/text-input handlers.

### Still Open

P1: Mounted-DMG Swift launcher path is still not reliable.

- File: [macos/Launcher.swift](/Users/josu/dev/rust/rustorrent/macos/Launcher.swift)
- Symptom: launching `Rustorrent.app` directly from the mounted DMG volume can stall before the backend/UI become reachable on `127.0.0.1:9473`.
- Important distinction: the mounted binary itself works when run directly from `/Volumes/Rustorrent/.../rustorrent-bin`; the failure is launcher-only.
- Practical impact: installed app path is not implicated by this audit result, but the “run directly from mounted DMG” path is not yet signed off.

P3: There are still a number of non-fatal dead-code warnings in tracker/udp tracker scrape helpers.

- Files: [src/tracker.rs](/Users/josu/dev/rust/rustorrent/src/tracker.rs), [src/udp_tracker.rs](/Users/josu/dev/rust/rustorrent/src/udp_tracker.rs)
- Impact: no functional regression found, but warning noise reduces signal during validation.

## Search Audit Result

Search is functional.

What was verified:

- startup status endpoint responds correctly
- live catalog download works
- plugin installation from URL works
- installed plugin capabilities refresh works
- live search query execution returns results

What changed:

- search initialization is now split into a synchronous prepare step and an async plugin refresh
- empty plugin state is explicitly surfaced to the UI instead of looking like a silent failure

## Packaging Audit Result

What is verified:

- release binary build works
- DMG creation works
- mounted `rustorrent-bin` works directly from the DMG and serves the local UI

What is not yet signed off:

- mounted `Rustorrent.app` via the Swift launcher still has a launcher-only readiness issue in local testing

## Recommended Next Actions

1. Finish the DMG launcher audit by instrumenting `macos/Launcher.swift` more aggressively around `startBackendIfNeeded()` and child-process lifetime, then re-run the mounted-DMG path until it is deterministic.
2. Reduce warning noise in tracker scrape helpers so future audits fail louder on real regressions.
3. Add an automated release-check script that verifies:
   - full Rust suite
   - Swift launcher compile
   - DMG build
   - mounted binary bind on a test UI port

