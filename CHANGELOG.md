# Changelog

All notable protocol, security, and public-interface changes to rtc2tcp are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are not assigned until the first tagged release.

## [Unreleased]

### Added (UX)
- `--socks5` flag on `rtc2tcp-peer expose` and `rtc2tcp-peer connect`. When both peers set this flag the tunnel becomes a dynamic SOCKS5 proxy: the connect-side listener accepts SOCKS5 `CONNECT` requests (RFC 1928, no-auth, IPv4 / IPv6 / FQDN), opens a multiplexed DataChannel per connection with the target encoded in the channel label, and the expose peer dials the requested host. Multiple connections are served concurrently over the same WebRTC session. No `--target` is required on the expose side.
- Branded startup banner with version/commit stamp and attribution (`haltman.io`, source URL). Suppressible via `-q`/`--quiet`/`--silent`; colour disabled on non-TTY, `NO_COLOR`, or `--no-color`.
- `rtc2tcp://TOKEN:SECRET@HOST[:PORT]` connection-string format. `rtc2tcp-peer expose` auto-generates a 128-bit rendezvous token and a 128-bit pairing secret when the operator does not provide them, and prints the exact `rtc2tcp-peer connect rtc2tcp://…` command the remote peer should run. `connect` accepts the connection string as a positional argument or via `--connection`.
- Short aliases for every major flag: `-t`/`--rendezvous-token`, `-s`/`--pairing-secret`, `-b`/`--broker`, `-T`/`--target`, `-l`/`--listen`, `-q`/`--quiet`, `-V`/`--version`.
- Pretty, coloured help menu on both binaries.

### Changed (UX)
- `rtc2tcp-peer expose` now validates `--target` before the banner and credential auto-generation run, so a missing target produces one clean error instead of a generated-credentials block followed by a late failure.

### Added (release)
- Release workflow now produces per-platform archives (`.tar.gz` on Unix, `.zip` on Windows) that bundle the two binaries alongside `README.md`, `LICENSE`, `SECURITY.md`, `PROTOCOL.md`, and `CHANGELOG.md`. Each archive ships with its own `.sha256` file in addition to the aggregate `SHA256SUMS` that cosign signs.
- Release workflow is fully automatic: every push to `main` parses commit subjects as [Conventional Commits](https://www.conventionalcommits.org/), computes the next [semantic version](https://semver.org) (`feat!:`/`BREAKING CHANGE:` → major, `feat:` → minor, `fix:`/`perf:`/`refactor:`/`revert:` → patch, everything else → skip), and cuts a signed GitHub Release with cross-platform binaries. Manual version pinning available via `workflow_dispatch` with a `version` input.

### Changed (security-critical)
- Peer authentication is now a balanced CPACE-Ristretto255 PAKE, sourced from `github.com/cloudflare/circl/group`. The default scheme identifier is `rtc2tcp-auth/cpace-ristretto255-v2`. The previous transitional ECDH scheme (`rtc2tcp-auth/interactive-ecdh-v2a`) is retained compiled in for rollout compatibility and refused structurally by CPACE-configured peers via the wire-level scheme-pin check.
- The broker now sees the pairing secret only through its effect on session timing; the secret is no longer committed to the broker via any hash derivation. The rendezvous token is operator-supplied and independent of the pairing secret.

### Added
- `PROTOCOL.md` pins the Milestone 2 wire format, transcript, state machine, key schedule, and error surface byte-for-byte.
- End-to-end pion-loopback tests for the full interactive handshake (happy path and wrong-secret path).
- Parametric unit tests that run the round-trip against both the CPACE and transitional schemes.
- Downgrade-refusal test that locks in CPACE peers rejecting the transitional scheme.
- Tunnel bridge backpressure via `OnBufferedAmountLow` / high-water threshold.
- Tunnel bridge wires `dc.OnError` so SCTP-level failures tear the pair down.

### Fixed
- Expose-side target TCP dial is now non-blocking with respect to pion's callback dispatcher.
- Session-binding material is now taken from the SDP application m-section fingerprint, with session-level fallback only when the application section does not carry its own fingerprint.
- Pre-auth payload DataChannels force `FAILED` instead of being silently rejected.

### Dependencies
- Added `github.com/cloudflare/circl` (transitively `github.com/bwesterb/go-ristretto`).

## Milestones
- Milestone 1 (protocol hardening): complete.
- Milestone 2 (interactive PAKE authentication): complete.
- Milestone 3 (public alpha, external audit, technical paper): scoped in `TODO.md`; not started.
