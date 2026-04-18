# Changelog

All notable protocol, security, and public-interface changes to rtc2tcp are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are not assigned until the first tagged release.

## [Unreleased]

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
