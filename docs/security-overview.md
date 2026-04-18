# Security overview

This page is the project-level summary. For cryptographic detail, see [PROTOCOL.md](../PROTOCOL.md); for the threat model, [THREAT-MODEL.md](../THREAT-MODEL.md); for release-signing and reporting, [SECURITY.md](../SECURITY.md).

## Current status

- **Milestone 1 (protocol hardening)** — implemented.
- **Milestone 2 (peer authentication)** — implemented.
- **Milestone 3 (external security review)** — open. The integration has unit tests and pion-loopback end-to-end coverage, but has not yet had a third-party cryptographic review.

## Milestone 1 — protocol hardening

- `rendezvous_token` is broker-visible and operator-supplied (or auto-generated on the expose side).
- `pairing_secret` is kept separate from the rendezvous token and is loaded locally from a file, environment variable, or compatibility flag — never sent to the broker.
- Non-control DataChannels are forbidden before authentication; any payload-channel-before-auth event fails the session.
- Broker transport must be `wss://` except for localhost development.
- Broker origin handling is restricted to same-host or no-origin clients.
- Session state is explicit: `INIT`, `RENDEZVOUS`, `SIGNALING`, `AUTH_PENDING`, `AUTHENTICATED`, `STREAMING`, `CLOSING`, `CLOSED`, `FAILED`.

## Milestone 2 — peer authentication

- Interactive three-message handshake (`hello` → `accept` → `confirm`) over the WebRTC control DataChannel.
- **Default scheme: CPACE-Ristretto255** (`rtc2tcp-auth/cpace-ristretto255-v2`), using the prime-order group from [`github.com/cloudflare/circl/group`](https://github.com/cloudflare/circl).
- Transcript binds scheme, session id, both peer roles, both application-section DTLS fingerprints, and both raw group shares.
- Role-separated HMAC-SHA256 key confirmation over the transcript is compared with `crypto/subtle.ConstantTimeCompare`.
- A transitional ECDH scheme (`rtc2tcp-auth/interactive-ecdh-v2a`) remains compiled in for rollout compatibility. It is not a PAKE; CPACE-configured peers refuse it structurally via the scheme-pin check.

Design notes for the authenticator: [authenticator-design.md](authenticator-design.md).

## Broker posture

- In-memory only; no persistence or clustering.
- Per-source-IP upgrade rate limiting (defaults: 30 req/min, burst 10) — tunable via `--rate-limit-per-minute` / `--rate-limit-burst`.
- Origin restrictions (same-host or no-origin).
- Message-size limits (1 MiB per WebSocket frame).
- Session and waiter TTLs (session: 1h, waiter: 5m) evict stale state.
- Trusted-proxy parsing so per-IP limits work correctly behind a reverse proxy ([reverse-proxy.md](reverse-proxy.md)).

## Known limitations

- The CPACE-Ristretto255 primitive is sourced from `github.com/cloudflare/circl`; its own test vectors are relied upon. The rtc2tcp integration (transcript construction, key schedule, session-binding material, state machine) has unit and pion-loopback end-to-end coverage but has not yet had an external security review.
- The broker has no persistence, clustering, or abuse controls beyond per-IP rate limiting, origin restrictions, and message-size caps.
- No TURN credential minting backend; TURN credentials are operator-supplied and static.
- No certificate-pinning UI or out-of-band verifier UX.
