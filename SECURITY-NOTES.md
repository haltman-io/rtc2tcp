# Security Notes

## Broker Role

The broker is a rendezvous and signaling relay only. It pairs peers by `rendezvous_token`, relays offer/answer messages, relays ICE candidates, and tears down in-memory sessions when peers disconnect. It does not proxy TCP tunnel payload bytes.

## Data Path

Tunnel payload bytes move over a WebRTC DataChannel once the peers complete ICE, DTLS, and SCTP setup. When ICE can find a direct route, traffic is peer-to-peer. If a TURN server is configured and a direct path is unavailable, the TURN server may relay encrypted WebRTC packets, but that is still separate from the broker role.

## Rendezvous Token vs Pairing Secret vs Transport Encryption

WebRTC transport encryption is separate from the broker pairing and peer authentication inputs.

- `rendezvous_token`
  Broker-visible pairing label used only for rendezvous.
- `pairing_secret`
  Peer-shared secret. Enters the CPACE generator derivation; never appears on the wire.
- WebRTC DTLS/SCTP
  Carries the encrypted peer-to-peer transport.

## Peer Authentication

Peers authenticate each other with a balanced CPACE-Ristretto255 PAKE. The flow is the three-message handshake `hello` -> `accept` -> `confirm` over the WebRTC control DataChannel, with transcript-bound HKDF-derived session keys and role-separated HMAC-SHA256 key confirmation. The authoritative specification is in `PROTOCOL.md` (section "Milestone 2 Authentication").

- Default scheme: `rtc2tcp-auth/cpace-ristretto255-v2`. Group arithmetic comes from `github.com/cloudflare/circl/group`.
- The CPACE generator is derived deterministically from the pairing secret, session id, and both transport fingerprints, so a broker that swaps session ids or rewrites SDP fingerprints produces a different generator and the handshake fails at key confirmation.
- Because the pairing secret only enters via the CPACE generator, an observer that records the full transcript cannot mount offline brute-force guesses against the pairing secret beyond the cost of the CPACE generator derivation on each candidate. CPACE is an online-only-guessing PAKE.
- A transitional ECDH scheme (`rtc2tcp-auth/interactive-ecdh-v2a`) is retained for rollout compatibility. It is not a PAKE. A CPACE-configured peer refuses any inbound whose scheme does not match byte-for-byte; this is a structural check, not a policy.

## Metadata Exposure

The broker still sees some metadata:

- broker-visible `rendezvous_token`
- whether a peer registered as `connect` or `expose`
- timing of registration, pairing, signaling, and disconnects
- ICE and SDP metadata needed for WebRTC setup

The broker should therefore be considered blind to plaintext and blind to the pairing secret, but not blind to session metadata.

## Current Limitations

- The CPACE-Ristretto255 primitive is sourced from `github.com/cloudflare/circl`. Its own audit and test vector coverage is relied upon; the rtc2tcp-specific integration (transcript construction, state machine, key schedule, session-binding material selection) has unit and pion-loopback end-to-end coverage but has not yet had external security review. Milestone 3 scopes that work.
- Broker state is in-memory only; no persistence or clustering.
- Message-size limits and origin restrictions exist, but broader rate limiting and abuse controls are not yet implemented.
- No TURN credential minting backend; TURN credentials are operator-supplied and static.
- No certificate-pinning UI or out-of-band verifier UX.
- Broker logs forward raw Go error strings verbatim to the other peer via the `error` signaling message. Contents are currently benign but the surface should be narrowed before public deployment.
- ICE candidate contents are not validated beyond what pion does; operators on multi-homed hosts should be aware that a hostile peer can influence candidate selection within what WebRTC normally allows.
