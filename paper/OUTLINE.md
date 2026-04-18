# Paper Outline

Working title: *rtc2tcp: A Broker-Blind WebRTC Tunnel for a Single Authenticated TCP Endpoint*

Status: outline only. Content is deferred until external review feedback is in, because the audit may reshape the threat-model framing and the correctness arguments.

## Target Audience

Security engineers and applied-cryptography practitioners familiar with TLS, SSH port forwarding, and the PAKE landscape (SPAKE2, CPACE, OPAQUE). Assumes WebRTC / ICE / DTLS fluency at the level of RFC 8827 / 8839 / 8445.

## Abstract (to write)

Two sentences on what rtc2tcp does and two on what is novel about its trust model: broker-blind peer authentication via CPACE-Ristretto255 bound to the DTLS transport fingerprints selected from the SDP application m-section, with structurally enforced no-payload-before-auth.

## 1. Introduction

- Problem: exposing a single local TCP service to a remote peer, without either side running a public listener, without trusting an intermediate broker, and without assuming a shared PKI.
- Existing options and where they fall short: ngrok-style tunnels (broker in the data path), reverse SSH (requires a public host and a pre-shared keypair), Tailscale-style mesh (great but heavier), raw WebRTC DataChannel tooling (no standard peer-authentication layer).
- The rtc2tcp shape: WebRTC DataChannel carries payload, a WebSocket broker does rendezvous only, CPACE-Ristretto255 binds authentication to the exact WebRTC session without adding a certificate authority.

## 2. Threat Model

- Adapted from [THREAT-MODEL.md](../THREAT-MODEL.md). Broker is untrusted; network attacker may reach broker and/or peers; TURN, if used, only relays encrypted WebRTC packets.
- Explicit non-goals: stealth, malware-adjacent use, browser peers, server-side password storage.
- Audit assumptions: CIRCL `group.Ristretto255` is correct; pion WebRTC correctly enforces DTLS against SDP fingerprints; Go stdlib cryptographic primitives are correct.

## 3. Protocol

- Broker signaling (registration, pairing, offer/answer/ICE relay).
- Session state machine (`INIT` -> `RENDEZVOUS` -> `SIGNALING` -> `AUTH_PENDING` -> `AUTHENTICATED` -> `STREAMING` -> `CLOSING`/`CLOSED`/`FAILED`).
- Pre-auth channel rule: any non-control DataChannel observed before `AUTHENTICATED` forces `FAILED`.
- CPACE-Ristretto255 handshake: hello / accept / confirm, transcript binding, key schedule. Reference: [PROTOCOL.md](../PROTOCOL.md) and [docs/authenticator-design.md](../docs/authenticator-design.md).

## 4. Session Binding

- Application-section DTLS fingerprint selected via per-m-section SDP parse, rejecting conflicts between session-level and media-level fingerprints.
- Transcript contents: scheme, session id, both roles, both fingerprints, both raw group shares — specified byte-for-byte with 4-byte length prefixes.
- Argument: a broker that rewrites either SDP's application fingerprint produces a different transcript on the rewritten side, so key confirmation fails without authenticating over the rewritten session.

## 5. Correctness Argument

- State-machine well-formedness: directed acyclic transition graph except for the `STREAMING -> STREAMING` self-loop. Every error edge terminates in `FAILED`. Tested adversarially via the `FuzzStep` target and end-to-end via pion loopback.
- Authenticator state-machine substructure: `INIT` -> role-specific path -> `SUCCEEDED` or `FAILED`. Terminality of `SUCCEEDED` and `FAILED` is invariant-tested by the fuzzer.
- Binding argument: any deviation in the transcript inputs yields divergent confirmation keys, and HMAC-SHA256 under constant-time compare rejects non-matching tags.

## 6. Implementation

- Language / module layout.
- Key primitive sources: `github.com/cloudflare/circl/group` for Ristretto255, `golang.org/x/crypto/{curve25519,argon2,hkdf}`, `github.com/pion/webrtc/v4`.
- Size metrics (LOC, test coverage) — collect from CI.
- Deviations from the spec: none at time of writing.

## 7. Evaluation

- Handshake latency microbenchmark (Bench in `internal/auth/auth_bench_test.go`). Ballpark ~7 ms on a consumer Ryzen, dominated by Argon2id.
- End-to-end tunnel setup from `rtc2tcp-peer connect` invocation to first forwarded byte, broken down by phase: broker dial, SDP exchange, ICE, DTLS, auth, DataChannel open, TCP dial on expose side.
- Tunnel throughput on a direct path vs a TURN-relayed path. Pending a reproducible TURN harness.
- Comparison points: SSH port forwarding (same laptop ↔ loopback), ngrok free tier (ngrok is broker-in-path so it is a different threat model, included for latency context only).

## 8. Limitations

- CIRCL primitive is trusted upstream; we do not verify group implementation.
- No formal verification of state-machine well-formedness; coverage is test-driven (unit, fuzz, pion loopback).
- No browser peers; WebRTC handshake details assume pion semantics.
- Single exposed TCP endpoint per pairing; no multi-stream negotiation beyond one DataChannel per accepted TCP connection.
- External review pending; some properties asserted here may be strengthened, relaxed, or reframed after audit.

## 9. Related Work

- SPAKE2 / SPAKE2+ (RFC 9382): balanced and augmented PAKE; direct comparison with CPACE.
- CPACE (CFRG draft `draft-irtf-cfrg-cpace`): the primitive rtc2tcp builds on.
- OPAQUE: asymmetric PAKE; not applicable to the rtc2tcp topology.
- WebRTC DTLS-SRTP identity (RFC 8842): similar transport-layer binding pattern, different application shape.
- ngrok, Cloudflare Tunnel, Tailscale: product comparison, not protocol comparison.

## 10. Conclusion

- What we shipped, what we do not claim, what we plan for the next milestone.

## Appendices

- A. Wire-format JSON schema (dumped from `internal/auth/auth.go`).
- B. Transcript derivation worked example with a fixed small pairing secret and fixed session id (for audit reproducibility).
- C. CPACE-Ristretto255 reference test vectors (cross-checked against an independent implementation before publication).

## Pending Before Drafting

- [ ] External audit report in hand so this paper can reference findings rather than pre-empt them.
- [ ] TURN-path throughput numbers with a reproducible harness.
- [ ] Consolidated LOC / coverage metrics from a CI run.
- [ ] Target venue: workshop-class (HotSec, FOCI), or technical blog post + arXiv preprint. Decide before drafting because the length budget and citation density differ.
