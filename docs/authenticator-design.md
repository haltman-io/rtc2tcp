# ADR: Peer Authentication Scheme Choice

Status: Accepted (Milestone 2)
Date: 2026-04-18
Supersedes: the Milestone 1 placeholder HMAC session-binding proof.

## Decision

rtc2tcp authenticates peers with a balanced CPACE PAKE over the Ristretto255 prime-order group, sourced from `github.com/cloudflare/circl/group`. The scheme identifier on the wire is `rtc2tcp-auth/cpace-ristretto255-v2`. The target primitive is specified in [PROTOCOL.md](../PROTOCOL.md) ("Milestone 2 Authentication") and implemented in [internal/auth/auth.go](../internal/auth/auth.go).

A second scheme identifier, `rtc2tcp-auth/interactive-ecdh-v2a`, remains compiled in solely as a rollout-compatibility bridge. It is not a PAKE and the peer-level structural downgrade-refusal assertion in [cmd/rtc2tcp-peer/main.go](../cmd/rtc2tcp-peer/main.go) refuses to operate under it.

## Context

The Milestone 1 placeholder used HMAC over session-binding material (broker session id + both DTLS fingerprints + peer roles) keyed on the pairing secret. That design had two fatal properties for the stated trust model:

- A passive observer of a single transcript could mount offline guesses against the pairing secret: candidate secret -> recompute HMAC over the visible inputs -> compare. No online interaction required per guess.
- A malicious broker, being a passive observer of everything it relays, could mount the same attack. Since our threat model treats the broker as untrusted, that is an unacceptable dependency on pairing-secret entropy.

A PAKE addresses both: it forces every guess to be an interactive session with the honest peer, turning a throughput-limited operation into an online-attack problem that is easy to rate-limit and detect. The pairing secret can be short and human-memorable without catastrophic offline exposure.

## Requirements

A Milestone 2 authenticator must:

1. Bind to the exact WebRTC session in use, not a generic credential. Session id, both application-section DTLS fingerprints, and both peer roles all enter the transcript.
2. Resist offline guessing of the pairing secret given full transcript visibility.
3. Be implementable on top of an audited, maintained Go primitive. No hand-rolled field or group arithmetic.
4. Fit a single control DataChannel round-trip budget. Three frames max (`hello` / `accept` / `confirm`), so initiator and responder can each walk away with key confirmation after one full round.
5. Allow the primitive to be replaced later without changing the transcript, state machine, wire format, or session-binding contract.
6. Default to secure: a peer built from this tree must not negotiate a weaker scheme unless the operator takes an explicit, code-visible step.

## Considered Alternatives

### SPAKE2 (and SPAKE2+ augmented)

- Two fixed generators `M` and `N` with unknown discrete logs relative to each other and to the group base. In RFC 9382 these are specified as concrete ristretto255 points.
- Per peer: pick uniform scalar `x`, publish `X = x*G + pw*M` (initiator) or `Y = y*G + pw*N` (responder). Shared secret is `Z = x*(Y - pw*N)`.
- Requires point addition and scalar multiplication with user-chosen scalars.

Why not:

- SPAKE2 commits to two independent generators pinned in the spec. rtc2tcp would inherit those constants, or we would have to pick and justify our own. CPACE derives the generator from session inputs deterministically, so there is nothing to pin and audit separately.
- SPAKE2+ is augmented (asymmetric: one side stores a verifier). We want balanced authentication — both peers share the same secret symmetrically. Using SPAKE2+ when what is wanted is balanced SPAKE2 would force an awkward server/client mapping onto a connect/expose topology that is not actually asymmetric in trust.
- CIRCL does not ship a ready-to-use SPAKE2 out of the box; we would implement the SPAKE2 structure on top of `group.Ristretto255`. That is a small amount of code but it is still our code, with our choice of generator encoding, our message framing, our test vectors. CPACE delivers the same security with less surface because the generator derivation is fully specified from transcript inputs.

### CPACE-X25519

- The CFRG CPACE draft defines a variant over raw X25519, using Elligator2 to map a hash of the transcript into a curve point (the deterministic generator).
- Pros: X25519 is ubiquitous, the Montgomery ladder is very fast, `golang.org/x/crypto/curve25519` ships the scalar multiplication.

Why not:

- `golang.org/x/crypto/curve25519` only exposes `X25519` (scalar multiplication against a supplied base). It does not expose field arithmetic or Elligator2. A CPACE-X25519 implementation requires either hand-rolled Elligator2 on top of `curve25519.X25519` primitives (which means hand-rolled field arithmetic) or pulling in a library that exposes field operations. Hand-rolled curve arithmetic is exactly the kind of custom crypto the TODO explicitly forbids.
- X25519 has a non-trivial cofactor (8). Getting CPACE right on top of a cofactor group requires care around small-subgroup inputs. Ristretto255 is an explicit prime-order quotient of Curve25519 with no small-subgroup concerns.

If/when CIRCL (or the standard library) ships CPACE-X25519 as a vetted primitive, swapping to it is a one-function change — `derivePakeShared` in [internal/auth/auth.go](../internal/auth/auth.go) is the only call site, and the wire format is already 32-byte group elements either way.

### OPAQUE (augmented PAKE)

- Server-stored credential; client proves knowledge of a password without revealing it to the server across registration and login.
- CIRCL ships OPAQUE via `github.com/cloudflare/circl/oprf` plus a higher-level OPAQUE implementation.

Why not:

- OPAQUE is designed for client/server asymmetry: one party has a registration record, the other has a password. Our topology is symmetric — both peers arrive at a pairing and each already knows the shared secret. Mapping expose/connect onto OPAQUE's client/server roles is arbitrary, and whichever peer gets the "server" role still has to hold the verifier ahead of time, which contradicts the lab-pairing workflow where peers exchange a secret out of band and rendezvous immediately.
- Augmented PAKEs are the right tool when the "server" should not learn the password and must survive server compromise. That is not our trust boundary: both peers are symmetric end-users of the tunnel; the broker is not in the secret.

### PAK / PPK

- Older password-authenticated key exchange constructions (Boyko/MacKenzie 2000 family).
- Some have known subtle issues; the CFRG has largely moved attention to SPAKE2 and CPACE for current standardization work.

Why not: less well-reviewed in modern analysis, no maintained Go implementation, and no advantage over CPACE for our use.

### J-PAKE

- Three-pass password-authenticated key exchange with zero-knowledge proofs of scalar possession. Standardised in RFC 8236.

Why not:

- Higher message count and more zero-knowledge machinery than CPACE. We want the minimum number of frames to fit in a single control-channel round-trip on top of WebRTC DataChannel latency.
- No maintained Go implementation in our dependency graph.

## Why CPACE-Ristretto255

- **Prime-order group.** Ristretto255 is the prime-order quotient of Curve25519 that avoids cofactor-8 pitfalls. CIRCL's `group.Ristretto255` exposes hash-to-element (`HashToElement` using Elligator2 per RFC 9380), scalar sampling, point addition, scalar multiplication, and canonical 32-byte encoding. Everything CPACE needs, already audited in library form.
- **Generator from the transcript.** CPACE derives its base point `G` from a hash of symmetric inputs: `Ristretto255.HashToElement(len_prefixed(pairing_secret) || len_prefixed(session_id) || len_prefixed(initiator_fingerprint) || len_prefixed(responder_fingerprint), DST="rtc2tcp-auth/cpace-gen/v2")`. Both peers compute the same generator iff they hold the same pairing secret, the same broker-assigned session id, and agree on each other's application-section DTLS fingerprint. Session confusion, SDP-fingerprint rewriting, or session-id swaps by the broker produce a different generator and the handshake fails at key confirmation — not after.
- **Single round-trip, three frames.** Initiator publishes `x*G`, responder publishes `y*G` plus its confirmation tag, initiator publishes its confirmation tag. One message per direction per round-trip, which fits the WebRTC control channel cleanly.
- **Identity rejection is cheap and structural.** `Element.IsIdentity()` catches low-order / zero shares before arithmetic. Ristretto255's canonical encoding rejects non-canonical byte inputs at `UnmarshalBinary` time.
- **No hand-rolled crypto.** Every primitive comes from `github.com/cloudflare/circl` or `golang.org/x/crypto`. The rtc2tcp integration code does transcript construction, state sequencing, HKDF/HMAC composition, and constant-time comparisons — all standard-library operations.
- **Dropped-in and tested.** The integration is unit- and fuzz-tested at [internal/auth/auth_test.go](../internal/auth/auth_test.go), [internal/auth/auth_kat_test.go](../internal/auth/auth_kat_test.go), [internal/auth/auth_fuzz_test.go](../internal/auth/auth_fuzz_test.go), and the full flow including SDP exchange runs end-to-end over a pion PeerConnection pair in [internal/webrtc/session_e2e_test.go](../internal/webrtc/session_e2e_test.go).

## Implementation Map

| Spec section ([PROTOCOL.md](../PROTOCOL.md)) | Implementation pointer                                                   |
| -------------------------------------------- | ------------------------------------------------------------------------ |
| Scheme identifiers                           | [internal/auth/auth.go](../internal/auth/auth.go) `SchemeCPACEV2`, `SchemeTransitionalV2` |
| Wire format                                  | [internal/auth/auth.go](../internal/auth/auth.go) `Message`, `MessageKind` |
| Authenticator state machine                  | [internal/auth/auth.go](../internal/auth/auth.go) `AuthState`, `Step`, `stepInitiator`, `stepResponder` |
| CPACE generator derivation                   | [internal/auth/auth.go](../internal/auth/auth.go) `setupCPACE`            |
| `pake_shared`                                | [internal/auth/auth.go](../internal/auth/auth.go) `derivePakeShared`, `derivePakeSharedCPACE`, `derivePakeSharedECDH` |
| Transcript construction                      | [internal/auth/auth.go](../internal/auth/auth.go) `buildTranscript`, `writeLenPrefixed` |
| Key derivation schedule                      | [internal/auth/auth.go](../internal/auth/auth.go) `computeTranscriptAndKeys`, `hkdfExtract`, `hkdfExpand` |
| Role-separated confirmation tags             | [internal/auth/auth.go](../internal/auth/auth.go) `macTranscript`, `verifyResponderConfirm`, `verifyInitiatorConfirm` |
| Session-machine binding                      | [internal/webrtc/session.go](../internal/webrtc/session.go) `handleControlMessage`, `maybeSendAuth`, `prepareInboundPayloadChannel` |
| Structural downgrade-refusal                 | [cmd/rtc2tcp-peer/main.go](../cmd/rtc2tcp-peer/main.go) scheme assertion in `runPeer` |

## Open Questions / Future Work

- **Toolchain pin.** `go.mod` floors the toolchain at 1.26.0 via the `go` directive. Once the module's `go` directive is bumped, the `toolchain` directive becomes load-bearing and the release will pin to an exact patch.
- **Per-token rate limit.** The broker rate-limits per source IP. A per-`rendezvous_token` limiter is deferred until abuse patterns warrant it; a determined attacker behind CG-NAT cannot use the IP lever alone against a single long-lived token.
- **External review.** The integration has not yet had an external audit. The audit scope is `internal/auth/*`, `internal/webrtc/session.go` control-channel wire-up, and the broker signaling surface. The CIRCL primitive itself is out of scope and relied on upstream.
- **Scheme versioning.** If CPACE-X25519 (or another scheme) is added, the version identifier changes (`v3`, not `v2`), the scheme-pin check on the peer is updated, and the transcript DST constants change in lockstep. The transitional ECDH scheme will be removed at that point.
