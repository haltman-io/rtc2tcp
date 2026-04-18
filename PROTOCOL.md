# rtc2tcp Protocol

## Status

This document freezes the protocol shape for the Milestone 1 hardening track.

- The broker is a rendezvous and signaling service only.
- WebRTC carries the payload and any control-channel authentication messages.
- Peer authentication is still a placeholder design in Milestone 1 and must not be described as a completed secure PAKE flow.

## Roles

- `connect`: accepts local TCP connections and opens WebRTC payload channels toward the peer.
- `expose`: receives authenticated payload channels and dials the configured local target TCP endpoint.
- `broker`: pairs peers by `rendezvous_token` and relays signaling only.

## Security-Critical Terms

- `rendezvous_token`
  An operator-provided broker-visible pairing label. It is an opaque identifier and is not derived from the `pairing_secret`.
- `pairing_secret`
  A peer-shared secret used by the authentication subsystem. In Milestone 1 it still feeds a placeholder auth mechanism; in Milestone 2 it will feed a real interactive PAKE.
- `session_binding_material`
  The material that binds peer authentication to a specific WebRTC session. In Milestone 1 it includes:
  - `session_id`
  - peer roles
  - the DataChannel transport fingerprint selected from the `application` media section, with session-level fallback only when the application section does not carry its own fingerprint

## Broker Protocol

Transport:

- WebSocket on `/ws`
- `wss://` is required for non-localhost brokers
- `ws://` is accepted only for localhost development

Message flow:

1. Peer opens WebSocket to broker.
2. First message must be `register`.
3. Broker replies with `registered`.
4. Broker pairs exactly one `connect` peer and one `expose` peer for the same `rendezvous_token`.
5. Broker sends `paired` with:
   - `session_id`
   - `initiator`
   - `peer_mode`
6. Peers exchange `signal` messages through broker:
   - `offer`
   - `answer`
   - `ice-candidate`
7. Broker may send `peer-left` or `error`.

Broker-visible metadata:

- `rendezvous_token`
- peer mode
- session lifecycle
- signaling metadata including SDP and ICE

Broker-not-visible data:

- TCP payload bytes
- DataChannel plaintext

## Peer Session State Machine

States:

- `INIT`
- `RENDEZVOUS`
- `SIGNALING`
- `AUTH_PENDING`
- `AUTHENTICATED`
- `STREAMING`
- `CLOSING`
- `CLOSED`
- `FAILED`

Allowed transitions:

- `INIT -> RENDEZVOUS`
- `RENDEZVOUS -> SIGNALING`
- `SIGNALING -> AUTH_PENDING`
- `AUTH_PENDING -> AUTHENTICATED`
- `AUTHENTICATED -> STREAMING`
- `STREAMING -> STREAMING`
- `INIT|RENDEZVOUS|SIGNALING|AUTH_PENDING|AUTHENTICATED|STREAMING -> CLOSING`
- `CLOSING -> CLOSED`
- `INIT|RENDEZVOUS|SIGNALING|AUTH_PENDING|AUTHENTICATED|STREAMING|CLOSING -> FAILED`

Invalid transitions are protocol errors and must terminate the session.

## DataChannel Rules

- Control channel label: `rtc2tcp-auth`
- Non-control payload channels are forbidden before successful authentication.
- Any inbound payload channel observed before authentication is a protocol violation and must fail the session.
- `connect` must not create outbound payload channels before authentication.
- `expose` must not dial the target TCP endpoint before authentication.

## Session Binding

Milestone 1 binding uses a placeholder proof design. The proof is currently bound to:

- `session_id`
- local role and peer role
- local selected transport fingerprint
- remote selected transport fingerprint

Milestone 2 replaces that one-shot proof with the interactive flow described below. The session-binding inputs above remain load-bearing: they feed the Milestone 2 transcript directly.

## Milestone 2 Authentication

This section is normative. It specifies the control-channel authentication flow for Milestone 2, including wire format, message sequencing, transcript shape, key derivation, and error handling. The Milestone 1 state machine and pre-auth channel rules in the sections above continue to apply unchanged; Milestone 2 adds substructure inside `AUTH_PENDING` but never relaxes any of the existing gates.

### Goals and Non-Goals

Goals:

- Replace the Milestone 1 placeholder with an interactive handshake whose wire format, transcript, state machine, and key derivation are stable across the PAKE swap.
- Bind every authenticator input to the concrete WebRTC session so a misbehaving broker cannot cross-splice handshakes.
- Require transcript-bound mutual key confirmation before the session state machine transitions out of `AUTH_PENDING`.
- Keep the PAKE substitution point small and local: only the `pake_shared` derivation changes when CPACE-X25519 lands.

Non-goals:

- Forward secrecy against pairing-secret compromise beyond what the PAKE primitive gives.
- Asymmetric or augmented authentication. Milestone 2 is balanced: both peers share one `pairing_secret`.
- Browser peers or non-Go implementations.

### Scheme Identifiers

Peers pin the scheme string byte-for-byte. Mismatch fails the handshake at the first inbound message with no partial state visible to the session state machine.

- `rtc2tcp-auth/cpace-ristretto255-v2` — the Milestone 2 shipped scheme. `pake_shared` is computed via balanced CPACE over Ristretto255 using the group arithmetic from `github.com/cloudflare/circl/group`. The generator is derived deterministically from symmetric inputs by hash-to-element:
  ```
  gen_input =
      lp(pairing_secret_utf8) ||
      lp(session_id) ||
      lp(initiator_fingerprint) ||
      lp(responder_fingerprint)
  G = Ristretto255.HashToElement(gen_input, "rtc2tcp-auth/cpace-gen/v2")
  ```
  Each peer picks a uniform non-zero scalar `x`, publishes `share = x*G` encoded as 32 bytes via Ristretto255 canonical encoding, and computes `pake_shared = MarshalBinary(x * peer_share)`. The identity element is rejected on both send and receive.
- `rtc2tcp-auth/interactive-ecdh-v2a` — transitional scheme retained for backward compatibility during the Milestone 2 rollout. Wire format, transcript, key derivation, state machine, and error paths are identical; only `pake_shared` is different (`X25519(local_private, remote_public)` with the Argon2id-stretched pairing-secret mix load-bearing). This is not a PAKE: an observer with the full transcript can still mount offline guesses against the pairing secret, bounded by the Argon2id cost parameters. Peers that build with the CPACE primitive must not fall back to this scheme: downgrade is prevented by the scheme-pin check at the first inbound message.

A peer receiving a scheme it does not implement transitions the session to `FAILED` and closes the PeerConnection.

### Roles

- The peer registered as `connect` is the authentication `initiator`.
- The peer registered as `expose` is the authentication `responder`.
- The initiator role on the control channel must match the broker's `paired.initiator` flag. If the two disagree the session fails before the first auth message is sent.

### Wire Format

Every authentication message is a UTF-8 JSON object sent as a single DataChannel text frame on the `rtc2tcp-auth` control channel. Unknown JSON fields are rejected (`json.Decoder.DisallowUnknownFields`).

```
{
  "scheme": "<scheme identifier>",
  "kind": "hello" | "accept" | "confirm",
  "initiator_role": "connect",              // hello only
  "responder_role": "expose",               // hello only
  "share": "<base64url, 32 bytes>",         // hello, accept
  "confirmation": "<base64url, 32 bytes>"   // accept, confirm
}
```

- `share` is the peer's public group element (X25519 public key for the transitional scheme; CPACE commitment `x*G` for the target scheme). 32 bytes on the wire.
- `confirmation` is HMAC-SHA256 of the transcript under the role-specific confirmation key. 32 bytes on the wire.
- The encoding is base64url without padding for both fields.

### Message Sequence

Exactly three frames, in this order:

```
INITIATOR (connect)                  RESPONDER (expose)
  state: INIT                          state: INIT
  --- hello ------>
                                       verify scheme, roles, share length
                                       compute pake_shared, transcript, keys
                                       state: SENT_ACCEPT
  <--- accept ----
  verify scheme, share length
  compute pake_shared, transcript, keys
  verify accept.confirmation == responder_confirm
  state: SENT_CONFIRM
  --- confirm --->
                                       verify confirm.confirmation == initiator_confirm
                                       state: SUCCEEDED
  state: SUCCEEDED (after send)
```

Invalid sequencing is a protocol violation:

- A responder that sees anything other than `hello` from state `INIT` fails.
- An initiator that sees anything other than `accept` from state `SENT_HELLO` fails.
- A responder that sees anything other than `confirm` from state `SENT_ACCEPT` fails.
- Either side, once in `SUCCEEDED` or `FAILED`, rejects every further inbound message.

### Transcript

Both peers compute byte-identical transcripts:

```
H = SHA-256
lp(x)  = 4-byte big-endian length of x, followed by x
transcript_input =
    lp("rtc2tcp-auth/transcript/v2") ||
    lp(scheme) ||
    lp(session_id) ||
    lp(initiator_role) ||
    lp(responder_role) ||
    lp(initiator_fingerprint) ||
    lp(responder_fingerprint) ||
    lp(initiator_share) ||
    lp(responder_share)
transcript = H(transcript_input)
```

- `session_id` is the broker-assigned identifier from `paired.sessionID`.
- `initiator_fingerprint` and `responder_fingerprint` are the DTLS fingerprints selected by `ExtractTransportFingerprint` from the `application` m-section of each peer's SDP, normalized to upper case and space-separated.
- `initiator_share` and `responder_share` are the raw 32-byte group elements, not their base64url encoding.

Any disagreement between peers (different SDP fingerprints, different roles, different session id, different shares) yields different transcripts and therefore different confirmation tags, so key confirmation fails before the session state machine leaves `AUTH_PENDING`.

### Key Derivation

```
pairing_salt = SHA-256("rtc2tcp/m2/pairing-salt/v1" || session_id)
pairing_mix  = Argon2id(
    password  = pairing_secret_utf8,
    salt      = pairing_salt,
    time      = 1,
    memory    = 8192 KiB,
    threads   = 1,
    key_len   = 32
)
ikm = pake_shared || pairing_mix
prk = HKDF-Extract(salt = transcript, ikm = ikm, hash = SHA-256)

session_key          = HKDF-Expand(prk, "rtc2tcp/m2/session-key/v1", 32)
k_initiator_confirm  = HKDF-Expand(prk, "rtc2tcp/m2/confirm-key/initiator/v1", 32)
k_responder_confirm  = HKDF-Expand(prk, "rtc2tcp/m2/confirm-key/responder/v1", 32)

initiator_confirm = HMAC-SHA256(k_initiator_confirm, transcript)
responder_confirm = HMAC-SHA256(k_responder_confirm, transcript)
```

- For `interactive-ecdh-v2a`, `pake_shared = X25519(local_private, remote_public)`. `pairing_mix` is load-bearing: it is the only place the pairing secret enters the key schedule, and it is what makes offline guessing cost Argon2id-work per candidate.
- For `cpace-ristretto255-v2`, `pake_shared = MarshalBinary(local_scalar * peer_share)` over the CPACE generator, which is already a function of the pairing secret. `pairing_mix` is retained for domain separation and is not load-bearing; it can be dropped or reparameterized without affecting PAKE security.
- All comparisons of confirmation tags use `crypto/subtle.ConstantTimeCompare`.
- The `X25519` result is rejected if it is the all-zero point (low-order peer share); likewise the peer share is rejected if it decodes to the all-zero point.

### Authenticator State Machine

Each peer owns an authenticator instance with its own internal state machine. This is a substructure of `AUTH_PENDING` in the session state machine; the session state machine itself does not move until the authenticator reports `SUCCEEDED`.

```
Initiator:
  INIT ── Start ──▶ SENT_HELLO ── Step(accept) ──▶ SENT_CONFIRM ──▶ SUCCEEDED
  Any state ── invalid input or error ──▶ FAILED

Responder:
  INIT ── Step(hello) ──▶ SENT_ACCEPT ── Step(confirm) ──▶ SUCCEEDED
  Any state ── invalid input or error ──▶ FAILED
```

- `SUCCEEDED` and `FAILED` are terminal.
- `FAILED` propagates to the session state machine as `StateFailed` and closes the PeerConnection.

### Session State Machine Binding

- The session stays in `AUTH_PENDING` for the entire handshake. It transitions to `AUTHENTICATED` only after the authenticator reports `done=true` with no error.
- The session's existing pre-auth payload-channel rule remains unchanged: any inbound non-control DataChannel received while the session is not `AUTHENTICATED` or `STREAMING` forces `FAILED`.
- The peer-level authentication timeout wraps the entire interactive flow; a timeout in `AUTH_PENDING` closes the session via `fail`, not via a separate authenticator path.

### Replay and Confusion Resistance

- The transcript includes `session_id` and both application-section transport fingerprints, so a proof from another session, a rewritten SDP, or a broker-driven session splice fails key confirmation.
- Each authenticator instance is single-use. After `SUCCEEDED` or `FAILED` every further inbound message is a protocol violation and forces `FAILED` on the session.
- Confirmation keys are role-separated (`k_initiator_confirm` vs `k_responder_confirm`), so an attacker cannot reflect a responder's tag as an initiator's tag or vice versa.

### Error Surface

| Condition                                             | Outcome                |
| ----------------------------------------------------- | ---------------------- |
| Unknown or unexpected scheme on inbound               | `AUTH_PENDING` -> `FAILED` |
| Unknown JSON field or malformed message               | `AUTH_PENDING` -> `FAILED` |
| Wrong `kind` for current authenticator state          | `AUTH_PENDING` -> `FAILED` |
| `share` not 32 bytes or decodes to all-zero point     | `AUTH_PENDING` -> `FAILED` |
| `X25519` result is the all-zero point                 | `AUTH_PENDING` -> `FAILED` |
| `confirmation` not 32 bytes                           | `AUTH_PENDING` -> `FAILED` |
| Confirmation HMAC mismatch                            | `AUTH_PENDING` -> `FAILED` |
| `hello` role fields disagree with session modes       | `AUTH_PENDING` -> `FAILED` |
| Missing local or remote fingerprint at transcript time| `AUTH_PENDING` -> `FAILED` |
| Second inbound after `SUCCEEDED` or `FAILED`          | session closed via protocol violation |

Every failure is delivered through `Session.fail` and closes the PeerConnection.

### Implementation Map

Direct pointers from each normative section above to the enforcing code. Auditors can cross-read the spec against the implementation without discovery:

| Spec section                       | Implementation                                                                        |
| ---------------------------------- | ------------------------------------------------------------------------------------- |
| Scheme identifiers                 | [`internal/auth/auth.go`](internal/auth/auth.go) `SchemeCPACEV2`, `SchemeTransitionalV2` |
| Wire format                        | [`internal/auth/auth.go`](internal/auth/auth.go) `Message`, `MessageKind`                |
| Authenticator state machine        | [`internal/auth/auth.go`](internal/auth/auth.go) `AuthState`, `Step`, `stepInitiator`, `stepResponder` |
| CPACE generator derivation         | [`internal/auth/auth.go`](internal/auth/auth.go) `setupCPACE`                            |
| `pake_shared` dispatcher           | [`internal/auth/auth.go`](internal/auth/auth.go) `derivePakeShared` (→ `derivePakeSharedCPACE` / `derivePakeSharedECDH`) |
| Transcript construction            | [`internal/auth/auth.go`](internal/auth/auth.go) `buildTranscript`, `writeLenPrefixed`   |
| Key derivation schedule            | [`internal/auth/auth.go`](internal/auth/auth.go) `computeTranscriptAndKeys`, `hkdfExtract`, `hkdfExpand` |
| Role-separated confirmation tags   | [`internal/auth/auth.go`](internal/auth/auth.go) `macTranscript`, `verifyResponderConfirm`, `verifyInitiatorConfirm` |
| Session state machine              | [`internal/webrtc/state.go`](internal/webrtc/state.go) `StateMachine`, `allowedTransitions` |
| Session-machine binding            | [`internal/webrtc/session.go`](internal/webrtc/session.go) `handleControlMessage`, `maybeSendAuth`, `bindAuthenticator` |
| Pre-auth payload-channel rejection | [`internal/webrtc/session.go`](internal/webrtc/session.go) `OnDataChannel` dispatch, `prepareInboundPayloadChannel` |
| Application-section fingerprint    | [`internal/webrtc/session.go`](internal/webrtc/session.go) `ExtractTransportFingerprint` |
| Broker rendezvous and pairing      | [`internal/rendezvous/broker.go`](internal/rendezvous/broker.go) `handleWebSocket`, `tryPair`, `unregisterPeer` |
| Broker origin and TLS policy       | [`internal/rendezvous/broker.go`](internal/rendezvous/broker.go) `brokerCheckOrigin`; [`internal/signaling/client.go`](internal/signaling/client.go) `normalizeBrokerURL` |
| Structural downgrade-refusal       | [`cmd/rtc2tcp-peer/main.go`](cmd/rtc2tcp-peer/main.go) scheme assertion in `runPeer`    |

Design rationale for choosing CPACE-Ristretto255 over SPAKE2, CPACE-X25519, OPAQUE, PAK, and J-PAKE is recorded in [`docs/authenticator-design.md`](docs/authenticator-design.md).

## Current Constraints

- Single exposed TCP endpoint per session.
- One control channel plus one payload DataChannel per local TCP connection.
- No persistence in the broker.
- No stealth, OS privilege work, firewall mutation, telemetry, or update path.
