# rtc2tcp TODO

## Current Status

[x] Milestone 1 protocol hardening is complete in code, docs, and unit-level adversarial coverage.
[-] `TODO.md` is the active execution ledger for protocol/security work.
[x] `PROTOCOL.md` freezes the Milestone 1 protocol shape and pins the Milestone 2 CPACE-Ristretto255 flow.
[x] `THREAT-MODEL.md` captures current trust boundaries and abuse paths.
[x] Code now has explicit `rendezvous_token` and `pairing_secret` concepts.
[x] Milestone 1 is complete.
[x] Milestone 2 is complete: CPACE-Ristretto255 is the default scheme, implemented via `github.com/cloudflare/circl/group`; transitional ECDH scheme is retained for rollout only and downgrade is refused by the scheme-pin check; pion-loopback end-to-end tests cover both schemes.
[-] Milestone 3 is scoped. Documentation sync is done; auditability hardening, broker/peer hardening, release prep, and the technical paper are the remaining blocks.

## Current Findings

- Peer auth is now an interactive three-message handshake in `internal/auth/auth.go`: `hello` -> `accept` -> `confirm`, with transcript-bound HKDF-derived session keys and role-separated HMAC key confirmation. The `derivePakeShared` function is the single substitution point for CPACE-X25519.
- The current scheme identifier is `rtc2tcp-auth/interactive-ecdh-v2a`. It is not a PAKE and must not be described as one. Pairing-secret compromise via offline transcript analysis remains possible, bounded by Argon2id cost.
- Session state machine gates remain enforced: pre-auth payload channels fail the session, and `StateAuthenticated` is only reached after the authenticator reports `done=true` with no error.
- Broker/client code uses explicit `rendezvous_token`; the old secret-derived rendezvous key path is gone.
- Non-control DataChannels fail the session before auth.
- Broker client rejects insecure `ws://`/`http://` outside localhost.
- Broker origin handling is same-host or empty-origin only.
- Broker and signaling paths have explicit WebSocket read size limits.
- CLI prefers `--pairing-secret-file` or env-backed secret loading; direct CLI secret flags remain as compatibility aliases.
- Fingerprint binding prefers the `application` media section for the DataChannel transport.
- `PROTOCOL.md` specifies the Milestone 2 wire format, transcript, state machine, and error surface; both the target (`cpace-x25519-v2`) and the transitional (`interactive-ecdh-v2a`) scheme identifiers are pinned.

## Milestones

- [x] Milestone 1: Freeze protocol shape and remove structural security lies
- [x] Create or update `PROTOCOL.md`
- [x] Create or update `THREAT-MODEL.md`
- [x] Introduce and enforce explicit peer session states
- [x] Ensure no non-control DataChannel is accepted before authentication
- [x] Tear down on any stream-before-auth violation
- [x] Fix SDP fingerprint extraction for the SCTP/DataChannel transport binding target
- [x] Reject insecure broker transport outside localhost
- [x] Stop encouraging direct CLI secret flag as the primary path
- [x] Add secret-file and environment variable support
- [x] Add WebSocket read size limits
- [x] Restrict broker origin handling
- [x] Make close/cleanup explicit on auth timeout and error paths
- [x] Remove the current hash-of-password rendezvous key design
- [x] Separate `rendezvous_token`, `pairing_secret`, and `session_binding_material`
- [x] Add adversarial tests for Milestone 1 failure paths
- [x] Milestone 2: Replace placeholder auth with a real interactive PAKE flow
  - [x] Specify Milestone 2 wire format, transcript, state machine, and key schedule in `PROTOCOL.md`
  - [x] Replace the one-shot authenticator with an interactive `Authenticator` interface and three-message handshake
  - [x] Bind the transcript to scheme, session id, both roles, both application-section fingerprints, and both raw shares
  - [x] Role-separated HMAC key confirmation gated by constant-time comparison
  - [x] Session state machine only enters `AUTHENTICATED` after `done=true`
  - [x] Adversarial unit tests for wrong secret, tampered share, role confusion, out-of-order message, scheme mismatch, session mismatch, all-zero share, post-complete input
  - [x] End-to-end pion-loopback integration tests for the happy path and the wrong-secret failure path (`internal/webrtc/session_e2e_test.go`)
  - [x] Bridge backpressure via `BufferedAmountLow` / high-water threshold in `internal/tunnel/bridge.go`
  - [x] Bridge wires `OnError` so SCTP-level failures tear the pair down
  - [x] Expose-side TCP dial runs off the pion callback goroutine so it cannot starve pion's dispatcher
  - [x] CPACE-Ristretto255 primitive wired into `derivePakeShared` via `github.com/cloudflare/circl/group`; default scheme is now `SchemeCPACEV2`
  - [x] Cross-version downgrade refusal: CPACE-configured peers reject the transitional scheme at the first inbound message (scheme-pin check in `Step`); test lock-in at `TestCPACEPeerRefusesTransitionalDowngrade`
- [-] Milestone 3: Prepare for public alpha + external audit + technical paper
  - Documentation sync
    - [x] `README.md`, `SECURITY-NOTES.md`, `THREAT-MODEL.md` updated to describe CPACE-Ristretto255 and remove all remaining "placeholder" language
    - [x] `CHANGELOG.md` added with the Milestone 2 cutover entry
    - [x] `PROTOCOL.md` "Implementation Map" table cross-references every normative section to the enforcing code (file + symbol). Auditors can cross-read spec against code without discovery.
    - [x] `docs/authenticator-design.md` ADR records why CPACE-Ristretto255 was picked over SPAKE2, SPAKE2+, CPACE-X25519, OPAQUE, PAK, and J-PAKE; includes an implementation-map table for the authenticator internals and open-questions block covering toolchain pinning, per-token rate limit, and future scheme-versioning semantics.
  - Auditability hardening
    - [x] Transcript, pairing-salt, HKDF, and HMAC byte-pinned against first-principles reference computations in `internal/auth/auth_kat_test.go`; any change to the length-prefixed transcript layout or the HKDF/HMAC labels fails CI
    - [x] Wire-format golden tests for `hello` / `accept` / `confirm` assert the JSON marshaling of each `Message` kind byte-for-byte, so a silent format drift breaks CI
    - [x] Live CPACE handshake consistency test asserts both peers agree on session key, transcript hash, and both role confirmation tags (byte-exact full-handshake KAT is not possible at this layer because CIRCL's `RandomNonZeroScalar` ignores its `io.Reader` argument and pulls from `crypto/rand`)
    - [x] Fuzz target for `Step` (native `testing.F`) in `internal/auth/auth_fuzz_test.go`, seeded with the three valid frames plus malformed JSON; asserts no panics, that errors force FAILED, that FAILED is terminal, and that done=true implies SUCCEEDED + 32-byte session key. Short `-fuzztime 20s` run executed ~2.5M inputs across 16 workers with no invariant violations.
    - [x] Structured `peer: auth_failure mode=... scheme=... reason=... detail=...` log line emitted whenever `WaitAuthenticated` returns a non-nil error in `cmd/rtc2tcp-peer/main.go`; reason is a fixed enum derived via `errors.Is` so operators can grep without inspecting raw error text
  - Broker hardening
    - [x] Idle-waiter TTL (default 5 min) and session TTL (default 1 h) in `internal/rendezvous/broker.go`; a janitor goroutine sweeps every 30 s and evicts expired state. Evicted peers receive a fixed `waiter-expired` / `session-expired` error and the conn is closed. `collectStale` is a pure-map-ops function tested directly in `internal/rendezvous/broker_test.go` without requiring real WebSocket conns.
    - [x] Per-source-IP WebSocket-upgrade rate limiting via `golang.org/x/time/rate` wrapped by `keyedLimiter` in `internal/rendezvous/ratelimit.go`; defaults 30/min with burst 10; exhausted bucket responds HTTP 429; idle IP entries evicted after 1 h via the janitor sweep. Unit-tested with injected clock in `internal/rendezvous/ratelimit_test.go`.
    - [ ] Per-token rate limiting (registrations per rendezvous_token per minute) — follow-up if abuse patterns warrant it; per-IP is the primary lever.
    - [x] Narrowed the broker-to-peer `error` surface: `register-failed`, `pairing-failed`, and `relay-failed` no longer forward raw `err.Error()` text; the peer-facing message is now a fixed per-code string, and the detail stays in the broker log only (`internal/rendezvous/broker.go` `genericBrokerMessage`)
    - [x] Structured logs with per-session correlation id via `internal/logx.Event`; broker emits `broker: event=<name> k=v ...` with `session_id` / `peer_id` / `rendezvous_token` / `source_ip` fields leading each line; peer and tunnel bridge share the same formatter. Quoting handles spaces/equals/quotes/backslashes/control chars. Unit-tested in `internal/logx/event_test.go`.
  - Peer hardening
    - [x] `--target` and `--listen` validated via `config.ValidateAddress`; unspecified (0.0.0.0, ::) and multicast addresses rejected for both roles; `--listen` additionally requires an IP literal so a misconfigured hostname cannot bind to an unexpected interface (`internal/config/address.go`, `internal/config/address_test.go`)
    - [x] Structural downgrade-refusal: `cmd/rtc2tcp-peer/main.go` asserts `authenticator.Name() == auth.SchemeCPACEV2` at startup. A future accidental change that flips the default authenticator will fail loudly instead of authenticating over a weaker scheme. Chose a code-level assertion over a `--min-scheme` CLI flag because the peer ships one scheme today and a flag adds surface for intentional downgrades.
    - [x] Fixed the `runListener` goroutine leak on early accept failure via a dedicated `stop` channel closed by the enclosing defer in `cmd/rtc2tcp-peer/main.go`
  - Release + audit prep
    - [x] Reproducible build recipe: `Makefile` with `-trimpath -ldflags "-s -w ..."` cross-compile targets, `CGO_ENABLED=0`, `Version`/`Commit` stamped via ldflags from git metadata; README build section updated; verified both binaries accept the stamped values at runtime. Toolchain is currently floored via `go 1.26.0` in `go.mod`; tidy strips an equal `toolchain` directive, so strict toolchain pinning waits until the CI host Go version moves ahead of the module's go directive.
    - [x] GitHub Actions CI: build + `go vet` + `go test ./... -race` on Linux/macOS/Windows + short `-fuzz=FuzzStep` run + `gofmt` + `go mod tidy` drift check in `.github/workflows/ci.yml`
    - [x] Release artifacts: `.github/workflows/release.yml` cross-compiles `rtc2tcp-broker` and `rtc2tcp-peer` for linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/amd64 on `v*` tag push; generates `SHA256SUMS`; signs the manifest keyless via Sigstore cosign with GitHub OIDC (`SHA256SUMS.sig` + `SHA256SUMS.pem`); attaches everything to an auto-generated GitHub Release. Verification recipe documented in `SECURITY.md`.
    - [x] `SECURITY.md` added: private reporting via GitHub Security Advisories, scope statement, acknowledgement/disclosure timelines, safe-harbour clause, and cosign verification recipe for release artifacts. README links to it from both the top matter and the Security Shape section.
    - [ ] Scope and contract an external review of the authenticator integration (`internal/auth`, `internal/webrtc/session.go` control-channel wire-up) and the broker signaling surface; external review is not expected to cover the CIRCL primitive itself
  - Technical paper
    - [x] Paper outline `paper/OUTLINE.md` scaffolded: abstract, threat model, protocol, correctness argument, evaluation, limitations, related work, appendices. Pending-work block names what has to land before a draft is reasonable (external audit, TURN throughput harness, venue decision).
    - [ ] Draft in `paper/` with reproducible experiments and numbers for handshake latency, tunnel throughput on TURN and direct paths. Handshake microbenchmark in place (`BenchmarkInteractiveHandshakeCPACE` — ~6.7 ms per round on a Ryzen 7 5800X, dominated by Argon2id); TURN-path throughput harness still to be built.

## Files Touched

- [x] `TODO.md`
- [x] `PROTOCOL.md`
- [x] `THREAT-MODEL.md`
- [x] `cmd/rtc2tcp-peer/main.go`
- [x] `internal/config/peer.go`
- [x] `internal/config/secrets.go`
- [x] `internal/signaling/types.go`
- [x] `internal/signaling/client.go`
- [x] `internal/rendezvous/broker.go`
- [x] `internal/rendezvous/token.go`
- [x] `internal/auth/auth.go`
- [x] `internal/webrtc/session.go`
- [x] `internal/webrtc/state.go`
- [x] `internal/webrtc/session_test.go`
- [x] `internal/webrtc/state_test.go`
- [x] `internal/auth/auth_test.go`
- [x] `README.md`
- [x] `SECURITY-NOTES.md`

## Validation

- [x] Repository inspection of broker, signaling, peer, auth, and current docs
- [x] Protocol and threat model docs added and aligned to current code reality
- [x] `go test ./...`
- [x] `go build ./cmd/rtc2tcp-broker ./cmd/rtc2tcp-peer`
- [x] Adversarial unit coverage added for stream-before-auth, replay-like control reuse, broker/session confusion, mismatched fingerprints, and invalid state transitions

## Next Action

Blocking items are all non-code:

1. Procure the external security review. The audit envelope is clean: protocol spec + implementation-map table, transcript/key-schedule byte-pins, state-machine unit tests, adversarial fuzz corpus, structured logs, reproducible build, signed release artifacts, ADR explaining scheme choice. Scope the brief as `internal/auth/*`, `internal/webrtc/session.go` control-channel wire-up, and the broker signaling surface — primitive correctness (`github.com/cloudflare/circl/group`) is relied on upstream.
2. Build a TURN-path throughput harness (local coturn or equivalent, docker-composed) so the paper's evaluation section has reproducible numbers.

Deferred-not-needed: per-token broker rate limit (current per-IP lever is sufficient for single-tenant lab deployments; revisit if abuse patterns warrant).

## Change Log

- [x] 2026-04-18: Replaced the placeholder TODO list with a milestone-driven security execution ledger based on current code inspection.
- [x] 2026-04-18: Added `PROTOCOL.md` and `THREAT-MODEL.md` to freeze the Milestone 1 design and trust boundaries.
- [x] 2026-04-18: Replaced the derived rendezvous-key path with explicit `rendezvous_token` handling and added file/env-backed pairing secret loading.
- [x] 2026-04-18: Added session-state enforcement, pre-auth payload rejection, broker transport/origin hardening, and transport-specific fingerprint selection.
- [x] 2026-04-18: Added adversarial Milestone 1 tests and synchronized `README.md` and `SECURITY-NOTES.md` with the hardened protocol shape.
- [x] 2026-04-18: Specified the Milestone 2 interactive auth flow in `PROTOCOL.md`; replaced the one-shot authenticator in `internal/auth/auth.go` with a three-message handshake driving transcript-bound HKDF/HMAC key confirmation; wired the new flow into `internal/webrtc/session.go` without weakening the state machine or pre-auth channel rules; isolated the PAKE primitive as the single-function `derivePakeShared` substitution point.
- [x] 2026-04-18: Added pion-loopback end-to-end tests covering the happy-path handshake and the wrong-secret failure path in `internal/webrtc/session_e2e_test.go`; added bridge backpressure via `OnBufferedAmountLow`/high-water threshold, wired `dc.OnError` for SCTP-level failures, and moved the expose-side target dial off pion's callback goroutine.
- [x] 2026-04-18: Added `github.com/cloudflare/circl` dependency and wired CPACE-Ristretto255 into `derivePakeShared`; the default scheme is now `rtc2tcp-auth/cpace-ristretto255-v2`; transitional ECDH scheme is retained for rollout compatibility but downgrade is refused by the scheme-pin check; added parametric round-trip tests across schemes, a CPACE identity-share rejection test, and a downgrade-refusal test.
- [x] 2026-04-18: Milestone 3 kickoff — synchronized `README.md`, `SECURITY-NOTES.md`, and `THREAT-MODEL.md` with the CPACE-Ristretto255 reality and removed the remaining "placeholder" language; added `CHANGELOG.md` with the Milestone 2 cutover entry; fleshed out the Milestone 3 plan (audit prep, broker/peer hardening, release, paper).
- [x] 2026-04-18: Landed transcript/HKDF/HMAC/pairing-salt byte-pin tests and wire-format golden tests for all three `Message` kinds in `internal/auth/auth_kat_test.go`; narrowed the broker-to-peer `error` surface so `register-failed`, `pairing-failed`, and `relay-failed` emit a fixed per-code message instead of raw Go error text; injectable `rng` threaded through the authenticator for future deterministic-scalar tests if the upstream primitive learns to respect it.
- [x] 2026-04-18: Landed `FuzzStep` native-fuzzer target asserting Step invariants (no panic, error⇒FAILED, FAILED is terminal, done⇒SUCCEEDED+32-byte key); broker waiter/session TTL + janitor with `collectStale` unit-tested directly; structured `auth_failure` log line on the peer with a fixed reason enum; `runListener` goroutine leak fixed.
- [x] 2026-04-18: Peer `--target`/`--listen` validation via `config.ValidateAddress` (unspecified/multicast rejected; listen requires IP literal); broker per-source-IP WebSocket-upgrade rate limiter (30/min, burst 10, janitor-swept idle cleanup) with HTTP 429 on exhaustion; GitHub Actions CI workflow with cross-platform build/vet/race tests, short fuzz run, gofmt check, and `go mod tidy` drift check.
- [x] 2026-04-18: Release hardening block — `Makefile` with reproducible `-trimpath`/`-ldflags`/CGO=0 build targets; `.github/workflows/release.yml` cross-compiles 5 platforms on `v*` tags, generates `SHA256SUMS`, signs keyless via Sigstore cosign, and uploads to a GitHub Release; `SECURITY.md` added with private reporting, scope, disclosure timeline, safe-harbour, and the cosign verification recipe; README build section now shows the reproducible recipe and links to `SECURITY.md`.
- [x] 2026-04-18: Structured-log block — new `internal/logx.Event(prefix, event, kv...)` formatter unit-tested for quoting/escaping/ordering; broker, peer, session, and tunnel bridge now emit `<prefix>: event=<name> k=v ...` lines with `session_id` / `peer_id` / `rendezvous_token` / `source_ip` fields leading every session-scoped line. Structural downgrade-refusal assertion added to the peer: `authenticator.Name() == auth.SchemeCPACEV2` must hold at startup.
- [x] 2026-04-18: Audit-prep doc block — `docs/authenticator-design.md` ADR records the scheme-choice rationale; `PROTOCOL.md` gets an Implementation Map table cross-referencing every normative section to the enforcing code symbol; `internal/auth/auth_bench_test.go` adds handshake microbenchmarks (full CPACE ~6.7 ms/op, transitional ~7.0 ms/op, `buildTranscript` ~0.5 µs, `Message` marshal ~0.3 µs on a Ryzen 7 5800X); `paper/OUTLINE.md` seeds the technical-paper structure and explicitly defers drafting until external audit input is in.
