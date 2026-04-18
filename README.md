# rtc2tcp

`rtc2tcp` tunnels one TCP endpoint over an end-to-end encrypted WebRTC DataChannel. A broker is used for rendezvous and signaling only; it is not in the payload path.

This repository is on a security-hardening track. Milestone 1 protocol hardening and Milestone 2 peer authentication are implemented. Peer authentication is a balanced CPACE-Ristretto255 PAKE; the primitive is sourced from `github.com/cloudflare/circl`. The project implementation itself has not yet had an external security review — Milestone 3 scopes that work.

## Binaries

- `rtc2tcp-broker`
- `rtc2tcp-peer`

`rtc2tcp-peer` provides:

- `expose`
- `connect`

## Architecture

- `cmd/rtc2tcp-broker`
  Runs the WebSocket broker and pairs peers by `rendezvous_token`.
- `cmd/rtc2tcp-peer`
  Runs the `expose` or `connect` role.
- `internal/signaling`
  Defines broker messages and the WebSocket client.
- `internal/webrtc`
  Owns the session state machine, WebRTC transport, control channel, and transport-binding logic.
- `internal/auth`
  Holds the interactive peer-authentication subsystem (CPACE-Ristretto255 by default, with a clearly-gated transitional ECDH scheme retained for rollout compatibility only).
- `internal/tunnel`
  Bridges a TCP connection to a WebRTC DataChannel.

The broker sees:

- `rendezvous_token`
- peer mode
- session lifecycle
- SDP and ICE metadata

The broker does not relay:

- TCP payload bytes
- DataChannel plaintext

## Security Shape

Milestone 1 (protocol hardening):

- `rendezvous_token` is broker-visible and operator-supplied.
- `pairing_secret` is separate from the rendezvous token and is loaded locally from a file, environment variable, or compatibility flag.
- Non-control DataChannels are forbidden before authentication; any payload-channel-before-auth event fails the session.
- Broker transport must be `wss://` except for localhost development.
- Broker origin handling is restricted to same-host or no-origin clients.
- Session state is explicit: `INIT`, `RENDEZVOUS`, `SIGNALING`, `AUTH_PENDING`, `AUTHENTICATED`, `STREAMING`, `CLOSING`, `CLOSED`, `FAILED`.

Milestone 2 (peer authentication):

- Peer authentication is an interactive three-message handshake (`hello` -> `accept` -> `confirm`) over the WebRTC control DataChannel.
- Default scheme: CPACE-Ristretto255 (`rtc2tcp-auth/cpace-ristretto255-v2`), using the prime-order group from `github.com/cloudflare/circl/group`.
- Transcript binds scheme, session id, both peer roles, both application-section DTLS fingerprints, and both raw group shares.
- Role-separated HMAC-SHA256 key confirmation over the transcript is compared with `crypto/subtle.ConstantTimeCompare`.
- A transitional ECDH scheme (`rtc2tcp-auth/interactive-ecdh-v2a`) remains compiled in for rollout compatibility. It is not a PAKE; CPACE-configured peers refuse it structurally via the scheme-pin check.

See [PROTOCOL.md](PROTOCOL.md), [THREAT-MODEL.md](THREAT-MODEL.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), and [TODO.md](TODO.md) for the current execution status.

## Known Limitations

- The CPACE-Ristretto255 primitive is sourced from `github.com/cloudflare/circl`; its own test vectors are relied upon. The rtc2tcp integration (transcript construction, key schedule, session-binding material, state machine) has unit and pion-loopback end-to-end coverage but has not yet had an external security review.
- Broker is in-memory only; no persistence, clustering, rate limiting, or abuse controls beyond message-size limits and origin restrictions.
- No TURN credential minting backend; TURN credentials are operator-supplied and static.
- No certificate-pinning UI or out-of-band verifier UX.

## Build

Quick local build:

```bash
go build ./cmd/rtc2tcp-broker
go build ./cmd/rtc2tcp-peer
```

Reproducible build (used by CI and release):

```bash
make all
# equivalent to:
# CGO_ENABLED=0 go build -trimpath \
#   -ldflags "-s -w \
#             -X rtc2tcp/internal/config.Version=$(git describe --tags --always --dirty) \
#             -X rtc2tcp/internal/config.Commit=$(git rev-parse --short HEAD)" \
#   -o bin/rtc2tcp-broker ./cmd/rtc2tcp-broker
```

Embed a default broker URL at build time:

```bash
go build -trimpath \
  -ldflags "-X rtc2tcp/internal/config.DefaultBrokerURL=https://broker.example.com \
            -X rtc2tcp/internal/config.Version=0.1.0 \
            -X rtc2tcp/internal/config.Commit=$(git rev-parse --short HEAD)" \
  ./cmd/rtc2tcp-peer
```

Release artifacts (per-platform binaries, `SHA256SUMS`, cosign signature + certificate) are produced by `.github/workflows/release.yml` on `v*` tags. See [SECURITY.md](SECURITY.md) for the verification recipe.

## Local Run

Create a secret file once:

```bash
printf "lab-secret\n" > pairing-secret.txt
```

Start the broker:

```bash
go run ./cmd/rtc2tcp-broker --listen :8080
```

Run the expose side:

```bash
go run ./cmd/rtc2tcp-peer expose \
  --rendezvous-token lab-demo \
  --pairing-secret-file pairing-secret.txt \
  --broker http://127.0.0.1:8080 \
  --target 127.0.0.1:22
```

Run the connect side:

```bash
go run ./cmd/rtc2tcp-peer connect \
  --rendezvous-token lab-demo \
  --pairing-secret-file pairing-secret.txt \
  --broker http://127.0.0.1:8080 \
  --listen 127.0.0.1:2222
```

Environment variables are also supported:

```bash
export RTC2TCP_RENDEZVOUS_TOKEN=lab-demo
export RTC2TCP_PAIRING_SECRET_FILE=pairing-secret.txt
```

## SSH Example

```bash
ssh -p 2222 localhost
```

## TURN

TURN remains optional and generic:

```bash
--turn turn:turn.example.net:3478?transport=udp \
--turn-username demo \
--turn-password demo-secret
```

Cloudflare-specific provider work is intentionally deferred and not part of the core protocol design.
