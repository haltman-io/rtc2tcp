# rtc2tcp

```
      _       ____     _
 _ __| |_ ___|___ \ __| |_ ___ _ __
| '__| __/ __| __) / _` __/ __| '_ \
| |  | || (__ / __/ (_| || (__| |_) |
|_|   \__\___|_____\__,_\__\___| .__/
                               |_|
```

`rtc2tcp` tunnels one TCP endpoint over an end-to-end encrypted WebRTC DataChannel. A broker is used for rendezvous and signaling only; it is not in the payload path.

Developed by [haltman.io](https://haltman.io/) · source at [github.com/haltman-io/rtc2tcp](https://github.com/haltman-io/rtc2tcp).

Milestone 1 protocol hardening and Milestone 2 peer authentication are implemented. Peer authentication is a balanced CPACE-Ristretto255 PAKE sourced from `github.com/cloudflare/circl`. The project implementation itself has not yet had an external security review — Milestone 3 scopes that work.

## Quick Start

One-liner: auto-generate secrets, expose local SSH, copy the printed command, paste on the other machine.

```
$ rtc2tcp-peer expose --target 127.0.0.1:22

Session credentials
  rendezvous token: jloh_XmGgi1HgUC3LWY7HA
  pairing secret  : N5mtwubpUlru9fyuOkf1Iw
  broker          : http://127.0.0.1:8080
  target          : 127.0.0.1:22

Run this on the connecting machine:
  rtc2tcp-peer connect rtc2tcp://jloh_XmGgi1HgUC3LWY7HA:N5mtwubpUlru9fyuOkf1Iw@127.0.0.1:8080

Keep this terminal open; closing it ends the tunnel.
```

On the other machine:

```
$ rtc2tcp-peer connect rtc2tcp://jloh_XmGgi1HgUC3LWY7HA:N5mtwubpUlru9fyuOkf1Iw@127.0.0.1:8080
$ ssh -p 2222 user@localhost
```

That is the whole thing. The broker must be reachable by both peers; run one yourself with `rtc2tcp-broker --listen :8080`, or point `--broker` at a shared instance.

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

Start the broker in one terminal:

```bash
go run ./cmd/rtc2tcp-broker --listen :8080
```

In a second terminal, expose a target. Credentials are auto-generated unless you pass them explicitly:

```bash
go run ./cmd/rtc2tcp-peer expose --target 127.0.0.1:22
```

The expose side prints a `rtc2tcp-peer connect rtc2tcp://…` command. Paste it on the third terminal (or a different machine reachable by the same broker):

```bash
go run ./cmd/rtc2tcp-peer connect rtc2tcp://<token>:<secret>@127.0.0.1:8080
ssh -p 2222 user@localhost
```

## Pinning Credentials

For long-lived setups or operator-supplied secrets, skip auto-generation and pin values explicitly. Use a file or environment variable rather than a command-line flag so the pairing secret does not land in shell history:

```bash
export RTC2TCP_RENDEZVOUS_TOKEN=lab-demo
export RTC2TCP_PAIRING_SECRET_FILE=pairing-secret.txt

rtc2tcp-peer expose  --target 127.0.0.1:22
rtc2tcp-peer connect --listen 127.0.0.1:2222
```

Short flags are available for every long option: `-t/--rendezvous-token`, `-s/--pairing-secret`, `-b/--broker`, `-T/--target`, `-l/--listen`, `-q/--quiet`, `-V/--version`.

## Flags Cheat Sheet

| Global                                         | Effect                                            |
| ---------------------------------------------- | ------------------------------------------------- |
| `-q`, `--quiet`, `--silent`                    | Suppress the banner and informational chatter.   |
| `--no-color`                                   | Disable ANSI colours (also respects `NO_COLOR`). |
| `-V`, `--version`                              | Print version and exit.                          |
| `-h`, `--help`                                 | Show help.                                        |

## Install

### Pre-built binaries

Grab a release from [github.com/haltman-io/rtc2tcp/releases](https://github.com/haltman-io/rtc2tcp/releases). Each tag publishes signed binaries for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, and `windows/amd64`, packaged as `.tar.gz` / `.zip` with a `SHA256SUMS` manifest and a cosign signature. Verification recipe is in [SECURITY.md](SECURITY.md).

### From source

```bash
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-peer@latest
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-broker@latest
```

## TURN

TURN remains optional and generic:

```bash
--turn turn:turn.example.net:3478?transport=udp \
--turn-username demo \
--turn-password demo-secret
```

Cloudflare-specific provider work is intentionally deferred and not part of the core protocol design.
