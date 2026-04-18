# rtc2tcp

```
      _       ____     _
 _ __| |_ ___|___ \ __| |_ ___ _ __
| '__| __/ __| __) / _` __/ __| '_ \
| |  | || (__ / __/ (_| || (__| |_) |
|_|   \__\___|_____\__,_\__\___| .__/
                               |_|
```

[![Release](https://img.shields.io/github/v/release/haltman-io/rtc2tcp?include_prereleases&sort=semver&color=blue)](https://github.com/haltman-io/rtc2tcp/releases)
[![License](https://img.shields.io/github/license/haltman-io/rtc2tcp?color=green)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/haltman-io/rtc2tcp.svg)](https://pkg.go.dev/github.com/haltman-io/rtc2tcp)
[![Go Version](https://img.shields.io/github/go-mod/go-version/haltman-io/rtc2tcp?logo=go&label=go)](go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/haltman-io/rtc2tcp)](https://goreportcard.com/report/github.com/haltman-io/rtc2tcp)

[![CI](https://img.shields.io/github/actions/workflow/status/haltman-io/rtc2tcp/ci.yml?branch=main&label=CI&logo=github)](https://github.com/haltman-io/rtc2tcp/actions/workflows/ci.yml)
[![Release Workflow](https://img.shields.io/github/actions/workflow/status/haltman-io/rtc2tcp/release.yml?label=release&logo=github)](https://github.com/haltman-io/rtc2tcp/actions/workflows/release.yml)
[![Last Commit](https://img.shields.io/github/last-commit/haltman-io/rtc2tcp?logo=github)](https://github.com/haltman-io/rtc2tcp/commits/main)
[![Issues](https://img.shields.io/github/issues/haltman-io/rtc2tcp?logo=github)](https://github.com/haltman-io/rtc2tcp/issues)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](#install)

[![Auth: CPACE-Ristretto255](https://img.shields.io/badge/auth-CPACE--Ristretto255-success?logo=letsencrypt&logoColor=white)](PROTOCOL.md)
[![Broker: blind](https://img.shields.io/badge/broker-blind-informational)](SECURITY-NOTES.md)
[![Signed releases: cosign](https://img.shields.io/badge/releases-signed%20(cosign)-success?logo=sigstore&logoColor=white)](SECURITY.md)
[![Downloads](https://img.shields.io/github/downloads/haltman-io/rtc2tcp/total?color=brightgreen&logo=github)](https://github.com/haltman-io/rtc2tcp/releases)
[![Stars](https://img.shields.io/github/stars/haltman-io/rtc2tcp?logo=github&color=yellow)](https://github.com/haltman-io/rtc2tcp/stargazers)

`rtc2tcp` tunnels one TCP endpoint over an end-to-end encrypted WebRTC DataChannel. A broker is used for rendezvous and signaling only; it is not in the payload path.

Developed by [haltman.io](https://haltman.io/) · source at [github.com/haltman-io/rtc2tcp](https://github.com/haltman-io/rtc2tcp).

Milestone 1 protocol hardening and Milestone 2 peer authentication are implemented. Peer authentication is a balanced CPACE-Ristretto255 PAKE sourced from `github.com/cloudflare/circl`. The project implementation itself has not yet had an external security review — Milestone 3 scopes that work.

## Quick Start

Two peers, three commands.

**Expose side** (the machine hosting the TCP service) — share local SSH. `--target` is required; everything else is auto-generated and printed back to you:

```
$ rtc2tcp-peer expose --target 127.0.0.1:22

Session credentials
  rendezvous token: jloh_XmGgi1HgUC3LWY7HA
  pairing secret  : N5mtwubpUlru9fyuOkf1Iw
  broker          : http://127.0.0.1:8080
  target          : 127.0.0.1:22

Run this on the connecting machine:
  rtc2tcp-peer connect rtc2tcp://jloh_XmGgi1HgUC3LWY7HA:N5mtwubpUlru9fyuOkf1Iw@127.0.0.1:8080

The tunnel will surface on the connect side at 127.0.0.1:2222 by default.
Override with --listen HOST:PORT. Keep this terminal open; closing it ends the tunnel.
```

**Connect side** (the machine that will reach the remote target through a local port) — paste the printed command and pick the local port:

```
$ rtc2tcp-peer connect rtc2tcp://jloh_XmGgi1HgUC3LWY7HA:N5mtwubpUlru9fyuOkf1Iw@broker.example.com:8080 --listen 127.0.0.1:2223
$ ssh -p 2223 root@localhost
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

In a second terminal, expose a target (`--target` is required):

```bash
go run ./cmd/rtc2tcp-peer expose --target 127.0.0.1:22
```

The expose side prints a `rtc2tcp-peer connect rtc2tcp://…` command. Paste it on the third terminal (or a different machine reachable by the same broker), and pick the local port where the tunnel should surface:

```bash
go run ./cmd/rtc2tcp-peer connect rtc2tcp://<token>:<secret>@127.0.0.1:8080 --listen 127.0.0.1:2223
ssh -p 2223 root@localhost
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

Grab a release from [github.com/haltman-io/rtc2tcp/releases](https://github.com/haltman-io/rtc2tcp/releases). Each release publishes signed binaries for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, and `windows/amd64`, packaged as `.tar.gz` / `.zip` with a `SHA256SUMS` manifest and a cosign signature. Verification recipe is in [SECURITY.md](SECURITY.md).

Releases are produced automatically on every push to `main` (see [Releases](#releases) below).

### From source

```bash
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-peer@latest
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-broker@latest
```

## Releases

The release pipeline is fully automatic. Every push to `main` runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which:

1. Parses commit subjects since the last `v*` tag as [Conventional Commits](https://www.conventionalcommits.org/).
2. Computes the next [semantic version](https://semver.org):
   - `feat!:` / `fix!:` / `BREAKING CHANGE:` → **major** bump.
   - `feat:` → **minor** bump.
   - `fix:` / `perf:` / `refactor:` / `revert:` → **patch** bump.
   - Everything else (`chore:`, `docs:`, `ci:`, `test:`, `style:`, `build:`) → no release.
3. Cross-compiles both binaries for the five supported targets with `-trimpath` and build-stamped `Version` / `Commit` via ldflags.
4. Packages each target as a `.tar.gz` (Unix) or `.zip` (Windows), bundling `README.md`, `LICENSE`, `SECURITY.md`, `PROTOCOL.md`, and `CHANGELOG.md` alongside the binaries.
5. Generates an aggregate `SHA256SUMS`, signs it keyless via Sigstore cosign with GitHub OIDC, and attaches `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem`, plus every archive and its `.sha256` file to an auto-created GitHub Release at `vX.Y.Z`.

### Cutting a release

Just push conventional commits:

```bash
git commit -m "feat: add --connection flag to rtc2tcp-peer connect"
git push origin main
```

Within ~3 minutes the GitHub Release appears with signed artifacts.

### Releasing a specific version manually

In the GitHub UI under **Actions → release → Run workflow**, enter `vX.Y.Z` in the `version` field. The detector is skipped and that version is released verbatim.

### Skipping a release

Use non-bumping Conventional Commit types:

```bash
git commit -m "chore: bump internal fuzzer seed"
git commit -m "docs: reword quick start"
git commit -m "ci: move windows runner to 2025"
```

These push to `main` without creating a release.

## TURN

TURN remains optional and generic:

```bash
--turn turn:turn.example.net:3478?transport=udp \
--turn-username demo \
--turn-password demo-secret
```

Cloudflare-specific provider work is intentionally deferred and not part of the core protocol design.
