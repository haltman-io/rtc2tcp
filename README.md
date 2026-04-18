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
[![CI](https://img.shields.io/github/actions/workflow/status/haltman-io/rtc2tcp/ci.yml?branch=main&label=CI&logo=github)](https://github.com/haltman-io/rtc2tcp/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](docs/install.md)

[![Auth: CPACE-Ristretto255](https://img.shields.io/badge/auth-CPACE--Ristretto255-success?logo=letsencrypt&logoColor=white)](PROTOCOL.md)
[![Broker: blind](https://img.shields.io/badge/broker-blind-informational)](SECURITY-NOTES.md)
[![Signed releases: cosign](https://img.shields.io/badge/releases-signed%20(cosign)-success?logo=sigstore&logoColor=white)](SECURITY.md)
[![Telegram](https://img.shields.io/badge/telegram-haltman__group-26A5E4?logo=telegram&logoColor=white)](https://t.me/haltman_group)

**Tunnel any TCP port over an end-to-end encrypted WebRTC DataChannel.**
No inbound ports, no VPN, no accounts. The broker only introduces peers — it never sees payload bytes.

---

## Install

```bash
# Pre-built, cosign-signed archives for Linux / macOS / Windows
#   → https://github.com/haltman-io/rtc2tcp/releases/latest

# Or from source
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-peer@latest
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-broker@latest
```

Signature verification and platform notes: [docs/install.md](docs/install.md).

---

## Quick Start

Two peers. Three commands. No config.

**Expose** the TCP service you want to share:

```console
$ rtc2tcp-peer expose --target 127.0.0.1:22

Session credentials
  rendezvous token: jloh_XmGgi1HgUC3LWY7HA
  pairing secret  : N5mtwubpUlru9fyuOkf1Iw
  broker          : https://rtc.haltman.io/
  target          : 127.0.0.1:22

Run this on the connecting machine:
  rtc2tcp-peer connect rtc2tcp://jloh_XmGgi1HgUC3LWY7HA:N5mtwubpUlru9fyuOkf1Iw@rtc.haltman.io
```

**Connect** from anywhere — paste the printed command, pick a local port:

```console
$ rtc2tcp-peer connect rtc2tcp://…@rtc.haltman.io --listen 127.0.0.1:2222
$ ssh -p 2222 root@localhost
```

That's the whole thing. The tunnel is end-to-end encrypted; the broker cannot read it.

---

## Examples

| Goal                                  | Expose                                              | Connect                                                                    |
| ------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------- |
| SSH into a box behind NAT             | `rtc2tcp-peer expose -T 127.0.0.1:22`               | `rtc2tcp-peer connect <url> -l 127.0.0.1:2222` → `ssh -p 2222 user@localhost` |
| Reach an internal HTTP admin panel    | `rtc2tcp-peer expose -T 10.0.0.5:8080`              | `rtc2tcp-peer connect <url> -l 127.0.0.1:8080` → `http://localhost:8080`   |
| Access a Postgres / MySQL inside a VPC | `rtc2tcp-peer expose -T 10.0.0.12:5432`             | `rtc2tcp-peer connect <url> -l 127.0.0.1:5432` → `psql -h localhost`       |
| RDP to a Windows host                 | `rtc2tcp-peer expose -T 127.0.0.1:3389`             | `rtc2tcp-peer connect <url> -l 127.0.0.1:3389`                             |

Pin credentials instead of generating them each run — [docs/pinning-credentials.md](docs/pinning-credentials.md).

---

## Public broker

**`https://rtc.haltman.io/`** is a free, public broker operated by [haltman.io](https://haltman.io/) for community use and testing.

- Blind by design. It sees rendezvous tokens, ICE metadata, and nothing more. Payload is end-to-end encrypted between your peers.
- Best-effort, no SLA. Fine for ad-hoc use, demos, CI, and one-off support calls.
- Rate-limited per IP. If you need guaranteed capacity or you're shipping a product on top, [self-host one](#self-host-a-broker).
- Defaults in the peer binaries already point at it — nothing to configure.

To opt out, pass `--broker <your-url>` or build with `-ldflags "-X …DefaultBrokerURL=…"` ([docs/build.md](docs/build.md)).

---

## Acceptable use

This tool exists for research, education, administration, and legitimate remote access. Using it to commit crimes is not clever and not welcome.

**The following are prohibited when using `rtc.haltman.io`:**

- Ransomware, wipers, stalkerware, or any malware delivery
- Botnet command-and-control
- DDoS, reflection, amplification, or traffic laundering
- Fraud, phishing infrastructure, credential stuffing
- Unauthorised access to systems you don't own or have explicit written permission to reach
- Harassment, doxxing, or "revenge" operations

We do not host criminal operations. Valid abuse reports are reviewed. Confirmed abuse is terminated without notice.

Abuse reports: **root@haltman.io** (PGP key on [haltman.io](https://haltman.io/)).
Security vulnerabilities: see [SECURITY.md](SECURITY.md).

Your responsibility, not ours. The software is offered under the [LICENSE](LICENSE) as-is.

---

## Self-host a broker

Run your own in one command:

```bash
rtc2tcp-broker --listen :8080
```

For a production deploy behind Caddy, nginx, or Cloudflare Tunnel — with TLS, trusted-proxy rate limiting, and a systemd service — see:

- [docs/reverse-proxy.md](docs/reverse-proxy.md) — Caddy, nginx, Cloudflare Tunnel worked examples.
- [contrib/systemd/](contrib/systemd/) — hardened unit + `install.sh` / `uninstall.sh`.

---

## Documentation

| Topic                                                   | File                                                        |
| ------------------------------------------------------- | ----------------------------------------------------------- |
| Install (pre-built, from source, verify signatures)     | [docs/install.md](docs/install.md)                          |
| Build from source (ldflags, reproducible builds)        | [docs/build.md](docs/build.md)                              |
| Architecture (what the broker sees, package layout)     | [docs/architecture.md](docs/architecture.md)                |
| Security overview (auth scheme, state machine, limits)  | [docs/security-overview.md](docs/security-overview.md)      |
| Reverse-proxy setup (Caddy, nginx, Cloudflare Tunnel)   | [docs/reverse-proxy.md](docs/reverse-proxy.md)              |
| Pinning credentials (long-lived setups, env vars)       | [docs/pinning-credentials.md](docs/pinning-credentials.md)  |
| All flags (peer + broker cheat sheet)                   | [docs/flags.md](docs/flags.md)                              |
| TURN relay configuration                                | [docs/turn.md](docs/turn.md)                                |
| Local development (run everything from source)          | [docs/development.md](docs/development.md)                  |
| Release pipeline (semver automation)                    | [docs/releases.md](docs/releases.md)                        |
| Wire protocol                                           | [PROTOCOL.md](PROTOCOL.md)                                  |
| Threat model                                            | [THREAT-MODEL.md](THREAT-MODEL.md)                          |
| Security posture + vulnerability reporting              | [SECURITY.md](SECURITY.md)                                  |
| Authenticator design notes                              | [docs/authenticator-design.md](docs/authenticator-design.md) |
| Changelog                                               | [CHANGELOG.md](CHANGELOG.md)                                |

---

## Community

- Telegram: [**t.me/haltman_group**](https://t.me/haltman_group)
- Issues / features: [github.com/haltman-io/rtc2tcp/issues](https://github.com/haltman-io/rtc2tcp/issues)
- Security: [SECURITY.md](SECURITY.md)

---

## Shoutz

- thc.org / [@hackerschoice](https://github.com/hackerschoice) - [@ohmymex](https://github.com/ohmymex)

---

Built by [haltman.io](https://haltman.io/). Source: [github.com/haltman-io/rtc2tcp](https://github.com/haltman-io/rtc2tcp).
