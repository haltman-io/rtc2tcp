# Pinning credentials

By default, `rtc2tcp-peer expose` auto-generates a fresh rendezvous token and pairing secret on every run and prints them for you to paste into the connect side. That's ideal for one-off sessions.

For long-lived setups (CI runners, persistent bastions, operator-managed infra), pin the values explicitly so both ends can be configured once and forgotten.

## Env vars (preferred)

Use a file or environment variable — never a command-line flag — so the pairing secret does not land in shell history or process listings.

```bash
# Same on both machines.
export RTC2TCP_RENDEZVOUS_TOKEN=lab-demo
export RTC2TCP_PAIRING_SECRET_FILE=pairing-secret.txt
```

Then:

```bash
# On the target machine
rtc2tcp-peer expose --target 127.0.0.1:22

# On the client machine
rtc2tcp-peer connect --listen 127.0.0.1:2222
ssh -p 2222 root@localhost
```

Omitting `--broker` uses the built-in default (`https://rtc.haltman.io/` in official releases).

## The pairing-secret file

```bash
umask 077
openssl rand -base64 24 > pairing-secret.txt
```

Treat it like an SSH private key: readable only by the process that needs it, never committed, never DM'd over a plaintext channel. Anyone with this file and the matching rendezvous token can complete the PAKE and land on your target.

## Short flags

Every long option has a short form:

| Long                      | Short | Notes                                                   |
| ------------------------- | ----- | ------------------------------------------------------- |
| `--rendezvous-token`      | `-t`  | Broker-visible pairing identifier.                      |
| `--pairing-secret`        | `-s`  | Secret itself. Prefer `--pairing-secret-file`.          |
| `--pairing-secret-file`   |       | Path to a file containing the secret.                   |
| `--broker`                | `-b`  | Broker URL (default `https://rtc.haltman.io/`).         |
| `--target`                | `-T`  | `expose` only: HOST:PORT to forward.                    |
| `--listen`                | `-l`  | `connect` only: local HOST:PORT to surface the tunnel.  |
| `--connection`            |       | `connect` only: full `rtc2tcp://…` URL (or positional). |
| `--quiet` / `--silent`    | `-q`  | Suppress banner.                                        |
| `--no-color`              |       | Disable ANSI colours (respects `NO_COLOR`).             |
| `--version`               | `-V`  | Print version and exit.                                 |

See [flags.md](flags.md) for the complete flag reference (peer + broker).
