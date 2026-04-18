# Flags reference

`--help` on either binary is authoritative. This page is a lookup table.

## `rtc2tcp-peer expose` / `connect`

### Target (expose only)

| Flag              | Short | Required | Default | Effect                                                                           |
| ----------------- | ----- | -------- | ------- | -------------------------------------------------------------------------------- |
| `--target HOST:PORT` | `-T` | yes      |         | Local TCP endpoint to share (e.g. `127.0.0.1:22`).                               |

### Listener (connect only)

| Flag              | Short | Default           | Effect                                                                  |
| ----------------- | ----- | ----------------- | ----------------------------------------------------------------------- |
| `--listen HOST:PORT` | `-l` | `127.0.0.1:2222` | Local TCP address where the remote target surfaces.                     |
| `--connection URL`   |       |                   | `rtc2tcp://…` connection string (equivalent to the positional arg).     |

### Rendezvous / auth

| Flag                        | Short | Default | Effect                                                                  |
| --------------------------- | ----- | ------- | ----------------------------------------------------------------------- |
| `--rendezvous-token TOKEN`  | `-t`  |         | Broker-visible pairing token. Auto-generated on expose if not set.      |
| `--pairing-secret SECRET`   | `-s`  |         | Peer pairing secret. Prefer `--pairing-secret-file`.                    |
| `--pairing-secret-file FILE` |      |         | Read the pairing secret from a file.                                    |
| `--broker URL`              | `-b`  | `https://rtc.haltman.io/` | Broker URL. `https://` is canonical; `http://` allowed only for localhost. |

### Network

| Flag                    | Default | Effect                                            |
| ----------------------- | ------- | ------------------------------------------------- |
| `--stun URL`            | Google STUN | STUN server (empty to disable).              |
| `--turn URL`            |         | TURN server URL.                                  |
| `--turn-username NAME`  |         | TURN username.                                    |
| `--turn-password PASS`  |         | TURN password.                                    |

See [turn.md](turn.md) for a full TURN walkthrough.

### Global

| Flag                           | Short | Effect                                           |
| ------------------------------ | ----- | ------------------------------------------------ |
| `--quiet` / `--silent`         | `-q`  | Suppress the banner and informational chatter.   |
| `--no-color`                   |       | Disable ANSI colours (also respects `NO_COLOR`). |
| `--version`                    | `-V`  | Print version and exit.                          |
| `--help`                       | `-h`  | Show help.                                       |

### Environment variables

| Variable                          | Effect                                                       |
| --------------------------------- | ------------------------------------------------------------ |
| `RTC2TCP_RENDEZVOUS_TOKEN`        | Same as `--rendezvous-token`.                                |
| `RTC2TCP_PAIRING_SECRET_FILE`     | Same as `--pairing-secret-file`.                             |
| `NO_COLOR`                        | Disable ANSI colours.                                        |

## `rtc2tcp-broker`

| Flag                          | Default           | Effect                                                                                                  |
| ----------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------- |
| `--listen HOST:PORT`          | `:8080`           | HTTP listen address. Behind a reverse proxy on the same host, prefer `127.0.0.1:8080`.                  |
| `--trusted-proxies LIST`      | *(empty)*         | Comma-separated IPs/CIDRs whose forwarded-for headers are honoured. Empty disables forwarded-for parsing. |
| `--trusted-proxy-header NAME` | `X-Forwarded-For` | `X-Forwarded-For`, `X-Real-IP`, or `CF-Connecting-IP`.                                                  |
| `--rate-limit-per-minute N`   | `30`              | Per-client-IP WebSocket upgrade rate.                                                                   |
| `--rate-limit-burst N`        | `10`              | Per-client-IP burst size.                                                                               |
| `--quiet` / `-q` / `--silent` |                   | Suppress the banner.                                                                                    |
| `--no-color`                  |                   | Disable ANSI colours.                                                                                   |
| `--version` / `-V`            |                   | Print version and exit.                                                                                 |

Reverse-proxy deployment recipes: [reverse-proxy.md](reverse-proxy.md).
