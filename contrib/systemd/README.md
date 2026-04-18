# systemd service for `rtc2tcp-broker`

Turn a built `rtc2tcp-broker` binary into a hardened, always-on systemd
service in one command.

## Files

| File                                                     | Purpose                                                                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| [`rtc2tcp-broker.service`](rtc2tcp-broker.service)       | Systemd unit. Runs the broker as a dedicated `rtc2tcp` user with sandboxing enabled.                                |
| [`broker.env.example`](broker.env.example)               | Default configuration. Installed to `/etc/rtc2tcp/broker.env`.                                                      |
| [`install.sh`](install.sh)                               | Installs the binary, unit, env file, creates the service user, then enables and starts the service.                |
| [`uninstall.sh`](uninstall.sh)                           | Stops and removes the service. Keeps the env file and user unless `PURGE=1`.                                        |

## Quick install

From a fresh clone on the broker host:

```bash
make all
sudo ./contrib/systemd/install.sh
```

`install.sh` looks for the binary at `./bin/rtc2tcp-broker` by default
(where `make all` puts it). Override with `BIN_SRC=/path/to/binary
sudo ./install.sh` if you built it elsewhere.

The script is idempotent; re-run it after an upgrade to roll out a new
binary without touching your config.

## Configure

Edit `/etc/rtc2tcp/broker.env` and restart:

```bash
sudo ${EDITOR:-nano} /etc/rtc2tcp/broker.env
sudo systemctl restart rtc2tcp-broker
```

All settings are documented inline in the env file.

## Reverse-proxy pairing

The defaults in [`broker.env.example`](broker.env.example) assume the
broker listens on `127.0.0.1:8080` and sits behind a reverse proxy on
the same host. See [`docs/reverse-proxy.md`](../../docs/reverse-proxy.md)
for Caddy, nginx, and Cloudflare Tunnel recipes.

For direct internet exposure (no proxy), flip the listen address and
clear the trusted-proxy list:

```bash
RTC2TCP_BROKER_LISTEN=:8080
RTC2TCP_BROKER_TRUSTED_PROXIES=
```

## Uninstall

```bash
sudo ./contrib/systemd/uninstall.sh
# or, to also remove /etc/rtc2tcp and the rtc2tcp user:
sudo PURGE=1 ./contrib/systemd/uninstall.sh
```

## Logs

Logs go to the systemd journal:

```bash
sudo journalctl -u rtc2tcp-broker -f            # tail
sudo journalctl -u rtc2tcp-broker --since=1h    # last hour
```

## Privileged-port note

The default `RTC2TCP_BROKER_LISTEN=127.0.0.1:8080` is an unprivileged
port. If you bind below 1024 (e.g. `:443` for direct TLS exposure),
uncomment the `CapabilityBoundingSet` / `AmbientCapabilities` lines in
[`rtc2tcp-broker.service`](rtc2tcp-broker.service) so the sandboxed
process is allowed `CAP_NET_BIND_SERVICE`.
