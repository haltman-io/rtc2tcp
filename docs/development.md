# Local development

Run everything from source on one machine.

## Prerequisites

- Go ≥ 1.22 (matches `go.mod`)
- A second terminal (or tmux pane) for each peer

## Three-terminal loop

Terminal 1 — broker:

```bash
go run ./cmd/rtc2tcp-broker --listen :8080
```

Terminal 2 — expose side (share local SSH as the example):

```bash
go run ./cmd/rtc2tcp-peer expose \
  --target 127.0.0.1:22 \
  --broker http://127.0.0.1:8080
```

The expose side prints a `rtc2tcp-peer connect rtc2tcp://…` command.

Terminal 3 — connect side:

```bash
go run ./cmd/rtc2tcp-peer connect rtc2tcp://<token>:<secret>@127.0.0.1:8080 \
  --listen 127.0.0.1:2222
ssh -p 2222 root@localhost
```

Both peers connect via loopback and the broker pairs them locally — handy for iterating without touching the public broker.

## Tests

```bash
go test ./...                  # everything
go test ./internal/rendezvous  # broker pairing + rate limiter + trusted-proxy
go test ./internal/auth        # PAKE / transcript binding
go test ./internal/webrtc      # pion-loopback end-to-end
```

`go vet ./...` and `gofmt -l .` are enforced by CI; run them locally before pushing.

## Project layout

See [architecture.md](architecture.md) for the package map and data flow. See [PROTOCOL.md](../PROTOCOL.md) for the wire format.

## Logging

Both binaries emit structured, grep-friendly lines via `internal/logx`:

```
broker: event=paired session_id=… rendezvous_token=… peer_a=… peer_b=…
peer:   event=auth_confirmed session_id=… scheme=cpace-ristretto255-v2
```

Keys are stable; values containing whitespace/control chars are Go-quoted.
