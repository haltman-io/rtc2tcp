# Build

## Quick local build

```bash
go build ./cmd/rtc2tcp-broker
go build ./cmd/rtc2tcp-peer
```

Binaries land in the current directory. Fine for iterating.

## Reproducible build (CI / release)

```bash
make all
```

Equivalent to:

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w \
            -X github.com/haltman-io/rtc2tcp/internal/config.Version=$(git describe --tags --always --dirty) \
            -X github.com/haltman-io/rtc2tcp/internal/config.Commit=$(git rev-parse --short HEAD)" \
  -o bin/rtc2tcp-broker ./cmd/rtc2tcp-broker
```

`-trimpath` strips the local build path; `CGO_ENABLED=0` keeps the binary static. The `Version` / `Commit` ldflags show up in `--version` output and in broker log lines.

## Embedding a default broker URL

By default the peer binary falls back to `https://rtc.haltman.io/` when `--broker` is not set. To point a re-branded build at a different broker, stamp it at build time:

```bash
go build -trimpath \
  -ldflags "-X github.com/haltman-io/rtc2tcp/internal/config.DefaultBrokerURL=https://broker.example.com \
            -X github.com/haltman-io/rtc2tcp/internal/config.Version=0.1.0 \
            -X github.com/haltman-io/rtc2tcp/internal/config.Commit=$(git rev-parse --short HEAD)" \
  ./cmd/rtc2tcp-peer
```

The runtime `--broker` flag still overrides the baked-in default; users can always opt out.

## Release pipeline

Release artifacts (per-platform binaries, `SHA256SUMS`, cosign signature + certificate) are produced automatically by [`.github/workflows/release.yml`](../.github/workflows/release.yml) on every push to `main` that bumps a Conventional Commit prefix. See [releases.md](releases.md) for the full workflow and [SECURITY.md](../SECURITY.md) for the verification recipe.
