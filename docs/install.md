# Install

`rtc2tcp` ships two binaries:

- **`rtc2tcp-peer`** — the user-facing tool (`expose` + `connect` subcommands).
- **`rtc2tcp-broker`** — the rendezvous/signaling server. Only run this if you're self-hosting; the peer binaries default to `https://rtc.haltman.io/`.

## Pre-built binaries (recommended)

Every push to `main` produces a [GitHub Release](https://github.com/haltman-io/rtc2tcp/releases) with cosign-signed binaries for:

- `linux/amd64`, `linux/arm64`
- `darwin/amd64`, `darwin/arm64`
- `windows/amd64`

Each archive (`.tar.gz` on Unix, `.zip` on Windows) contains the binary plus `README.md`, `LICENSE`, `SECURITY.md`, `PROTOCOL.md`, and `CHANGELOG.md`. A per-release `SHA256SUMS`, `SHA256SUMS.sig`, and `SHA256SUMS.pem` let you verify integrity and provenance end-to-end.

### Verify before using

```bash
# 1. Grab the archive and the sig bundle. Archive names look like
#    rtc2tcp-vX.Y.Z-<os>-<arch>.tar.gz (.zip on windows).
VERSION=v0.1.0
BASE=https://github.com/haltman-io/rtc2tcp/releases/download/${VERSION}
curl -LO ${BASE}/rtc2tcp-${VERSION}-linux-amd64.tar.gz
curl -LO ${BASE}/SHA256SUMS
curl -LO ${BASE}/SHA256SUMS.sig
curl -LO ${BASE}/SHA256SUMS.pem

# 2. Check the hash.
sha256sum -c SHA256SUMS --ignore-missing

# 3. Verify the signature (keyless, Sigstore).
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/.+/rtc2tcp/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com' \
  SHA256SUMS
```

Full verification context: [SECURITY.md](../SECURITY.md).

## From source

Requires Go ≥ 1.22 (see `go.mod`).

```bash
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-peer@latest
go install github.com/haltman-io/rtc2tcp/cmd/rtc2tcp-broker@latest
```

Clone + build (for contributors or to pin commits):

```bash
git clone https://github.com/haltman-io/rtc2tcp
cd rtc2tcp
make all       # puts binaries in ./bin/
```

For reproducible, version-stamped builds with a custom default broker baked in, see [build.md](build.md).

## Platform notes

- **Linux / macOS** — no dependencies; static binaries.
- **Windows** — the binary is signed the same way but not Authenticode-signed. If SmartScreen complains, verify with cosign (above) and unblock.
- **Docker** — not shipped as an image. Any Go-ready base works: `FROM scratch` with the static binary is fine.
