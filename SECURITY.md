# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories:

- Open an advisory at `Security -> Advisories -> Report a vulnerability` on the repository.

Do **not** file public issues or pull requests for suspected vulnerabilities. Do not disclose the issue publicly until a fix has been released or we have explicitly agreed on a coordinated disclosure date.

## Scope

In scope:

- `cmd/rtc2tcp-broker`
- `cmd/rtc2tcp-peer`
- `internal/auth`, `internal/signaling`, `internal/rendezvous`, `internal/webrtc`, `internal/tunnel`, `internal/config`
- Release artifacts produced by `.github/workflows/release.yml` and their signatures

Out of scope (please report upstream):

- Third-party libraries (`github.com/pion/...`, `github.com/cloudflare/circl`, `github.com/bwesterb/go-ristretto`, `golang.org/x/...`, `github.com/gorilla/websocket`)
- Operator-supplied STUN/TURN services
- Misconfigured pairing secrets (weak secrets, shared over insecure channels)
- Attacks that require local admin or kernel compromise on both peer hosts

## Acknowledgement and Disclosure

- We aim to acknowledge receipt within 3 business days.
- We aim to provide an initial assessment within 14 days.
- We will coordinate a disclosure timeline with the reporter. As a default, we target 90 days from acknowledgement, shorter if a fix is available sooner, longer if the fix is non-trivial and requires careful rollout.
- We credit reporters by name and link in the release notes unless the reporter requests anonymity.

## What to Include in a Report

Please include, if you can:

- A minimal reproduction (protocol trace, PoC code, or a concrete configuration that triggers the issue).
- The commit hash or release tag you tested against.
- Your assessment of impact.
- Any suggested mitigation.

## Safe Harbour

Good-faith security research on the in-scope components listed above is welcome. Please do not:

- Exfiltrate data that is not yours.
- Disrupt third-party brokers or peer deployments you do not operate.
- Publicly disclose the issue before the coordinated disclosure date.

## Release Integrity

Releases are produced automatically on every push to `main`. The workflow in `.github/workflows/release.yml`:

- Parses Conventional-Commit subjects since the last `v*` tag to compute the next semantic version (`feat!:` / `BREAKING CHANGE:` → major, `feat:` → minor, `fix:` / `perf:` / `refactor:` / `revert:` → patch, everything else → no release).
- Cross-compiles both binaries from the pushed `main` commit using `-trimpath` and build-stamped `Version` / `Commit` via `-ldflags`.
- Packages each target triple as a `.tar.gz` (Unix) / `.zip` (Windows), bundling `README.md`, `LICENSE`, `SECURITY.md`, `PROTOCOL.md`, and `CHANGELOG.md` alongside the binaries.
- Signs the aggregate `SHA256SUMS` keyless via Sigstore cosign using GitHub OIDC; the signature (`SHA256SUMS.sig`) and certificate (`SHA256SUMS.pem`) are attached to the release.

The Fulcio certificate's OIDC subject is `https://github.com/<org>/rtc2tcp/.github/workflows/release.yml@refs/heads/main`, so verification pins the certificate identity to the release workflow running on `main`:

```
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/.+/rtc2tcp/.github/workflows/release.yml@refs/heads/main' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com' \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

A manual release triggered via `workflow_dispatch` uses the same identity regex because workflow-dispatched runs on the default branch still carry `refs/heads/main` as the ref.
