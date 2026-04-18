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

Release binaries built by `.github/workflows/release.yml` are:

- Cross-compiled from a single, checked-out tag using `-trimpath` and build-stamped `Version` / `Commit` via `-ldflags`.
- Accompanied by a `SHA256SUMS` manifest.
- Signed keyless via Sigstore cosign using GitHub OIDC; the signature (`SHA256SUMS.sig`) and certificate (`SHA256SUMS.pem`) are attached to the release.

To verify a downloaded artifact:

```
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/.+/rtc2tcp/.github/workflows/release.yml@refs/tags/.+' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com' \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```
