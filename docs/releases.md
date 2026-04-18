# Release pipeline

Releases are fully automatic. Every push to `main` runs [`.github/workflows/release.yml`](../.github/workflows/release.yml):

1. **Parse commits** since the last `v*` tag as [Conventional Commits](https://www.conventionalcommits.org/).
2. **Compute the next [semver](https://semver.org)**:
   - `feat!:` / `fix!:` / `BREAKING CHANGE:` → **major** bump.
   - `feat:` → **minor** bump.
   - `fix:` / `perf:` / `refactor:` / `revert:` → **patch** bump.
   - Everything else (`chore:`, `docs:`, `ci:`, `test:`, `style:`, `build:`) → no release.
3. **Cross-compile** both binaries for five targets with `-trimpath` and build-stamped `Version` / `Commit` via ldflags.
4. **Package** each target as a `.tar.gz` (Unix) or `.zip` (Windows), bundling `README.md`, `LICENSE`, `SECURITY.md`, `PROTOCOL.md`, and `CHANGELOG.md`.
5. **Sign** — generate an aggregate `SHA256SUMS`, sign it keyless via Sigstore cosign with GitHub OIDC, and attach `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem` plus every archive and its `.sha256` file to an auto-created GitHub Release at `vX.Y.Z`.

Verification recipe: [install.md#verify-before-using](install.md#verify-before-using).

## Cutting a release

Push a conventional commit that bumps:

```bash
git commit -m "feat: add --connection flag to rtc2tcp-peer connect"
git push origin main
```

Within ~3 minutes the GitHub Release appears with signed artifacts.

## Releasing a specific version manually

**Actions → release → Run workflow**, enter `vX.Y.Z` in the `version` field. The commit-subject detector is skipped and that version is released verbatim.

## Skipping a release

Use non-bumping types:

```bash
git commit -m "chore: bump internal fuzzer seed"
git commit -m "docs: reword quick start"
git commit -m "ci: move windows runner to 2025"
```

These push to `main` without creating a release.
