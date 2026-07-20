# Public Release Guide

This guide applies only to the public GitHub repository and its free bundled packs.

## Before Tagging

- Run `go vet ./...`, `go test ./...`, and `go test -race ./...`.
- Confirm every tracked `control-sets/*.yaml` file has `tier: free`.
- Run `./scripts/package-free-controls.sh` and `./scripts/verify-free-artifact.sh`.
- Run the local SQLite demo: `bash examples/siem-demo/run.sh`.
- Confirm README, configuration, and release notes match the archive.
- Keep the release an `-rc.N` pre-release until control-pack signing is CI/KMS-managed.

## Public Boundary Check

The public repository may contain the universal agent core but no paid-pack content, private backend-service code, credentials, private configuration, customer data, or internal documents.

Before every public commit and tag, review the staged file list:

```bash
git diff --cached --name-only
```

If a file is not clearly free-public material, do not commit it.

## Create a Release

The GitHub Actions workflow builds Linux, macOS, and Windows archives after a `v*` tag is pushed. It publishes a release only after every platform job succeeds.

```bash
VERSION=1.0.0-rc.1
git tag -a v${VERSION} -m "v${VERSION}"
git push origin v${VERSION}
```

Verify that the release contains all platform archives and matching SHA-256 files before announcing it.

## Signing

The currently documented signing process uses a local development key. Do not publish a stable release until signing is managed by CI or KMS. See [docs/SIGNING.md](docs/SIGNING.md).
