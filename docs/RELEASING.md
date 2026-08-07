# Releasing Sindook

The release workflow runs only when a `v*` tag is pushed. Ordinary branch pushes cannot publish a release.

## Before tagging

Work from a clean checkout of the intended commit and run:

```sh
gofmt -w $(git ls-files '*.go')
git diff --exit-code
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
(cd interop && go vet ./... && go test ./...)
```

Also run the short fuzz targets used by CI and read the compatibility, security, and user documentation for any user-visible change.

Confirm that the version in `cmd/sindook/main.go`, the planned tag, and compatibility statements agree. Do not tag a release that changes the file format or cryptographic construction without an explicit migration and review plan.

## Tag and publish

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The GitHub Actions release workflow builds archives for Linux, macOS, and Windows, generates checksums and SBOMs, signs the checksums with Sigstore keyless signing, attaches GitHub build provenance, and creates the GitHub release.

## Verify a published release

Download an archive and `checksums.txt` from the matching release. Verify the checksum, then verify the Sigstore bundle and GitHub provenance:

```sh
shasum -a 256 -c checksums.txt
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'github.com/ruddro-roy/sindook' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify sindook_*.tar.gz --owner ruddro-roy
```

Finally run `sindook version`, complete a recipient seal/open round trip using synthetic data, and record any release issue before promoting the release in documentation.