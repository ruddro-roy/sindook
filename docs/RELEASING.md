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

For an end-user release, also run the installer syntax checks and confirm the
archive names remain compatible with `scripts/install.sh` and
`scripts/install.ps1`:

```sh
sh -n scripts/install.sh
goreleaser check
```

On Windows, parse the PowerShell installer before tagging:

```powershell
[scriptblock]::Create((Get-Content -Raw .\scripts\install.ps1)) | Out-Null
```

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

For a Windows ZIP, substitute the selected `.zip` archive in the provenance
command. The PowerShell installer performs the SHA-256 check automatically;
use `Get-FileHash -Algorithm SHA256 ARCHIVE.zip` for a manual comparison.

Finally run `sindook version`, complete a recipient seal/open round trip using synthetic data, and record any release issue before promoting the release in documentation.

## Publish packaging manifests

The package manifests under `packaging/` are prepared for the release with
placeholder hashes. Fill them with the SHA-256 values from the published
release's `checksums.txt` and commit the change in the same repository.

### Homebrew

Fill the four `sha256` entries in `packaging/homebrew/sindook.rb` from the
published archives:

```sh
shasum -a 256 sindook_0.5.0_darwin_amd64.tar.gz
shasum -a 256 sindook_0.5.0_darwin_arm64.tar.gz
shasum -a 256 sindook_0.5.0_linux_amd64.tar.gz
shasum -a 256 sindook_0.5.0_linux_arm64.tar.gz
```

Then validate the formula locally:

```sh
brew install --formula packaging/homebrew/sindook.rb
brew audit --strict packaging/homebrew/sindook.rb
brew test packaging/homebrew/sindook.rb
```

Publish it by adding `packaging/homebrew` as a tap (for example a
`homebrew-sindook` repository with the formula at the root), or by
submitting it to a central tap the project endorses.

### Scoop

Fill the `hash` values in `packaging/scoop/sindook.json` with the matching
`sha256:...` entries from the release's `checksums.txt` (computed on
Windows with `Get-FileHash -Algorithm SHA256 ARCHIVE.zip`):

```powershell
Get-FileHash -Algorithm SHA256 .\sindook_0.5.0_windows_amd64.zip
Get-FileHash -Algorithm SHA256 .\sindook_0.5.0_windows_arm64.zip
```

The manifest's `autoupdate` block keeps `url` and `hash` current for later
releases, but every published version must start with real hashes. Validate
with `scoop install .\packaging\scoop\sindook.json` and, if the manifest is
published as a bucket, `scoop checkver` and `scoop update`.

### winget

Fill `InstallerSha256` for both installers in
`packaging/winget/manifests/r/ruddro-roy/sindook/0.5.0/sindook.yaml` and set
the `ReleaseDate` to the tag date. The winget CLI's schema validation rejects
the placeholder hashes, which is intentional: a manifest with placeholders
must never be submitted. Validate locally:

```powershell
winget validate .\packaging\winget\manifests\r\ruddro-roy\sindook\0.5.0\sindook.yaml
winget install --manifest .\packaging\winget\manifests\r\ruddro-roy\sindook\0.5.0\sindook.yaml
```

Publish by opening a pull request to `microsoft/winget-pkgs` using the
validated manifest; after acceptance, users install with
`winget install ruddro-roy.sindook`. Do not submit manifests for unverified
archives: the hashes must come from a release that passed the verification
steps above.
