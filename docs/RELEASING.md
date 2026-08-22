# Releasing Sindook

The release workflow runs only when a `v*` tag is pushed. Ordinary branch pushes cannot publish a release. The pipeline is gated and draft-first: CI must pass on the tagged commit before a GitHub release is created, and a release stays a draft until a verification job has re-checked every artifact.

## Recovering from a broken release

Tags are immutable. If a published release turns out to be broken:

1. Do not move or delete the tag. Leave the broken release published.
2. Fix the problem on main with a regression test that fails on the
   broken code.
3. Cut the next patch version through the normal pipeline (CI gate,
   draft-first, verification job).
4. After the patch is public, verify the recovery end to end:
   `scripts/verify-release.sh X.Y.Z`, `scripts/verify-reproducibility.sh
   vX.Y.Z`, and a manual run of the installer-validation workflow
   (Actions tab), which installs the latest release on real Windows,
   macOS, and Linux hosts and runs the tagged-module `go install` check.
5. Record the incident and the fix in docs/CHANGELOG.md.

This drill gets a real exercise the first time a release breaks; until
then it stays a documented procedure, not a claim.

## Verifying reproducibility

Release binaries are reproducible: building from a tag with the release
flags (`CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=X.Y.Z"`)
reproduces the published binary byte-for-byte, verified for v0.8.1 on
darwin/arm64. Anyone can check a release without trusting the publisher:

```sh
scripts/verify-reproducibility.sh vX.Y.Z
```

The script downloads the published archive, verifies it against
checksums.txt, rebuilds from the tag, and compares SHA-256 hashes.
Run it after each release and record the result in the release notes.
A mismatch means the release was built with a different Go toolchain;
investigate before promoting the draft.

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

Confirm that the version in `cmd/sindook/main.go`, the planned tag, and
compatibility statements agree, and run the consistency check exactly as
the release validation job will:

```sh
scripts/check-version-consistency.sh X.Y.Z
```

The script fails if any man page `.TH` header, the `cmd/sindook/main.go`
dev default, the README install command (`@vX.Y.Z`), or a packaging
manifest does not match `X.Y.Z` (packaging manifests for the *previous*
release are allowed, because they are refreshed only after the new release
is published). The release workflow calls this script for the tag it is
building; the consistency check is therefore CI-enforced.

Do not tag a release that changes the file format or cryptographic
construction without an explicit migration and review plan.

Update the man page headers so the packaged documentation carries the
release version:

```sh
# set "sindook X.Y.Z" and today's date in every .TH line
grep -h '^\.TH' docs/man/*.1
```

Update `docs/CHANGELOG.md` and `docs/COMPATIBILITY.md` in the same commit
so the tag carries accurate documentation.

## Tag and publish

Tags are immutable: never move, delete, or re-create a tag after pushing it.
If a tagged release turns out to be broken, cut a new patch version instead,
because installers, package managers, and provenance verifiers pin the tag.
Push the tag only after the CI checks above have passed on the tagged commit.

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The GitHub Actions release workflow then runs in three gated stages:

1. **CI gate.** The full CI suite (test matrix, race detector, quality
   checks, govulncheck, and the version-consistency script) runs against
   the tagged commit through the reusable `ci` workflow. Nothing else
   starts until it finishes green.
2. **Build and draft.** goreleaser builds the archives for Linux, macOS,
   and Windows, generates checksums and SBOMs, signs the checksums with
   Sigstore keyless signing, attaches GitHub build provenance, and creates
   a **draft** GitHub release. The draft is not publicly visible.
3. **Verify and promote.** The verification job downloads the draft
   artifacts, verifies each SHA-256 against `checksums.txt`, verifies the
   Sigstore bundle, validates the SBOM, verifies the GitHub provenance
   attestation, and re-runs `scripts/check-version-consistency.sh` for the
   tag. Only when every gate passes is the draft promoted to public. A
   release is never published from a tree whose gates failed, and the
   checksums installers download come from the same verified release.

Because stages 2 and 3 both read the immutable tag, an artifact that fails
verification cannot be "fixed in place": cut a new patch version instead.

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

Finally run `sindook version` (it must print the exact tag, e.g.
`sindook X.Y.Z`), complete a recipient seal/open round trip using synthetic
data, and record any release issue before promoting the release in
documentation.

## Publish packaging manifests

The package manifests under `packaging/` carry the hashes of the *previous*
published release until the new release exists. After the release is
published, refresh them from the published `checksums.txt` with the
provided script and commit the change in the same repository:

```sh
scripts/fill-package-hashes.sh X.Y.Z
```

The script fails closed on a missing or mismatched checksum, so a manifest
can never silently point at an unverified archive. Do not edit the
manifest hashes by hand.

### Homebrew

`packaging/homebrew/sindook.rb` carries four `sha256` entries (darwin
amd64/arm64, linux amd64/arm64) plus `version "X.Y.Z"`. After refreshing,
validate the formula locally:

```sh
brew install --formula packaging/homebrew/sindook.rb
brew audit --strict packaging/homebrew/sindook.rb
brew test packaging/homebrew/sindook.rb
```

Publish it by adding `packaging/homebrew` as a tap (for example a
`homebrew-sindook` repository with the formula at the root), or by
submitting it to a central tap the project endorses.

### Scoop

`packaging/scoop/sindook.json` carries the two Windows archive hashes and
`"version": "X.Y.Z"`. The manifest's `autoupdate` block keeps `url` and
`hash` current for later releases, but every published version must start
with real hashes. Validate with `scoop install .\packaging\scoop\sindook.json`
and, if the manifest is published as a bucket, `scoop checkver` and
`scoop update`.

### winget

winget manifests use the multi-file layout: one file per installer under
`packaging/winget/manifests/r/ruddro-roy/sindook/X.Y.Z/` plus the version
and locale files, with `PackageVersion: X.Y.Z` and per-installer
`InstallerSha256` values. The winget CLI's schema validation rejects
placeholder hashes, which is intentional: a manifest with placeholders
must never be submitted. Validate locally:

```powershell
winget validate .\packaging\winget\manifests\r\ruddro-roy\sindook\X.Y.Z\
winget install --manifest .\packaging\winget\manifests\r\ruddro-roy\sindook\X.Y.Z\
```

Publish by opening a pull request to `microsoft/winget-pkgs` using the
validated manifest; after acceptance, users install with
`winget install ruddro-roy.sindook`. Do not submit manifests for unverified
archives: the hashes must come from a release that passed the verification
steps above.

### Concurrency

Manifest refreshes for two releases must never interleave: the manifest
version field, the URLs, and the hashes are checked in as one atomic commit
per release, and `scripts/check-version-consistency.sh X.Y.Z` is re-run
against that commit. If two releases are cut in quick succession, finish
publishing and refreshing the first before tagging the second.
