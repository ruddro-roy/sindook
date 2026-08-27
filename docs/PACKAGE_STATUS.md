Package-manager publication status (truthful, as of 2026-08-27, after the
v0.8.1 release):

- Homebrew formula (packaging/homebrew/sindook.rb): published as the
  ruddro-roy/homebrew-sindook tap. Install with
  `brew install ruddro-roy/sindook/sindook`. Refreshed to v0.8.1.
  Not submitted to homebrew-core; core inclusion is adoption-gated.

- Scoop: the ScoopInstaller/Main submission (Main#8454, 2026-08-27) was
  closed the same day by a maintainer under the bucket's popularity
  criterion (a GitHub-hosted tool needs at least 500 stars and 150
  forks); every other Main criterion is met and the PR is reopenable
  once sindook passes the bar. The official bucket lives at
  github.com/ruddro-roy/scoop-bucket: install with `scoop bucket add
  sindook https://github.com/ruddro-roy/scoop-bucket` then `scoop
  install sindook`. The bucket manifest is regenerated daily from the
  release's checksums.txt by a scheduled workflow and was verified
  end to end (upgrade path, malformed-hash refusal); the source of
  truth remains packaging/scoop/sindook.json in this repo.

- Winget manifests: 0.6.0, 0.7.0, and 0.8.1 multi-file manifests with real
  release URLs and hashes, filled by scripts/fill-package-hashes.sh. The
  package was submitted to microsoft/winget-pkgs on 2026-08-27 as a new
  package at 0.8.1 (microsoft/winget-pkgs#425225). Checks 01-07 pass;
  check 08 (Installation Validation) failed twice, the second time with a
  Microsoft Defender flag inside the validation sandbox that current
  signatures do not reproduce: a windows-latest runner scan of both
  release binaries reports no threats (defender-scan workflow run
  33091965668), and the evidence was posted on the PR with a retrigger
  request. `PortableCommandAlias` was removed from all manifests after
  the first failure as the one nonstandard element. If the retrigger
  still blocks, the next step is a false-positive submission to the
  Defender team (maintainer-gated).

- AUR: PKGBUILD prepared (packaging/aur/PKGBUILD, source build). The build
  was verified from a pristine v0.8.1 tarball: the binary reports
  `sindook 0.8.1` and `selftest` passes. Not published — publication
  requires the maintainer's AUR SSH key; the steps are in
  packaging/aur/README.md.

Installation paths available:
- Direct binary download + checksum verification (scripts/install.sh, scripts/install.ps1)
- Homebrew tap: `brew install ruddro-roy/sindook/sindook`
- Scoop bucket: `scoop bucket add sindook https://github.com/ruddro-roy/scoop-bucket` then `scoop install sindook`
- Local winget manifest: `winget install --manifest packaging/winget/manifests/r/ruddro-roy/sindook/0.8.1/`
- Source build: `go install github.com/ruddro-roy/sindook/cmd/sindook@v0.8.1` (Go 1.26.6+)

No claim is made about community-repository acceptance. Both upstream PRs
are in review; this file is updated when they merge or are declined.
