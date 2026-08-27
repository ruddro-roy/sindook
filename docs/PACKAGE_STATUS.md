Package-manager publication status (truthful, as of 2026-08-27, after the
v0.8.1 release):

- Homebrew formula (packaging/homebrew/sindook.rb): published as the
  ruddro-roy/homebrew-sindook tap. Install with
  `brew install ruddro-roy/sindook/sindook`. Refreshed to v0.8.1.
  Not submitted to homebrew-core; core inclusion is adoption-gated.

- Scoop manifest (packaging/scoop/sindook.json): v0.8.1, with autoupdate
  that uses default checksums.txt extraction (no custom regex). Submitted
  to ScoopInstaller/Main on 2026-08-27 (ScoopInstaller/Main#8454, in
  review). Local installation keeps working regardless of the outcome.

- Winget manifests: 0.6.0, 0.7.0, and 0.8.1 multi-file manifests with real
  release URLs and hashes, filled by scripts/fill-package-hashes.sh. The
  package was submitted to microsoft/winget-pkgs on 2026-08-27 as a new
  package at 0.8.1 (microsoft/winget-pkgs#425225, in review).

- AUR: PKGBUILD prepared (packaging/aur/PKGBUILD, source build). The build
  was verified from a pristine v0.8.1 tarball: the binary reports
  `sindook 0.8.1` and `selftest` passes. Not published — publication
  requires the maintainer's AUR SSH key; the steps are in
  packaging/aur/README.md.

Installation paths available:
- Direct binary download + checksum verification (scripts/install.sh, scripts/install.ps1)
- Homebrew tap: `brew install ruddro-roy/sindook/sindook`
- Local Scoop manifest: `scoop install packaging/scoop/sindook.json`
- Local winget manifest: `winget install --manifest packaging/winget/manifests/r/ruddro-roy/sindook/0.8.1/`
- Source build: `go install github.com/ruddro-roy/sindook/cmd/sindook@v0.8.1` (Go 1.26.6+)

No claim is made about community-repository acceptance. Both upstream PRs
are in review; this file is updated when they merge or are declined.
