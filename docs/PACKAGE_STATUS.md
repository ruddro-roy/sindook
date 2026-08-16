Package-manager publication status (truthful, as of release preparation):

- Homebrew formula (packaging/homebrew/sindook.rb): references v0.6.0 hashes.
  Must be updated to v0.7.0 by scripts/fill-package-hashes.sh after public release.
  Not submitted to upstream Homebrew/core.

- Scoop manifest (packaging/scoop/sindook.json): references v0.6.0 hashes.
  Must be updated to v0.7.0 by scripts/fill-package-hashes.sh after public release.
  Not submitted to Scoop/Main bucket.

- Winget 0.6.0 manifests: published format (multi-file); deleted singleton in working tree.
- Winget 0.7.0 manifests: prepared with correct schema; placeholders (000... hash, 1970-01-01)
  must be filled by scripts/fill-package-hashes.sh after public release.
  Not submitted to winget-pkgs.

Installation paths available:
- Direct binary download + checksum verification (scripts/install.sh, scripts/install.ps1)
- Local Homebrew formula installation (brew install --formula packaging/homebrew/sindook.rb)
- Local Scoop manifest installation (scoop install packaging/scoop/sindook.json)
- Local winget manifest installation (winget install --manifest packaging/winget/manifests/r/ruddro-roy/sindook/0.7.0/)

No claim is made about upstream community repository acceptance.
