Package-manager publication status (truthful, as of v0.8.1 preparation):

- Homebrew formula (packaging/homebrew/sindook.rb): local-only formula that
  currently references the published v0.7.0 archives. It must be refreshed to
  v0.8.1 with scripts/fill-package-hashes.sh after the v0.8.1 release exists.
  Not submitted to upstream Homebrew/core.

- Scoop manifest (packaging/scoop/sindook.json): local-only manifest that
  currently references the published v0.7.0 archives. It must be refreshed to
  v0.8.1 with scripts/fill-package-hashes.sh after the v0.8.1 release exists.
  Not submitted to Scoop/Main bucket.

- Winget 0.6.0 and 0.7.0 manifests: multi-file local manifests with real
  release URLs and hashes. The v0.8.1 winget directory is created and filled
  by scripts/fill-package-hashes.sh 0.8.0 after the release exists.
  Not submitted to winget-pkgs.

Installation paths available:
- Direct binary download + checksum verification (scripts/install.sh, scripts/install.ps1)
- Local Homebrew formula installation (brew install --formula packaging/homebrew/sindook.rb)
- Local Scoop manifest installation (scoop install packaging/scoop/sindook.json)
- Local winget manifest installation (winget install --manifest packaging/winget/manifests/r/ruddro-roy/sindook/0.7.0/)

No claim is made about upstream community repository acceptance.
