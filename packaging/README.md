# Packaging (cross-platform installers and package managers)

Workstream 3 owns everything under `packaging/`, `scripts/install.sh`,
`scripts/install.ps1`, `scripts/fill-package-hashes.sh`, and
`.github/workflows/package-manifests.yml`.

## Layout

```
packaging/
  homebrew/sindook.rb          Homebrew formula (project-local, not yet in homebrew-core)
  scoop/sindook.json           Scoop manifest (64bit + arm64)
  winget/manifests/r/ruddro-roy/sindook/
    0.6.0/                     Publishable multi-file manifest for the published v0.6.0 release
      ruddro-roy.sindook.yaml
      ruddro-roy.sindook.installer.yaml
      ruddro-roy.sindook.locale.en-US.yaml
    0.7.0/                     Publishable multi-file manifest for the published v0.7.0 release
      ... (same three files)
scripts/
  install.sh                   POSIX sh installer (Linux/macOS), sha256 fail-closed
  install.ps1                  PowerShell installer (Windows), Get-FileHash fail-closed
  fill-package-hashes.sh       fills real digests into all manifests after a release publishes
.github/workflows/package-manifests.yml   CI validation for all of the above
```

## Publication status

As of this commit:

| Package manager | Status |
| --- | --- |
| winget (microsoft/winget-pkgs) | **Not published.** The `0.6.0/` and `0.7.0/` manifests are real local manifests; PR to winget-pkgs is a future step. |
| Scoop (ScoopInstaller buckets) | **Not published.** `packaging/scoop/sindook.json` is real and publishable as a local manifest (Main-bucket criteria TBD). |
| Homebrew (homebrew-core) | **Not published.** This is a project-local formula; upstream homebrew-core submission is a future step. |

Verified against the community repos on 2026-08-16: no `ruddro-roy.sindook`
in microsoft/winget-pkgs, no `sindook.json` in ScoopInstaller/Main, Extras,
Java or Versions, and no `Formula/s/sindook.rb` in homebrew-core (all probes
404 / empty search results).

## Hash-fill procedure (each release)

1. Publish the release (GitHub release with `sindook_<VERSION>_{os}_{arch}`
   assets and `checksums.txt`).
2. Run `scripts/fill-package-hashes.sh VERSION`. It updates:
   - `packaging/homebrew/sindook.rb` (version + the four sha256 values),
   - `packaging/scoop/sindook.json` (version, literal URLs, hashes),
   - `packaging/winget/manifests/r/ruddro-roy/sindook/<VERSION>/*.yaml`
     (PackageVersion, InstallerSha256; ReleaseDate is set to today only
     where the 1970-01-01 placeholder is still present).
   The script fails closed (exit 1) when a required hash is missing from
   `checksums.txt`, when a manifest lacks the expected pattern to replace,
   or when any placeholder remains afterwards. If the target winget directory
   does not exist yet, the script creates it from the latest existing winget
   manifest layout before filling hashes. Re-running with the same version is
   a no-op: `fill-package-hashes.sh <CURRENT_VERSION>` must leave
   `packaging/` byte-identical (there is a CI self-test for this).
3. Let CI validate (`.github/workflows/package-manifests.yml`) and merge.
4. Submit upstream: PR the `<VERSION>` winget directory to
   microsoft/winget-pkgs, and the Scoop JSON to the chosen bucket. Homebrew:
   `brew install ./packaging/homebrew/sindook.rb` works today; a tap or a
   homebrew-core submission is a future step.

For the *next* version, do not hand-edit hashes. After the release exists, run
`scripts/fill-package-hashes.sh <NEXT_VERSION>` and commit the resulting
Homebrew, Scoop, and winget changes together.

## Placeholders are never publishable

Temporary winget manifests created during the hash-fill process use
`InstallerSha256: 000...` and `ReleaseDate: 1970-01-01` only in real manifest
fields. The script replaces those fields before it exits successfully, and CI
has a guard step that fails if any placeholder field remains. Homebrew/Scoop
manifests always carry real digests; before v0.7.1 is published they track the
published v0.7.0 release.

## Using the manifests today

- **Homebrew** (project-local formula):
  `brew install ./packaging/homebrew/sindook.rb`
- **Scoop** (local manifest):
  `scoop install packaging/scoop/sindook.json`
  (a `scoop bucket add` for sindook is a future step)
- **winget** (local manifests):
  `winget install --manifest packaging/winget/manifests/r/ruddro-roy/sindook/0.7.0 --accept-source-agreements --accept-package-agreements`
- **Installer scripts**: `curl -fsSL https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.sh | sh`
  (or download and run) — supports `SINDOOK_VERSION`, `SINDOOK_INSTALL_DIR`
  (default `~/.local/bin` on Unix, `%LOCALAPPDATA%\sindook\bin` on Windows)
  and `SINDOOK_REPO`. Both scripts download the archive **and**
  `checksums.txt` and refuse to install on any checksum or download failure.

## Known limitations

- **winget schema conformance cannot be validated on macOS/Linux** — `winget
  validate` runs only in CI on `windows-latest`. The manifests were modeled
  on a current accepted winget-pkgs zip + nested-portable manifest
  (Derailed.k9s, June 2026) at ManifestVersion 1.6.0. `PortableCommandAlias:
  sindook` is schema-valid per the official 1.6.0 installer schema (only
  when `NestedInstallerType: portable`), though current winget-pkgs
  manifests rarely use it; omitting it would also work because the alias
  then defaults to the exe name.
- **Windows arm64**: the x64 runners cannot execute an arm64 install. CI
  downloads the arm64 zip and verifies its SHA-256 against the Scoop manifest
  instead.
- **Homebrew**: not in homebrew-core; `brew install` from the repo path is
  the current distribution channel.
- **Scoop autoupdate**: `sindook_$version_windows_<arch>.zip` URLs with a
  checksums.txt `$sha256\s+$basename\n` regex (the pattern used by accepted
  Main-bucket manifests such as k9s).
