# Changelog

All notable user-visible changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses semantic versioning. Pre-1.0 releases may change commands with a
clear entry here, as described in [docs/COMPATIBILITY.md](COMPATIBILITY.md).

## [Unreleased]

Target version: v0.8.0.

### Added

- One-line installs. `curl -fsSL .../scripts/install.sh | sh` on Linux and
  macOS and `irm .../scripts/install.ps1 | iex` on Windows install the
  latest verified release without administrator rights. Both scripts
  read nothing from standard input or the console, so piping is safe, and
  both still support download-and-run with `--version` pinning.
- Compression: `sindook seal -z` compresses with gzip before encrypting
  and `sindook open -z` reverses it. A 1.5 MB server log seals to a few
  kilobytes. Armor, rewrap, and verify all work on compressed files
  unchanged. The sealed-file format is unchanged; compression wraps the
  plaintext above the encryption layer, so nothing about the content is
  revealed beyond the compressed length. Opening a compressed file
  without `-z` writes the raw gzip stream, and opening an uncompressed
  file with `-z` fails with a message that names the flag.
- Default identity in daily commands. After `sindook init`, `seal`,
  `open`, `verify`, and `rewrap` use that identity automatically when no
  credential flag is given, printing which identity they used. Explicit
  `-i`, `-r`, `-p`, and `-passfile` flags keep their exact prior meaning,
  and `SINDOOK_CONFIG_DIR` pointed at an empty directory restores the old
  fail-closed behavior for scripts that need it.
- First-run hints. Missing-credential errors now teach the next command
  (`sindook init`), `open` with the wrong identity on a recipient file
  appends a `-p` suggestion, and `rewrap` without new slots names the
  flags that add them.

### Changed

- README rewritten around a three-command quickstart with the one-line
  install first, a when-to-use section, and a comparison against age and
  GPG. Documentation wording reviewed: no em dashes, no author name.
- Man pages updated for `-z`, the credential defaults, and the new
  examples; dev default bumped to `0.8.0-dev`.

### Fixed

- The README pinned `go install ...@v0.7.1`, a release that was never
  published (latest is v0.7.0), so the command failed for users. It now
  pins the real latest release, v0.7.0.

## [v0.7.1] - 2026-08-18

This release supersedes v0.7.0 without moving the public v0.7.0 tag. It is the
first release intended to carry the productization, version-resolution, and
draft-first release pipeline changes below on the tagged source commit.

### Added

- Version resolution via Go module build info: a binary installed with
  `go install github.com/ruddro-roy/sindook/cmd/sindook@v0.7.1` reports
  `sindook 0.7.1` instead of the source-tree dev default. Release builds
  (linker-stamped) report the exact tag, and dev builds stay visibly
  `0.7.1-dev` with commit provenance.
- `contacts list` prints short `sha256:` fingerprints (first 16 bytes of
  SHA-256 over the decoded public key) instead of full keys; `contacts
  show NAME` and `contacts list -json` continue to print full keys.
- `doctor` remediations are executable: a missing default public key now
  points at `sindook pubkey @default > IDENTITY.pub`.
- Compatibility fixtures produced by the released v0.6.0 binary
  (`internal/box/testdata/v060-*.sindook`), pinned into the test suite so
  every future release proves it still opens v0.6.0 files.
- A version-consistency check script
  (`scripts/check-version-consistency.sh`) that verifies man pages, the
  dev-default version, packaging manifests, and README install commands
  agree with a release version; wired into CI.
- Documentation: product contract expanded
  ([docs/COMPATIBILITY.md](COMPATIBILITY.md)), v1 readiness checklist
  ([docs/V1_READINESS.md](V1_READINESS.md)).

### Changed

- X-Wing key lifecycle is concurrency-safe: `Wipe` is idempotent, drops
  expanded key material, serializes with `Seed` and `Decapsulate`, and use
  after `Wipe` fails closed.
- The unsupported-memory-lock platform check in `sindook doctor` is now a
  `warning` (previously `ok`), so the report honestly signals that key
  material may reach swap; warnings are not fatal.
- Release pipeline is gated and draft-first: full CI must pass on the
  tagged commit before the draft release is created, and a verify job
  re-checks checksums, the Sigstore signature, the SBOM, and build
  provenance before the draft is promoted to public.
- winget packaging moved to multi-file manifests; the installers'
  checksum verification fails closed on a missing or mismatched entry.
- Source-tree dev default bumped to `0.7.1-dev`; man pages carry
  `sindook 0.7.1`.

### Fixed

- `doctor` no longer suggests a `pubkey -i @default` invocation that the
  CLI would reject; the remediation uses the accepted positional form.
- The version resolver now honors a real linker-stamped release version before
  tagged-module build info, matching the documented release-build precedence.
- `doctor` and `selftest` now use the same resolved version as `sindook
  version`, so tagged module installs and linker-stamped release binaries do
  not report a stale source-tree dev version in health output.
- Package manifest checks now fail when a manifest declares one version but
  points at another version's release URLs.

## Historical releases

- v0.7.0: public release superseded by v0.7.1 because the immutable tag did
  not contain the productization commit represented here.
- v0.6.0: exit code `3` split for authentication failures, memory-lock
  downgrade below 96 MiB `RLIMIT_MEMLOCK` to avoid CI OOM, FreeBSD memory
  locking.
- v0.5.0 and earlier predate this changelog; see the Git history and the
  GitHub releases for details.
