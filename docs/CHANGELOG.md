# Changelog

All notable user-visible changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses semantic versioning. Pre-1.0 releases may change commands with a
clear entry here, as described in [docs/COMPATIBILITY.md](COMPATIBILITY.md).

## [Unreleased]

### Added

- Recipient groups. `sindook contacts group add team alice bob` saves a
  named recipient list, and `sindook seal -r @team` (or
  `sindook rewrap -r @team`) seals to every member, deduplicated, in
  sorted member order. Groups list saved contacts only (no nesting) and
  share the contact namespace, so a name is never both; removing a
  contact that a group lists is refused until the group is repaired.
  `contacts group list [-json]`, `show`, `add-member`, `remove-member`,
  and `remove` manage them. The config file gains an additive `groups`
  section: older sindook binaries ignore it, and configs without it load
  unchanged.
- `sindook config` for scripted inspection and change of the managed
  configuration: `config get default-identity`, `config set
  default-identity PATH` (validated to exist, stored as an absolute
  path), `config unset default-identity`, and `config list [-json]`.
- Public Go library API. The sealing engine moved from `internal/` to the
  top-level `box` package: `github.com/ruddro-roy/sindook/box` exposes
  `Seal`, `SealRecipient`, `SealPassphrase`, `Open`, `Rewrap`, `Inspect`,
  and `SelfTest`, with `github.com/ruddro-roy/sindook/xwing` as the key
  package. The stability policy is in docs/COMPATIBILITY.md. Code that
  imported the old `internal/box` path must switch to
  `github.com/ruddro-roy/sindook/box`.

### Changed

- Continuous fuzzing now builds all fifteen declared fuzz targets (a
  compiler-wrapper quirk silently skipped targets whose names prefix
  another fuzz function), runs daily with a persistent, pruned corpus on
  the `corpora` branch, and fails the workflow if corpus storage stops
  advancing.

## [v0.8.1] - 2026-08-19 (the first published 0.8.x release; the v0.8.0 tag exists but was never released, see below)

### Added

- One-line installs. `curl -fsSL .../scripts/install.sh | sh` on Linux and
  macOS and `irm .../scripts/install.ps1 | iex` on Windows install the
  latest verified release without administrator rights. Both scripts
  read nothing from standard input or the console, so piping is safe, and
  both still support download-and-run with `--version` pinning.
- Compression: `sindook seal -z` compresses with gzip before encrypting
  and `sindook open -z` reverses it. A 1.5 MB server log seals to a few
  kilobytes. Armor and rewrap work on compressed files unchanged. The
  sealed-file format is unchanged; compression wraps the plaintext above
  the encryption layer, so nothing about the content is revealed beyond
  the compressed length. Opening a compressed file without `-z` writes
  the raw gzip stream, and opening an uncompressed file with `-z` fails
  with a message that names the flag.
- Decompressed-size control: `open -z` and a new `verify -z` cap gzip
  expansion at 1 TiB by default, adjustable with `-max-decompressed`
  (accepts `2G`, `512MiB`, or a byte count; `0` means unlimited). A
  hostile archive that tries to expand past the cap fails with a clear
  error and no partial output is kept. `verify -z` additionally proves a
  compressed archive is fully recoverable, gzip checksum included.
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

### Fixed

- Decompression deadlock. `open -z` on a file whose gzip data is corrupt
  past the 64 KiB pipe buffer blocked forever once the pipe filled,
  because nothing closed the reader end after the decompressor stopped.
  The reader end is now always closed on every exit path, the compressor
  pipe is torn down when sealing fails, and a regression test fails on
  timeout if the deadlock returns.
- Error priority after early decompression failure: the real cause (a
  corrupt stream or the size cap) is reported instead of the internal
  pipe teardown error.
- The README pinned `go install ...@v0.7.1`, a release that was never
  published (latest was v0.7.0), so the command failed for users.

### Changed

- README rewritten around a three-command quickstart with the one-line
  install first, a when-to-use section, and a comparison against age and
  GPG. Documentation wording reviewed: no em dashes, no author name.
- Man pages updated for `-z`, `-max-decompressed`, `verify -z`, the
  credential defaults, and the new examples.
- Corrected release history wording: v0.7.1 was prepared on main but its
  tag was never pushed and no release was published, so every v0.7.1
  claim in the documentation was wrong. Its changes are part of v0.8.1.

## v0.8.0 (tagged, never released; use v0.8.1 or later)

The v0.8.0 tag was pushed with all of the changes in v0.8.1 above, but its
release workflow failed the CI gate before anything was published: two
version tests expected the source-tree dev default and did not account for
a tagged checkout, where Go's build info carries the tag and the release
version correctly wins. Tags are immutable, so the fix and the release
ship as v0.8.1. The v0.8.0 tag has no artifacts and must not be installed
from; nothing about the sealed-file format differs.

## v0.7.1 (prepared, never tagged, never published)

A v0.7.1 recovery release was prepared on main to supersede v0.7.0
without moving the public v0.7.0 tag, but its tag was never pushed and no
GitHub release exists for it. Do not reference v0.7.1 in install commands
or documentation. The prepared changes below shipped in v0.8.1 instead:

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

## v0.7.0 (2026-08-16)

Public release. See the
[v0.7.0 GitHub release](https://github.com/ruddro-roy/sindook/releases/tag/v0.7.0)
for its notes; it was superseded by v0.8.0 after a prepared v0.7.1
recovery release turned out to have never been tagged or published.

## Historical releases

- v0.7.0: public release; superseded by v0.8.0 (a prepared v0.7.1 was
  never tagged or published).
- v0.6.0: exit code `3` split for authentication failures, memory-lock
  downgrade below 96 MiB `RLIMIT_MEMLOCK` to avoid CI OOM, FreeBSD memory
  locking.
- v0.5.0 and earlier predate this changelog; see the Git history and the
  GitHub releases for details.
