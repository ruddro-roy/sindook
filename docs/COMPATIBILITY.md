# Compatibility promise

## Sealed files

Every file sealed by a released version of sindook opens in every later release. Golden fixtures for each format version are committed to the test suite and checked on every CI run, so a change that breaks old files cannot merge. Format evolution is additive: new slot types and versions extend the header, readers skip slot types they do not know, and existing files are never rewritten except by an explicit rewrap or migrate.

The promise runs forward, not backward. A file sealed in format v3 does not open in sindook 0.4.x or earlier, which predate the format. `seal` writes v3 from 0.5.0 on; pass `-format 2` when a file must be readable by an older build, and check what the recipient runs before sealing for them.

## CLI

Within a major version, existing commands, flags, and exit codes keep their meaning; new ones may appear in minor versions. Machine-facing output (`-json`, exit codes) is stable. Human-readable text is not an interface and may change in any release.

## Go API

`github.com/ruddro-roy/sindook/xwing` tracks the X-Wing Internet-Draft and is draft-stable: a wire-format change in the draft before RFC publication is the one event that may break it, and it will be a major-version event. `internal/` packages are not an API.

## Releases

From v0.4.0 on, every tag is a signed release carrying an SBOM, a cosign keyless signature over the checksums, and SLSA build provenance. The latest release receives fixes; there is no LTS branch yet.
