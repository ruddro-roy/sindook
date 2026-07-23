# Compatibility promise

## Sealed files

Every file sealed by a released version of sindook opens in every later release. Golden fixtures for each format version are committed to the test suite and checked on every CI run, so a change that breaks old files cannot merge. Format evolution is additive: new slot types and versions extend the header, readers skip slot types they do not know, and existing files are never rewritten except by an explicit rewrap.

## CLI

Within a major version, existing commands, flags, and exit codes keep their meaning; new ones may appear in minor versions. Machine-facing output (`-json`, exit codes) is stable. Human-readable text is not an interface and may change in any release.

## Go API

`github.com/ruddro-roy/sindook/xwing` tracks the X-Wing Internet-Draft and is draft-stable: a wire-format change in the draft before RFC publication is the one event that may break it, and it will be a major-version event. `internal/` packages are not an API.

## Releases

From v0.4.0 on, every tag is a signed release carrying an SBOM, a cosign keyless signature over the checksums, and SLSA build provenance. The latest release receives fixes; there is no LTS branch yet.
