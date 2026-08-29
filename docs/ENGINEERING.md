# Engineering practices

This page lists the practices behind sindook and links each claim to the
script, test, or workflow that enforces it. Everything below is
checkable in this repository. The [threat model](THREAT_MODEL.md) and
[security model](SECURITY.md) describe what the tool protects against;
this page describes how the code is proven.

## Tests

`go test ./...` runs the draft's published X-Wing vectors, round trips
at chunk boundaries, multi-recipient and mixed-slot cases, golden
fixtures from every released format version, and a tamper suite: bit
flips, truncation, extension, slot stripping, wrong keys, hostile
headers, forced-output safety, and symlink refusal
([box/box_test.go](../box/box_test.go),
[xwing/xwing_test.go](../xwing/xwing_test.go)).

CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) runs the
suite on an OS matrix, in shuffled order, plus a dedicated race-detector
job. A cross-compile step builds the binary for every release target on
non-release pushes, so a platform-only break shows up before tagging.

The `interop` module cross-tests sindook's X-Wing against Cloudflare's
CIRCL and filippo.io's X-Wing, proving byte agreement in both
directions ([interop/interop_test.go](../interop/interop_test.go)). A
divergence from the draft in any of the three implementations fails CI
and the race job. The module has its own go.mod so its dependencies
never link into the CLI.

A timing test guards decapsulation
([xwing/timing_test.go](../xwing/timing_test.go)), and
`sindook selftest` runs the built-in vectors plus a round trip and
tamper check after a fresh install
([cmd/sindook/selftest.go](../cmd/sindook/selftest.go)).

## Fuzzing

Sixteen Go fuzz targets cover the box format, ASCII armor, the X-Wing
implementation, and baseline-record parsing
([box/fuzz_test.go](../box/fuzz_test.go),
[internal/armor/fuzz_test.go](../internal/armor/fuzz_test.go),
[xwing/fuzz_test.go](../xwing/fuzz_test.go),
[internal/baseline/fuzz_test.go](../internal/baseline/fuzz_test.go)).
The count is enforced, not asserted. Both fuzz build scripts,
[.clusterfuzzlite/build.sh](../.clusterfuzzlite/build.sh) and
[oss-fuzz/build.sh](../oss-fuzz/build.sh), fail the build if any declared
`Fuzz` function lacks a compile line, or if any compiled target is
missing from the output.

ClusterFuzzLite batch-fuzzes daily at 02:00 UTC under the address
sanitizer, fails the run if the corpus branch did not advance, and
prunes stale corpus entries
([.github/workflows/cflite_batch.yml](../.github/workflows/cflite_batch.yml)).
Pull requests that touch Go code get a shorter fuzzing pass with SARIF
results ([.github/workflows/cflite_pr.yml](../.github/workflows/cflite_pr.yml)).
Every CI run smoke-tests a subset of the targets.

## The concurrency contract

Rewrapping an identity concurrent with its wipe must linearize:
`Decapsulate` either completes with the pre-wipe key or fails with a
wiped-key error, never both, never a torn read.
[xwing/lifecycle_test.go](../xwing/lifecycle_test.go) stresses this with
concurrent wipers and decapsulators, synchronized by an atomic wipe
counter rather than clock reads, because wall-clock ordering across
goroutines can land in the same scheduler tick and lie about order.
[TestWipeInvalidatesKey](../xwing/xwing_test.go) pins the serial
contract.

## Release engineering

Releases are tagged, gated, and draft-first
([.github/workflows/release.yml](../.github/workflows/release.yml)).
CI must pass on the tagged commit before anything builds. goreleaser
then produces archives with checksums, SBOMs, a Sigstore keyless
signature, and GitHub build provenance, into a draft release. A separate
verification job
([scripts/verify-release.sh](../scripts/verify-release.sh)) re-checks
every artifact against the checksums file, the signature bundle, the
SBOM, and the provenance attestation before the draft is promoted. A
release is never published from a tree whose gates failed. The full
procedure, including recovery from a broken release, is
[RELEASING.md](RELEASING.md).

Release notes are not a generated commit log. Promotion applies the
matching [CHANGELOG.md](CHANGELOG.md) section through
[scripts/release-notes.sh](../scripts/release-notes.sh), so the notes a
user reads are the notes the maintainer wrote.

Release binaries rebuild byte-for-byte from their tags.
[scripts/verify-reproducibility.sh](../scripts/verify-reproducibility.sh)
rebuilds a published tag with the release flags and compares SHA-256
hashes, and the go-winres version pinned in
[.goreleaser.yaml](../.goreleaser.yaml) keeps Windows rebuilds
identical. Anyone can check a release without trusting the publisher.

Installers are exercised on real runner hosts for all three platforms by
the installer-validation workflow
([.github/workflows/installer-validation.yml](../.github/workflows/installer-validation.yml)),
and published Windows binaries are scanned with Microsoft Defender to
surface false positives early
([.github/workflows/defender-scan.yml](../.github/workflows/defender-scan.yml)).

## Compatibility enforcement

Version strings must agree across every man page `.TH` line, the dev
default in `cmd/sindook/main.go`, the README install pin, and the
packaging manifests.
[scripts/check-version-consistency.sh](../scripts/check-version-consistency.sh)
fails on any mismatch, and both CI and the release pipeline run it, so a
release cannot be built from a tree with drifting versions.

The file format is pinned by a fixture chain: files sealed by released
binaries for v1, v0.6.0, v0.9.0, and v0.10.0 live in
[box/testdata/](../box/testdata/) and are opened by
[box/compat_test.go](../box/compat_test.go) on every test run. Each
release extends the chain with fixtures sealed by the just-published
binary, never a local build, because the fixtures must prove what
shipped ([RELEASING.md](RELEASING.md)). The byte-level layout is
specified in [FORMAT.md](FORMAT.md) and the machine-facing contract in
[COMPATIBILITY.md](COMPATIBILITY.md).

## Supply chain

govulncheck runs on every CI push, CodeQL analyzes the Go code on push
and weekly, and the OpenSSF Scorecard runs weekly
([.github/workflows/ci.yml](../.github/workflows/ci.yml),
[codeql.yml](../.github/workflows/codeql.yml),
[scorecard.yml](../.github/workflows/scorecard.yml)). The CLI's runtime
dependencies are three golang.org/x modules; everything else in the
standard library.

## Honest limits

The [README](../README.md#security-posture-honestly) states the posture
plainly: pre-1.0, no independent audit, no FIPS validation, and no
quantum-proof claim, because no honest tool can make one. Known limits
of `shred` and fast `rewrap` are documented where those commands are,
and the packaging status page records exactly which package managers
carry which version, including the ones still pending
([PACKAGE_STATUS.md](PACKAGE_STATUS.md)).
