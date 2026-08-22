# V1 readiness

A checklist for deciding whether Sindook is ready for a 1.0.0 release. It
separates work that is code (Completed / Required before v0.x.y) from work
that only external parties can provide (independent review, adoption,
fuzzing history). Presence here does not create a deadline; it is the
evidence a future 1.0 decision must be able to point at.

## Completed through v0.8.1

(v0.7.1 was prepared but never tagged or published; its changes are part
of v0.8.1. See docs/CHANGELOG.md.)

- Version resolution: release binaries and `go install @v0.8.1` report the
  exact tag; source-tree builds report `0.8.0-dev` with commit provenance.
- Concurrency-safe X-Wing key lifecycle: Wipe/Seed/Decapsulate serialize on
  a per-key mutex, Wipe is idempotent and drops expanded key material, and
  use after Wipe fails closed.
- `contacts list` prints short `sha256:` fingerprints; `show` and `-json`
  carry full keys.
- `doctor` reports the unsupported-memory-lock platform as a warning (not
  an error) and carries executable remediations, including
  `sindook pubkey @default` for a missing default public key.
- Gated draft-first release pipeline: full CI before the draft is created,
  and a verify job that re-checks checksums, Sigstore signature, SBOM, and
  build provenance before promoting the draft to public.
- Compatibility fixtures produced by the released v0.6.0 binary
  (`box/testdata/v060-*.sindook`), pinned into the test suite.
- Installer and package-manifest improvements: fail-closed installer
  checksum handling and multi-file winget manifests.

## Completed in v0.9 development

- Public Go API decision: `box` (seal, open, rewrap, inspect, selftest)
  and `xwing` are the public, versioned library API with the stability
  policy in docs/COMPATIBILITY.md; the engine moved from `internal/box`
  to the top-level `box` package, and everything under `internal/` is
  explicitly not an API.
- Continuous fuzzing: all fifteen declared fuzz targets build under
  derived guards, daily batch runs persist and prune a corpus on the
  `corpora` branch, and the workflow fails if corpus storage stops
  advancing.
- FreeBSD decision: source-only, documented in docs/COMPATIBILITY.md —
  the pure-Go code paths support it, but no CI runner or maintainer
  hardware exists to guarantee artifacts.
- Automated cross-platform installer validation: the installer-validation
  workflow installs the released binary through install.sh (Linux,
  macOS) and install.ps1 (Windows) on real runner hosts and exercises
  version, selftest, doctor, and a seal/open round trip; a weekly
  schedule revalidates the latest release.
- Tagged-module install verification: the installer-validation workflow's
  go-install-from-tag job installs `cmd/sindook@<latest tag>` with a stock
  Go toolchain, asserts the reported version matches the tag, and runs
  selftest; it revalidates on every run and weekly.
- Reproducible-release procedure: scripts/verify-reproducibility.sh
  rebuilds a tag with the release flags and compares SHA-256 with the
  published binary; verified byte-for-byte for v0.8.1 on darwin/arm64
  and documented in docs/RELEASING.md. The release script's doctor
  check is hermetic (scratch HOME, generated identity).

## Required before v0.9.0

- The recovery drill is documented in docs/RELEASING.md; it gets a real
  exercise the first time a release breaks (not a claim until then).

## Mandatory before v1.0.0

- Stable CLI and public Go API commitments (current pre-1.0 policy says
  commands may change with changelog notice; 1.0 freezes the contract in
  docs/COMPATIBILITY.md).
- Stable documented file format and a migration policy with enforced
  compatibility fixtures across every released format version.
- Backward-compatibility evidence: files sealed by every released version
  open with the 1.0 candidate, demonstrated by committed fixtures.
- Cross-platform installer validation on all supported OS/architectures.
- Reliable release reproducibility and provenance: an independent rebuild
  from the tag reproduces the published artifacts, and provenance
  verification is scriptable.
- Long-running fuzzing history: ClusterFuzzLite daily batch runs with a
  persistent corpus (committed to the `corpora` branch) are the current
  mechanism and their accumulated history counts toward this. An OSS-Fuzz
  application (google/oss-fuzz#15899, 2026-07-23) was closed by the
  maintainers because the project does not yet have a wide user base; no
  technical objections were raised against the integration. Reapply once
  real-world adoption grows.
- Security-response process: private reporting, response SLAs, and at
  least one exercised coordinated-disclosure cycle.
- Independent cryptographic and implementation review of the X-Wing
  implementation, the file format, and the key-management design.
- Real external adoption and user feedback: enough production-style use
  outside the author to have found and fixed real-world issues.
- Resolution of all known high-severity issues.
- No misleading security or maturity claims in the documentation,
  README, or release notes.

## Requires external evidence rather than code changes

- An independent security audit (not claimed in v0.8.1; none has been
  performed).
- Continuous fuzzing results from an external service. (OSS-Fuzz
  application google/oss-fuzz#15899 was declined on 2026-07-23 for
  insufficient adoption; reapply once real-world use grows.)
- Adoption metrics and user reports from parties other than the author.
- Confirmation from the IETF process on the final X-Wing RFC status (the
  current integration targets draft-10).

Nothing in v0.8.1 claims an audit, formal verification, OSS-Fuzz
acceptance, perfect memory erasure, or guaranteed secure deletion. Do not
add such claims without the evidence listed above.
