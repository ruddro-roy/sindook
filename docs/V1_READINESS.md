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
  (`internal/box/testdata/v060-*.sindook`), pinned into the test suite.
- Installer and package-manifest improvements: fail-closed installer
  checksum handling and multi-file winget manifests.

## Required before v0.9.0

- FreeBSD release artifacts, or an explicit decision to keep FreeBSD
  source-only (documented in docs/COMPATIBILITY.md).
- End-to-end verification of each tagged-module install path
  (`go install ...@vX.Y.Z` reports `sindook X.Y.Z`) recorded in the release
  checklist after the tag is public.
- A documented, exercised recovery drill for a broken release: cut a patch
  version, never move a tag, and verify installers pick the patch up.

## Required before v0.9.0

- Public Go API decision: either publish a supported, versioned library
  API (with a stability policy) or state explicitly that only the CLI and
  the `xwing` package are public, as currently documented.
- Automated cross-platform installer validation on real Windows, macOS,
  and Linux hosts (PowerShell installer on Windows in particular), not
  only syntax checks in CI.
- A repeatable, documented reproduction procedure for release artifacts
  (build-from-tag and compare checksums with the published release).

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
