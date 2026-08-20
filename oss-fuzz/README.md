# OSS-Fuzz integration

These files are the sindook project definition for
[google/oss-fuzz](https://github.com/google/oss-fuzz). They live here so
the fuzzing setup is reviewed with the code it fuzzes; the copy of record
goes in the OSS-Fuzz repo.

## Submission history

- 2026-07-23: PR [google/oss-fuzz#15899](https://github.com/google/oss-fuzz/pull/15899)
  ("projects: add sindook") was closed by an OSS-Fuzz maintainer without
  merge. The stated reason was adoption, not the integration: the project
  "doesn't look mature enough for OSS-Fuzz. We target projects that
  already have a wide user base", with a recommendation to use
  ClusterFuzzLite in the meantime. No technical objections were raised
  against these files. The Google CLA was signed during that PR and
  carries over.
- Interim: continuous fuzzing runs through ClusterFuzzLite
  (`.clusterfuzzlite/`), daily batch mode with a persistent corpus
  branch. See `.clusterfuzzlite/README.md`.

Reapply when the adoption-based objection plausibly no longer holds:
growing external user base, rising criticality score, evidence of
real-world use. At that point, fork google/oss-fuzz, copy these three
files to `projects/sindook/` (`primary_contact` is already set),
open a PR, and reference the earlier thread and CLA signature. The
contact must be a deliverable mailbox a maintainer controls and can
verify with a Google account (GitHub noreply addresses do not
qualify), and it becomes public in the oss-fuzz repo; the address in
project.yaml is already public through this repository's commit
history, so it exposes nothing new. Swap in a dedicated project
mailbox if one exists by then.

## Targets

Fifteen native Go targets — every `Fuzz` function declared in the
repository's test files: eight box header/payload/parser targets
including open, rewrap, rewrap-round-trip, and inspect; the three armor
codec targets; and four X-Wing targets (decapsulation, encapsulation,
key generation, and decapsulation against random identities). The list
is kept complete automatically: guards in both build scripts fail the
build if a declared `Fuzz` function has no compile line, or if a
compile line produces no binary.

Both build scripts use `compile_native_go_fuzzer_v2` and verify every
expected binary exists afterward. The legacy `compile_native_go_fuzzer`
wrapper silently skipped targets whose names are a prefix of another
fuzz function in the same package (it greps `func Name` as a substring),
which is why earlier builds produced only seven of the nine binaries.

## Local verification

From a checkout of github.com/google/oss-fuzz with these three files
copied to `projects/sindook/`:

    printf 'n\n' | python infra/helper.py build_image sindook
    python infra/helper.py build_fuzzers sindook
    python infra/helper.py check_build sindook

The `printf` answers the base-image pull prompt without a TTY. The
pinned base-builder image is amd64; on Apple Silicon the fuzzers build
and run under emulation, so local runs are slower than OSS-Fuzz's
infrastructure.
