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
files to `projects/sindook/`, add a `primary_contact`, open a PR, and
reference the earlier thread and CLA signature. The contact must be a
deliverable mailbox a maintainer controls and can verify with a Google
account (GitHub noreply addresses do not qualify), and it becomes
public in the oss-fuzz repo; `roy@ruddro.com` is already public
through this repository's commit history, so it exposes nothing new,
or use a dedicated project mailbox if one exists by then.

## Targets

Nine native Go targets, kept in sync with `.clusterfuzzlite/build.sh`:
four box header/payload parsers, the armor decoder, and four X-Wing
targets (decapsulation, encapsulation, key generation, and
decapsulation against random identities). When a target is added to
`.clusterfuzzlite/build.sh`, add it here too.

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
