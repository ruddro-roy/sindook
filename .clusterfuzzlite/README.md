# ClusterFuzzLite

ClusterFuzzLite (CFLite) continuously fuzzes sindook's parsers and crypto
code: on every pull request that touches Go code (`.github/workflows/cflite_pr.yml`,
300 s, code-change mode) and daily in batch mode (`.github/workflows/cflite_batch.yml`,
1800 s) followed by a corpus-pruning job (600 s, prune mode). Batch runs
persist their corpus to the `corpora` branch of this repository, so each
run starts from everything earlier runs found, and the workflow fails
unless that branch actually advanced — the storage branch must exist on
origin before the first run (it is an orphan branch initialized with a
single empty marker commit).

## Files

- `Dockerfile` — builds on the OSS-Fuzz `base-builder-go` image, pinned by
  digest so the toolchain is reproducible. It copies the repository into
  `$SRC/sindook` and `build.sh` to `$SRC/build.sh`.
- `build.sh` — compiles each fuzz target with `compile_native_go_fuzzer_v2`
  and installs the resulting binaries under `$OUT` with unique names
  (`fuzz_box_open`, `fuzz_xwing_decapsulate`, ...). The legacy
  `compile_native_go_fuzzer` wrapper silently skips a target whose name is a
  prefix of another fuzz function in the same package (it greps `func Name`
  as a substring), which is why `FuzzArmor` and `FuzzDecapsulate` went
  unbuilt until 2026-08; the `_v2` wrapper matches `func Name(` exactly and
  exits nonzero on ambiguity. The `go-118-fuzz-build` shim is pinned to
  commit `fc5dc53b9db8` in two places — the `go get` in `build.sh` and the
  binary rebuild in the `Dockerfile` (the image ships a Go-1.25 build that
  cannot process go1.26 sources) — keep the two pins, the Go tarball
  SHA-256, and the Go version in `go.mod` in sync when bumping any of
  them. `build.sh` ends with two automatic guards: every `Fuzz` function
  declared in the repository's `*_test.go` files must have a compile line
  in the script, and every compile line must have produced its binary in
  `$OUT` — a fuzz target can never go missing silently again.
- `project.yaml` — declares the project language (`go`).

Adding a fuzz target: write a `FuzzXxx(f *testing.F)` function in the
package's `fuzz_test.go`, then add one `compile_native_go_fuzzer_v2
github.com/ruddro-roy/sindook/<pkg> FuzzXxx fuzz_<unique_name>` line to
`build.sh` (in both this copy and `oss-fuzz/build.sh`). The guards at the
bottom fail the build if a declared function is missing from the script or
a compile line produced no binary. Output names may contain only
alphanumerics, `_`, and `-`.

## Building and running locally

### With the oss-fuzz helper (recommended)

From a checkout of `github.com/google/oss-fuzz`:

```bash
export PATH_TO_PROJECT=<path to this repository>
python infra/helper.py pull_images
python infra/helper.py build_image --external "$PATH_TO_PROJECT"
python infra/helper.py build_fuzzers --external "$PATH_TO_PROJECT" --sanitizer address
python infra/helper.py check_build --external "$PATH_TO_PROJECT" --sanitizer address
python infra/helper.py run_fuzzer --external \
    --corpus-dir=/tmp/sindook-corpus "$PATH_TO_PROJECT" fuzz_xwing_decapsulate
```

### With plain docker

The Dockerfile copies the source in at build time, so no volume mounts are
needed:

```bash
# From the repository root:
docker build -t sindook-cflite -f .clusterfuzzlite/Dockerfile .
# Run build.sh inside the image (produces fuzzers in the container's /out):
docker run --rm sindook-cflite compile
# Validate the built fuzzers start and survive a few seconds of fuzzing:
docker run --rm sindook-cflite check_build
# Run one fuzzer for N seconds (libFuzzer flag):
docker run --rm sindook-cflite /out/fuzz_xwing_decapsulate -max_total_time=30
# Copy fuzzers out for native runs:
docker create --name cflite-extract sindook-cflite
docker cp cflite-extract:/out /tmp/sindook-fuzzers
docker rm cflite-extract
```

## Reproducing and minimizing a crash

When a fuzzer crashes in CI, the crashing input is uploaded as a workflow
artifact (downloadable from the run's summary page; the artifact is a zip of
the crash testcases, one file per crash).

Native replay with the CFLite binary (ASan-instrumented):

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
  /tmp/sindook-fuzzers/fuzz_xwing_decapsulate -runs=100 /path/to/crash-input
```

libFuzzer minimization:

```bash
/tmp/sindook-fuzzers/fuzz_xwing_decapsulate -minimize_crash=1 \
  /path/to/crash-input -max_total_time=60
```

Replay and minimize with the Go fuzzer instead: copy the crash input into the
target's seed corpus as a `go test fuzz v1`-format file (see the files under
`*/testdata/fuzz/`) and run:

```bash
# Baseline replay of every seed; a crashing seed fails here:
go test -run='^$' -fuzz='^FuzzDecapsulate$' -fuzztime=10s ./xwing
# Deterministic replay of one corpus file, named by the first 16 hex chars
# of its sha256:
go test -run='FuzzDecapsulate/<hash>' ./xwing
# When -fuzz itself finds the crash, go test minimizes it automatically and
# writes the minimized input to testdata/fuzz/FuzzDecapsulate/.
```

## Corpus policy

The committed seed corpora under `internal/box/testdata/fuzz/`,
`internal/armor/testdata/fuzz/`, and `xwing/testdata/fuzz/` are the starting
points for every fuzz run and replay under plain `go test`.

Rules:

- Never commit real private keys, real passphrases, or any user file.
- Only license-compatible inputs: outputs produced by the library's own
  selftest fixtures or freshly generated test data using the fixed
  non-secret constants already used by the fuzz targets.
- Keep each seed small (under ~4-5 KB).
- Seeds for targets with multiple arguments use the `go test fuzz v1` text
  format (`[]byte("...")`, `bool(true)`, `uint32(8)`, `byte('\x01')`, one
  value per line); single-`[]byte` targets use the same wrapped format.

## CI artifact and SARIF upload

- Crash artifacts: `run_fuzzers` uploads crashing testcases as workflow
  artifacts automatically; download them from the run summary
  ("Artifacts" panel).
- SARIF: both workflows set `output-sarif: true`, so crash results are
  uploaded as SARIF to GitHub code scanning (Security → Code scanning),
  where each crash appears as a code scanning alert.
- Batch corpora are committed to the `corpora` branch of this repository
  (`storage-repo`/`storage-repo-branch` in `cflite_batch.yml`), which is
  what makes the daily runs compound instead of restarting from the seed
  corpora. The storage URL must carry push credentials — the workflow
  embeds the ephemeral `GITHUB_TOKEN` as `x-access-token`, per the
  ClusterFuzzLite storage-repo pattern; a bare https URL makes every
  corpus push fail with "could not read Username" while the workflow
  still reports success. The batch workflow needs `contents: write` for
  this; keep that permission in sync with the storage-repo settings.
