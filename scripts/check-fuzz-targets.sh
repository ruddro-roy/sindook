#!/usr/bin/env bash
# Verify that every fuzz target declared in the repository's *_test.go
# files is registered with a compile_native_go_fuzzer_v2 line in each
# build script:
#   - .clusterfuzzlite/build.sh  (runs in the ClusterFuzzLite image)
#   - oss-fuzz/build.sh          (copy of record for google/oss-fuzz)
#
# The build scripts carry the same check as an in-container guard, but it
# only fires inside the docker build — a missing registration used to
# surface in the nightly batch run. Running it here fails a push or pull
# request in seconds instead.
#
# usage: scripts/check-fuzz-targets.sh
#
# Checks (each failure prints FAIL: and counts; exit 1 if any failed):
#   - every "func FuzzXxx(.. *testing.F)" in *_test.go has a compile line
#     in each build script
#   - every compile line names a declared Fuzz function (catches stale
#     entries left behind when a target is removed or renamed)
#   - no two compile lines in a script emit the same $OUT binary name
#   - both scripts emit the same binary name for a given target, so
#     crash artifacts and corpora line up across CFLite and OSS-Fuzz
#
# POSIX sh and bash 3.2 compatible: no arrays, no bashisms.

set -u

failures=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

# The declared set uses the same extraction the build scripts' guards
# use, so all checks agree on what counts as a fuzz target.
declared=$(grep -rhoE 'func Fuzz[A-Za-z0-9_]+\([A-Za-z]+ \*testing\.F\)' --include='*_test.go' . \
    | sed -E 's/^func (Fuzz[A-Za-z0-9_]+)\(.*/\1/' | sort -u)
if [ -z "$declared" ]; then
    fail 'no fuzz targets found in *_test.go files'
    exit 1
fi

scripts=".clusterfuzzlite/build.sh oss-fuzz/build.sh"
for script in $scripts; do
    if [ ! -f "$script" ]; then
        fail "$script: not found"
        continue
    fi
    for fn in $declared; do
        grep -qE "^compile_native_go_fuzzer_v2 [^ ]+ $fn " "$script" \
            || fail "$script: $fn is declared in a *_test.go but not compiled"
    done
    lines=$(grep -oE '^compile_native_go_fuzzer_v2 [^ ]+ Fuzz[A-Za-z0-9_]+ [A-Za-z0-9_-]+' "$script")
    for fn in $(printf '%s\n' "$lines" | awk '{print $3}' | sort -u); do
        printf '%s\n' "$declared" | grep -qx "$fn" \
            || fail "$script: compiles $fn, which no *_test.go declares"
    done
    for name in $(printf '%s\n' "$lines" | awk '{print $4}' | sort | uniq -d); do
        fail "$script: binary name $name is produced by more than one compile line"
    done
done

# A target's binary name must match across scripts; the guards above only
# prove each script covers the declared set, not that the names agree.
for fn in $declared; do
    name_a=$(grep -oE "^compile_native_go_fuzzer_v2 [^ ]+ $fn [A-Za-z0-9_-]+" .clusterfuzzlite/build.sh | awk '{print $4}')
    name_b=$(grep -oE "^compile_native_go_fuzzer_v2 [^ ]+ $fn [A-Za-z0-9_-]+" oss-fuzz/build.sh | awk '{print $4}')
    if [ -n "$name_a" ] && [ -n "$name_b" ] && [ "$name_a" != "$name_b" ]; then
        fail "$fn: binary name differs (.clusterfuzzlite: $name_a, oss-fuzz: $name_b)"
    fi
done

if [ "$failures" -gt 0 ]; then
    printf 'fuzz target registration: %d problem(s)\n' "$failures" >&2
    exit 1
fi
printf 'fuzz target registration: ok (%s targets)\n' "$(printf '%s\n' "$declared" | wc -l | tr -d ' ')"
