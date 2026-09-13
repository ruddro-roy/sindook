#!/usr/bin/env bash
# Verify the fuzz build wiring stays consistent, so the ClusterFuzzLite
# nightly cannot fail on a stale pointer:
#
# Registration:
#   - every "func FuzzXxx(.. *testing.F)" in *_test.go has a
#     compile_native_go_fuzzer_v2 line in each build script
#     (.clusterfuzzlite/build.sh, oss-fuzz/build.sh)
#   - every compile line names a declared Fuzz function (catches stale
#     entries left behind when a target is removed or renamed)
#   - no two compile lines in a script emit the same $OUT binary name
#   - both scripts emit the same binary name for a given target, so
#     crash artifacts and corpora line up across CFLite and OSS-Fuzz
#
# Toolchain pins:
#   - the Go version pinned in each Dockerfile (the tarball name and the
#     `go version` assertion) matches the "go X.Y.Z" line in go.mod
#   - the go-118-fuzz-build commit each build.sh pins via `go get`
#     matches the commit each Dockerfile checks out when rebuilding the
#     v2 shim (the base image's prebuilt one cannot process the pinned
#     Go release's sources)
#
# The build scripts carry the registration check as an in-container
# guard, but it only fires inside the docker build — a missing line or
# a drifted pin used to surface in the nightly batch run. Running this
# in the ci quality job fails a push or pull request in seconds instead.
#
# usage: scripts/check-fuzz-build.sh
#
# Checks print FAIL: and count toward the exit status; exit 1 if any
# failed. POSIX sh and bash 3.2 compatible: no arrays, no bashisms.

set -u

failures=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

scripts=".clusterfuzzlite/build.sh oss-fuzz/build.sh"
dockerfiles=".clusterfuzzlite/Dockerfile oss-fuzz/Dockerfile"

# --- registration ------------------------------------------------------

# The declared set uses the same extraction the build scripts' guards
# use, so all checks agree on what counts as a fuzz target.
declared=$(grep -rhoE 'func Fuzz[A-Za-z0-9_]+\([A-Za-z]+ \*testing\.F\)' --include='*_test.go' . \
    | sed -E 's/^func (Fuzz[A-Za-z0-9_]+)\(.*/\1/' | sort -u)
if [ -z "$declared" ]; then
    fail 'no fuzz targets found in *_test.go files'
    exit 1
fi

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

# --- toolchain pins ----------------------------------------------------

# go.mod is the source of truth for the toolchain the project needs;
# each Dockerfile installs that exact release because the base image
# ships an older one.
go_mod=$(sed -n 's/^go \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' go.mod | head -n 1)
if [ -z "$go_mod" ]; then
    fail 'go.mod: cannot derive a "go X.Y.Z" line'
fi

for dockerfile in $dockerfiles; do
    if [ ! -f "$dockerfile" ]; then
        fail "$dockerfile: not found"
        continue
    fi
    tar_ver=$(grep -oE 'go[0-9]+\.[0-9]+\.[0-9]+\.linux-amd64\.tar\.gz' "$dockerfile" | head -n 1 \
        | sed 's/^go//; s/\.linux-amd64\.tar\.gz$//')
    grep_ver=$(grep -oE "go version \| grep -q 'go[0-9]+\.[0-9]+\.[0-9]+'" "$dockerfile" | head -n 1 \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    if [ "$tar_ver" != "$go_mod" ]; then
        fail "$dockerfile: Go tarball go${tar_ver:-<none>} != go.mod go $go_mod"
    fi
    if [ "$grep_ver" != "$go_mod" ]; then
        fail "$dockerfile: 'go version' assertion go${grep_ver:-<none>} != go.mod go $go_mod"
    fi
    sha=$(grep -oE 'git checkout -q [0-9a-f]+' "$dockerfile" | head -n 1 | awk '{print $4}')
    if [ -z "$sha" ]; then
        fail "$dockerfile: no go-118-fuzz-build checkout pin found"
        continue
    fi
    for script in $scripts; do
        pin=$(grep -oE 'go-118-fuzz-build/testing@[0-9a-f]+' "$script" | head -n 1 | sed 's/.*@//')
        if [ -z "$pin" ]; then
            fail "$script: no go-118-fuzz-build pin found"
            continue
        fi
        # One side may pin the abbreviated commit; accept either
        # direction of prefix match, reject any other disagreement.
        case "$sha" in
            "$pin"*) ;;
            *) case "$pin" in
                "$sha"*) ;;
                *) fail "$script pins go-118-fuzz-build $pin but $dockerfile checks out $sha" ;;
            esac ;;
        esac
    done
done

if [ "$failures" -gt 0 ]; then
    printf 'fuzz build consistency: %d problem(s)\n' "$failures" >&2
    exit 1
fi
printf 'fuzz build consistency: ok (%s targets, go %s)\n' \
    "$(printf '%s\n' "$declared" | wc -l | tr -d ' ')" "$go_mod"
