#!/usr/bin/env bash
# Verify that every place a Sindook version appears agrees with the target
# release version. The release workflow's validation job runs this with the
# tag it is building; developers run it without arguments to check the
# source tree against the dev default in cmd/sindook/main.go.
#
# usage: scripts/check-version-consistency.sh [VERSION]
#
# Checks (each failure prints FAIL: and counts; exit 1 if any failed):
#   - every docs/man/*.1 .TH line names "sindook VERSION"
#   - cmd/sindook/main.go declares: var version = "VERSION-dev"
#   - with an explicit VERSION (release mode):
#       - README.md shows the pinned install command with @vVERSION
#       - packaging/scoop/sindook.json declares "version": "VERSION"
#       - packaging/homebrew/sindook.rb declares version "VERSION"
#       - packaging/winget/manifests/r/ruddro-roy/sindook/VERSION exists
#         with PackageVersion: VERSION in every manifest
#     Packaging manifests declaring an OLDER version than VERSION are
#     noted but not failed: they are refreshed from the published
#     checksums only after the new release exists
#     (scripts/fill-package-hashes.sh). A manifest declaring a NEWER
#     version than VERSION, or one whose version field disagrees with its
#     own URLs, always fails.
#
# POSIX sh and bash 3.2 compatible: no arrays, no bashisms.

set -u

failures=0

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

note() {
    printf 'note: %s\n' "$1" >&2
}

RELEASE_MODE=no
if [ "$#" -eq 1 ]; then
    VERSION="${1#v}"
    RELEASE_MODE=yes
elif [ "$#" -eq 0 ]; then
    VERSION=$(sed -n 's/^var version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*-dev\)"/\1/p' cmd/sindook/main.go | head -n 1)
    if [ -z "$VERSION" ]; then
        fail 'cannot derive VERSION from '\''var version = "X.Y.Z-dev"'\'' in cmd/sindook/main.go'
        exit 1
    fi
    VERSION="${VERSION%-dev}"
    note "dev mode: derived version $VERSION from cmd/sindook/main.go"
else
    printf 'usage: %s [VERSION]\n' "$0" >&2
    exit 2
fi

# version_lt exits 0 when the first dotted X.Y.Z triple is numerically
# smaller than the second, 1 otherwise.
version_lt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        na = split(a, x, "."); nb = split(b, y, ".");
        for (i = 1; i <= 3; i++) {
            if (x[i] + 0 < y[i] + 0) exit 0
            if (x[i] + 0 > y[i] + 0) exit 1
        }
        exit 1
    }'
}

# version_manifest_url_ok FILE VERSION verifies that a package manifest's
# literal GitHub release URLs agree with its own declared version.
version_manifest_url_ok() {
    file=$1
    declared=$2
    grep -qF "releases/download/v$declared/" "$file" || return 1
    grep -qF "sindook_${declared}_" "$file" || return 1
}

# Every man page .TH line must name the release version.
found=no
for f in docs/man/*.1; do
    if [ ! -f "$f" ]; then
        continue
    fi
    found=yes
    if ! grep -q "^\.TH .*\"sindook $VERSION\"" "$f"; then
        fail "$f: .TH line does not name \"sindook $VERSION\""
    fi
done
if [ "$found" = no ]; then
    fail 'docs/man/*.1: no man pages found'
fi

# The source-tree dev default must match VERSION-dev.
if ! grep -q "^var version = \"$VERSION-dev\"" cmd/sindook/main.go; then
    fail "cmd/sindook/main.go: expected 'var version = \"$VERSION-dev\"'"
fi

if [ "$RELEASE_MODE" = no ]; then
    if [ "$failures" -gt 0 ]; then
        printf 'version consistency: %d problem(s) for %s (dev mode)\n' "$failures" "$VERSION" >&2
        exit 1
    fi
    printf 'version consistency: ok for %s (dev mode)\n' "$VERSION"
    exit 0
fi

# README install commands must pin the release version.
if ! grep -qF "@v$VERSION" README.md; then
    fail "README.md: pinned install command with @v$VERSION not found"
fi

# Scoop manifest.
check_scoop() {
    f=packaging/scoop/sindook.json
    declared=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' "$f" | head -n 1)
    if [ -z "$declared" ]; then
        fail "$f: no \"version\" field"
        return
    fi
    if [ "$declared" = "$VERSION" ]; then
        if ! version_manifest_url_ok "$f" "$declared"; then
            fail "$f: declares $declared but its URLs do not reference v$declared"
        fi
        return
    fi
    if ! version_manifest_url_ok "$f" "$declared"; then
        fail "$f: declares $declared but its URLs do not reference v$declared"
        return
    fi
    if version_lt "$declared" "$VERSION"; then
        note "$f declares $declared (< $VERSION); refreshed from the published checksums after the release (scripts/fill-package-hashes.sh)"
        return
    fi
    fail "$f declares $declared, newer than $VERSION"
}
check_scoop

# Homebrew formula.
check_homebrew() {
    f=packaging/homebrew/sindook.rb
    declared=$(sed -n 's/^[[:space:]]*version "\([^"]*\)"/\1/p' "$f" | head -n 1)
    if [ -z "$declared" ]; then
        fail "$f: no version line"
        return
    fi
    if [ "$declared" = "$VERSION" ]; then
        if ! grep -qF 'v#{version}' "$f"; then
            fail "$f: declares $VERSION but its URLs do not reference v#{version}"
        fi
        return
    fi
    if version_lt "$declared" "$VERSION"; then
        note "$f declares $declared (< $VERSION); refreshed from the published checksums after the release (scripts/fill-package-hashes.sh)"
        return
    fi
    fail "$f declares $declared, newer than $VERSION"
}
check_homebrew

# winget multi-file manifests.
check_winget() {
    root=packaging/winget/manifests/r/ruddro-roy/sindook
    for existing in "$root"/*; do
        if [ ! -d "$existing" ]; then
            continue
        fi
        existing_version=${existing##*/}
        case "$existing_version" in
            [0-9]*.[0-9]*.[0-9]*)
                ;;
            *)
                continue
                ;;
        esac
        for f in "$existing"/*.yaml; do
            if [ ! -f "$f" ]; then
                continue
            fi
            if ! grep -qF "PackageVersion: $existing_version" "$f"; then
                fail "$f: PackageVersion must match directory $existing_version"
            fi
        done
        installer="$existing/ruddro-roy.sindook.installer.yaml"
        locale="$existing/ruddro-roy.sindook.locale.en-US.yaml"
        if [ -f "$installer" ] && ! version_manifest_url_ok "$installer" "$existing_version"; then
            fail "$installer: InstallerUrl values do not reference v$existing_version"
        fi
        if [ -f "$locale" ] && ! grep -qF "releases/tag/v$existing_version" "$locale"; then
            fail "$locale: ReleaseNotesUrl does not reference v$existing_version"
        fi
        if [ -f "$locale" ] && ! grep -qF "blob/v$existing_version/LICENSE" "$locale"; then
            fail "$locale: LicenseUrl does not reference v$existing_version"
        fi
    done

    d=packaging/winget/manifests/r/ruddro-roy/sindook/$VERSION
    if [ ! -d "$d" ]; then
        note "$d does not exist yet; scripts/fill-package-hashes.sh $VERSION will create it from the latest existing winget manifest after the release is published"
        return
    fi
    found=no
    for f in "$d"/*.yaml; do
        if [ ! -f "$f" ]; then
            continue
        fi
        found=yes
        if ! grep -qF "PackageVersion: $VERSION" "$f"; then
            fail "$f: PackageVersion must be $VERSION"
        fi
    done
    if [ "$found" = no ]; then
        fail "$d: no winget manifests found"
    fi
}
check_winget

if [ "$failures" -gt 0 ]; then
    printf 'version consistency: %d problem(s) for %s\n' "$failures" "$VERSION" >&2
    exit 1
fi
printf 'version consistency: ok for %s\n' "$VERSION"
