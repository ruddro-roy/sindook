#!/bin/sh
# Rebuild a released binary from its tag and compare it byte-for-byte with
# the published artifact. Complements scripts/verify-release.sh, which
# checks a release's metadata: this script proves the artifact can be
# reproduced from source by anyone with the same Go toolchain.
#
# Usage: scripts/verify-reproducibility.sh vX.Y.Z
# Requires: curl, tar, git, and go (GOTOOLCHAIN=auto picks up the pinned
# version from go.mod).
set -eu

tag=${1:-}
[ -n "$tag" ] || { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
version=${tag#v}

case "$(uname -s)/$(uname -m)" in
Darwin/arm64) os=darwin; arch=arm64 ;;
Darwin/x86_64) os=darwin; arch=amd64 ;;
Linux/x86_64) os=linux; arch=amd64 ;;
Linux/aarch64) os=linux; arch=arm64 ;;
*) echo "verify-reproducibility: unsupported host $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sindook-repro.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

asset="sindook_${version}_${os}_${arch}.tar.gz"
base="https://github.com/ruddro-roy/sindook/releases/download/$tag"
curl -fsSL --retry 3 -o "$tmp/$asset" "$base/$asset"
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt"

expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
[ -n "$expected" ] || {
	echo "verify-reproducibility: $asset not listed in checksums.txt" >&2
	exit 1
}
archive_hash=$(hash_file "$tmp/$asset")
[ "$archive_hash" = "$expected" ] || {
	echo "verify-reproducibility: archive checksum mismatch against published checksums.txt" >&2
	exit 1
}

tar -xzf "$tmp/$asset" -C "$tmp" sindook
published=$(hash_file "$tmp/sindook")

git clone --quiet --depth 1 --branch "$tag" https://github.com/ruddro-roy/sindook "$tmp/src"
( cd "$tmp/src" && CGO_ENABLED=0 go build -trimpath \
	-ldflags "-s -w -X main.version=$version" \
	-o "$tmp/sindook-rebuilt" ./cmd/sindook )
built=$(hash_file "$tmp/sindook-rebuilt")

if [ "$published" = "$built" ]; then
	echo "reproducible: $tag $os/$arch sha256 $published"
else
	echo "verify-reproducibility: NOT reproducible for $tag $os/$arch" >&2
	echo "  published: $published" >&2
	echo "  rebuilt:   $built" >&2
	echo "  A mismatch usually means the release was built with a different Go toolchain." >&2
	exit 1
fi
