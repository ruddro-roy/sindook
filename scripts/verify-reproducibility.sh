#!/bin/sh
# Rebuild a released binary from its tag and compare it byte-for-byte with
# the published artifact. Complements scripts/verify-release.sh, which
# checks a release's metadata: this script proves the artifact can be
# reproduced from source by anyone with the same Go toolchain.
#
# Usage: scripts/verify-reproducibility.sh vX.Y.Z [os arch]
#   With no os/arch, verifies the binary for the host platform.
#   Pass an explicit target (e.g. "windows amd64") to cross-verify any
#   released binary; Go cross-compiles with CGO disabled, so this works
#   from any host. Useful for demonstrating that the Windows executables
#   winget validation scans are reproducible from public source.
# Requires: curl, tar, git, and go (GOTOOLCHAIN=auto picks up the pinned
# version from go.mod). Windows targets also need unzip.
set -eu

# Must match the version pinned in .goreleaser.yaml's before hook, or
# Windows rebuilds of tags that embed resources will not be byte-identical.
GO_WINRES=github.com/tc-hib/go-winres@v0.3.3

tag=${1:-}
[ -n "$tag" ] || { echo "usage: $0 vX.Y.Z [os arch]" >&2; exit 2; }
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
version=${tag#v}

if [ "$#" -ge 3 ]; then
	os=$2; arch=$3
else
	case "$(uname -s)/$(uname -m)" in
	Darwin/arm64) os=darwin; arch=arm64 ;;
	Darwin/x86_64) os=darwin; arch=amd64 ;;
	Linux/x86_64) os=linux; arch=amd64 ;;
	Linux/aarch64) os=linux; arch=aarch64 ;;
	*) echo "verify-reproducibility: unsupported host $(uname -s)/$(uname -m)" >&2; exit 1 ;;
	esac
fi
case "$arch" in aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sindook-repro.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

if [ "$os" = windows ]; then
	asset="sindook_${version}_${os}_${arch}.zip"
	binary=sindook.exe
else
	asset="sindook_${version}_${os}_${arch}.tar.gz"
	binary=sindook
fi
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

if [ "$os" = windows ]; then
	unzip -q -o "$tmp/$asset" "$binary" -d "$tmp"
else
	tar -xzf "$tmp/$asset" -C "$tmp" "$binary"
fi
published=$(hash_file "$tmp/$binary")

git clone --quiet --depth 1 --branch "$tag" https://github.com/ruddro-roy/sindook "$tmp/src"

# Releases with packaging/winres/winres.json embed a version-info resource
# and manifest into the Windows executables; regenerate the same .syso
# objects (pinned go-winres) and keep symbols, matching .goreleaser.yaml.
ldflags="-s -w -X main.version=$version"
if [ "$os" = windows ]; then
	if [ -f "$tmp/src/packaging/winres/winres.json" ]; then
		ldflags="-X main.version=$version"
		( cd "$tmp/src" && go run "$GO_WINRES" make \
			--in packaging/winres/winres.json --out cmd/sindook/rsrc \
			--arch "$arch" --file-version "$version" --product-version "$version" )
	fi
fi
( cd "$tmp/src" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
	-ldflags "$ldflags" \
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
