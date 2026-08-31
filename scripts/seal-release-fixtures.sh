#!/bin/sh
# Seal the per-release compatibility fixtures with a published release
# binary, extending the fixture chain in box/testdata. The binary is
# downloaded from the release and verified against the release's
# checksums.txt BEFORE it seals anything, and every fixture is opened
# again with the same binary before the script reports success: a
# fixture that the sealing binary cannot re-open is a bug in the
# release, not test data. Implements the step documented in
# docs/RELEASING.md ("Seal the next compatibility fixtures") and the
# header comment in box/compat_test.go.
#
# Usage: scripts/seal-release-fixtures.sh X.Y.Z ["flavor line"]
#   X.Y.Z        published release, e.g. 0.11.0 (leading 'v' optional)
#   flavor line  optional one-line description baked into the fixture
#                plaintext after "compatibility fixture: X.Y.Z"
#
# The script creates box/testdata/vXXX-{passphrase,recipient,compressed}.sindook
# (vXXX = first three characters of the version with dots removed, the
# convention of every existing fixture) and prints the constants to add
# to box/compat_test.go: the plaintext, the passphrase, and the base64
# identity. The test cases themselves are added by hand in the follow-up
# commit, following the previous release's block.
#
# Requires: curl, tar (or unzip), sha256sum/shasum, base64, cmp.
set -eu

usage() {
	cat <<'EOF' >&2
usage: seal-release-fixtures.sh X.Y.Z ["flavor line"]
EOF
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage; exit 2; }
case "$1" in v*) version=${1#v} ;; *) version=$1 ;; esac
flavor=${2:-sealed by the published binary}
tag="v$version"

repo_dir=$(cd "$(dirname "$0")/.." && pwd)
testdata=$repo_dir/box/testdata

case "$(uname -s)/$(uname -m)" in
Darwin/arm64) os=darwin; arch=arm64 ;;
Darwin/x86_64) os=darwin; arch=amd64 ;;
Linux/x86_64) os=linux; arch=amd64 ;;
Linux/aarch64) os=linux; arch=arm64 ;;
*) echo "seal-release-fixtures: unsupported host $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

prefix="v$(printf '%s' "$version" | tr -d . | cut -c1-3)"
for kind in passphrase recipient compressed; do
	if [ -e "$testdata/$prefix-$kind.sindook" ]; then
		echo "seal-release-fixtures: $testdata/$prefix-$kind.sindook already exists; refusing to overwrite" >&2
		echo "  fixtures are sealed once, by the published binary of $tag" >&2
		exit 1
	fi
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sindook-seal.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
umask 077

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
	echo "seal-release-fixtures: $asset not listed in checksums.txt" >&2
	exit 1
}
[ "$(hash_file "$tmp/$asset")" = "$expected" ] || {
	echo "seal-release-fixtures: archive checksum mismatch against published checksums.txt" >&2
	exit 1
}

if [ "$os" = windows ]; then
	unzip -q -o "$tmp/$asset" "$binary" -d "$tmp"
else
	tar -xzf "$tmp/$asset" -C "$tmp" "$binary"
fi
sindook="$tmp/$binary"
chmod +x "$sindook"

[ "$("$sindook" version | awk '{print $2}')" = "$version" ] || {
	echo "seal-release-fixtures: binary reports a different version than $tag" >&2
	"$sindook" version >&2
	exit 1
}

passphrase="fixture-passphrase-$prefix"
printf 'compatibility fixture: %s\n%s\n' "$version" "$flavor" > "$tmp/plain.txt"
printf '%s\n' "$passphrase" > "$tmp/pass.txt"
"$sindook" keygen -o "$tmp/id.key"

"$sindook" seal -passfile "$tmp/pass.txt" -o "$tmp/$prefix-passphrase.sindook" "$tmp/plain.txt"
"$sindook" seal -r "$tmp/id.key.pub" -o "$tmp/$prefix-recipient.sindook" "$tmp/plain.txt"
"$sindook" seal -z -r "$tmp/id.key.pub" -o "$tmp/$prefix-compressed.sindook" "$tmp/plain.txt"

"$sindook" open -passfile "$tmp/pass.txt" -o "$tmp/check1" "$tmp/$prefix-passphrase.sindook"
"$sindook" open -i "$tmp/id.key" -o "$tmp/check2" "$tmp/$prefix-recipient.sindook"
"$sindook" open -z -i "$tmp/id.key" -o "$tmp/check3" "$tmp/$prefix-compressed.sindook"
cmp -s "$tmp/plain.txt" "$tmp/check1" && cmp -s "$tmp/plain.txt" "$tmp/check2" && cmp -s "$tmp/plain.txt" "$tmp/check3" || {
	echo "seal-release-fixtures: a fixture did not round-trip with the sealing binary; not a fixture, a release bug" >&2
	exit 1
}

for kind in passphrase recipient compressed; do
	cp "$tmp/$prefix-$kind.sindook" "$testdata/$prefix-$kind.sindook"
done

echo "sealed: $tag fixtures $prefix-{{passphrase,recipient,compressed}}.sindook into box/testdata/"
echo
echo "Add the following constants and test cases to box/compat_test.go,"
echo "following the previous release's block (the identity is TEST-ONLY"
echo "and lives in the test because *.key files are gitignored):"
echo
printf 'const %sPlaintext = "compatibility fixture: %s\\n%s\\n"\n' "$prefix" "$version" "$flavor"
printf 'const %sPassphrase = "%s"\n' "$prefix" "$passphrase"
echo "const ${prefix}IdentityB64 = \`$(base64 < "$tmp/id.key")\`"
