#!/bin/sh
# Push packaging/homebrew/sindook.rb to the ruddro-roy/homebrew-sindook
# tap. The tap has no sync workflow by design (it is hand-maintained,
# like Homebrew taps usually are), so this is the one command that
# replaces the old copy-and-paste step. Commits as the noreply identity.
#
# Usage: scripts/update-tap.sh X.Y.Z
#
# Fails closed: the local formula must already carry version X.Y.Z with
# real (non-placeholder) SHA-256 digests, and every digest is re-checked
# against the published release checksums.txt before anything is pushed.
# Run scripts/fill-package-hashes.sh X.Y.Z first.
#
# Requires: gh (authenticated), curl, sha256sum/shasum.
set -eu

usage() {
	cat <<'EOF' >&2
usage: update-tap.sh X.Y.Z
EOF
}

[ "$#" -eq 1 ] || { usage; exit 2; }
case "$1" in v*) version=${1#v} ;; *) version=$1 ;; esac
tag="v$version"

repo_dir=$(cd "$(dirname "$0")/.." && pwd)
formula=$repo_dir/packaging/homebrew/sindook.rb
tap=ruddro-roy/homebrew-sindook
committer_name="Ruddro Roy"
committer_email="223927316+ruddro-roy@users.noreply.github.com"

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
	else shasum -a 256 "$1" | awk '{print $1}'; fi
}

grep -q "version \"$version\"" "$formula" || {
	echo "update-tap: packaging/homebrew/sindook.rb does not carry version $version" >&2
	echo "  run scripts/fill-package-hashes.sh $version first" >&2
	exit 1
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sindook-tap.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
base="https://github.com/ruddro-roy/sindook/releases/download/$tag"
curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt"

# Every archive digest in the formula must match the published
# checksums.txt entry for that archive.
for archive in $(grep -o 'sindook_[0-9][0-9a-zA-Z._-]*\.\(tar\.gz\|zip\)' "$formula" | sort -u); do
	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
	[ -n "$want" ] || {
		echo "update-tap: $archive not listed in $tag checksums.txt" >&2
		exit 1
	}
	grep -q "sha256 \"$want\"" "$formula" || {
		echo "update-tap: formula digest for $archive does not match the published checksums.txt" >&2
		exit 1
	}
done

# No placeholder digest may remain.
if grep -q 'sha256 "0000000000000000000000000000000000000000000000000000000000000000"' "$formula"; then
	echo "update-tap: formula still carries a placeholder digest" >&2
	exit 1
fi

gh auth status >/dev/null 2>&1 || {
	echo "update-tap: gh is not authenticated" >&2
	exit 1
}

# The contents API needs the existing blob's sha to update it, and a
# missing file means a first push. gh prints its 404 error object to
# stdout, so a plain capture would swallow it into the payload: accept
# only a real 40-character hex sha, and search both common locations.
tap_path=""
blob_sha=""
for candidate in sindook.rb Formula/sindook.rb; do
	sha=$(gh api "repos/$tap/contents/$candidate" --jq .sha 2>/dev/null || true)
	case "$sha" in
	[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
		tap_path=$candidate
		blob_sha=$sha
		break
		;;
	esac
done
[ -n "$tap_path" ] || {
	echo "update-tap: found no sindook.rb at the tap root or Formula/ in $tap" >&2
	exit 1
}
# Base64 output can wrap; newlines are invalid inside a JSON string, and
# the base64 alphabet needs no further JSON escaping.
content=$(base64 < "$formula" | tr -d '\n')
payload=$(mktemp "$tmp/payload.XXXXXX")
{
	printf '{"message":"sindook %s"' "$version"
	printf ',"content":"%s"' "$content"
	printf ',"committer":{"name":"%s","email":"%s"}' "$committer_name" "$committer_email"
	if [ -n "$blob_sha" ]; then
		printf ',"sha":"%s"' "$blob_sha"
	fi
	printf '}'
} > "$payload"

gh api -X PUT "repos/$tap/contents/$tap_path" --input "$payload" >/dev/null

echo "tap updated: $tap $tap_path -> $version"
echo "verify: brew install ruddro-roy/sindook/sindook && sindook version"
