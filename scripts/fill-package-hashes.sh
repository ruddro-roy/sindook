#!/bin/bash
# Fill the package-manager manifests (Homebrew, Scoop, winget) with the real
# SHA-256 digests of a published Sindook release, read from the release's
# checksums.txt. Run this AFTER the release assets have been published:
#
#   scripts/fill-package-hashes.sh 0.7.0
#
# Updated files:
#   packaging/homebrew/sindook.rb                       version + 4 sha256
#   packaging/scoop/sindook.json                        version, urls, hashes
#   packaging/winget/manifests/r/ruddro-roy/sindook/<VERSION>/*.yaml
#                                                       PackageVersion,
#                                                       InstallerSha256 and
#                                                       ReleaseDate (set to
#                                                       today only where it
#                                                       still holds the
#                                                       1970-01-01
#                                                       placeholder)
#
# The script fails closed: it exits nonzero when a required hash is missing
# from checksums.txt, when a manifest does not contain the expected pattern
# to replace, or when any placeholder (all-zero hash or 1970-01-01) remains
# in an updated file afterwards. It never writes a manifest with an
# unresolved placeholder. Re-running with an already-filled version is a
# no-op (idempotent).
set -euo pipefail

repo="${SINDOOK_REPO:-ruddro-roy/sindook}"
repo_dir=$(cd "$(dirname "$0")/.." && pwd)

usage() {
	cat <<'EOF'
usage: fill-package-hashes.sh VERSION [checksums.txt]

Fill packaging/homebrew/sindook.rb, packaging/scoop/sindook.json and
packaging/winget/manifests/r/ruddro-roy/sindook/<VERSION>/*.yaml with the
SHA-256 digests of the published release archives.

  VERSION        release to fill, e.g. 0.7.0 (leading 'v' optional)
  checksums.txt  optional path to the release checksums file; when omitted,
                 https://github.com/ruddro-roy/sindook/releases/download/v<VERSION>/checksums.txt
                 is downloaded to a temporary file

Environment override: SINDOOK_REPO (default ruddro-roy/sindook).
EOF
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { usage >&2; exit 2; }
case "$1" in
	v*) version=${1#v} ;;
	*) version=$1 ;;
esac
printf '%s' "$version" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+$' || {
	printf 'fill-package-hashes.sh: invalid version %s (expected X.Y.Z with optional v)\n' "$1" >&2
	exit 2
}

die() {
	printf 'fill-package-hashes.sh: %s\n' "$*" >&2
	exit 1
}

if [ "$#" -eq 2 ]; then
	checksums=$2
	[ -f "$checksums" ] || die "checksums file not found: $checksums"
	tmp_checksums=0
else
	command -v curl >/dev/null 2>&1 || die "curl is required to download checksums.txt"
	checksums=$(mktemp "${TMPDIR:-/tmp}/sindook-checksums.XXXXXX")
	tmp_checksums=1
	printf 'Downloading checksums.txt for v%s...\n' "$version"
	if ! curl -fsSL --retry 3 -o "$checksums" \
		"https://github.com/$repo/releases/download/v$version/checksums.txt"; then
		rm -f "$checksums"
		die "could not download checksums.txt for v$version (is the release published?)"
	fi
fi
trap 'if [ "$tmp_checksums" = 1 ]; then rm -f "$checksums"; fi' EXIT

# lookup_hash ASSET -> echoes the hash from checksums.txt; dies when the
# asset is missing or the hash is not a 64-character hex digest.
lookup_hash() {
	local asset=$1 hash
	hash=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$checksums")
	[ -n "$hash" ] || die "no entry for $asset in $checksums"
	printf '%s' "$hash" | grep -Eq '^[0-9a-fA-F]{64}$' ||
		die "invalid hash for $asset in $checksums: $hash"
	printf '%s\n' "$hash"
}

# require_next FILE CONTEXT_ERE AFTER_ERE — fail closed when the line
# immediately following the first CONTEXT line does not match AFTER.
require_next() {
	local file=$1 ctx=$2 after=$3
	awk -v ctx="$ctx" -v after="$after" '
		found && NR == found + 1 {
			if ($0 ~ after) { ok = 1 }
			exit
		}
		!found && $0 ~ ctx { found = NR }
		END { if (ok) { exit 0 } else { exit 1 } }
	' "$file" || die "$file: expected a line matching '$after' directly after '$ctx'"
}

# replace_after CONTEXT_ERE FILE SED_EXPR — run SED_EXPR on the line
# immediately following the first CONTEXT line.
replace_after() {
	local ctx=$1 file=$2 expr=$3
	sed -e "/$ctx/{" -e "n" -e "$expr" -e "}" "$file" > "$file.tmp" ||
		die "sed failed on $file"
	mv "$file.tmp" "$file"
}

placeholder_hash="0000000000000000000000000000000000000000000000000000000000000000"

# version_lt exits 0 when the first dotted X.Y.Z triple is numerically smaller
# than the second, 1 otherwise.
version_lt() {
	awk -v a="$1" -v b="$2" 'BEGIN {
		split(a, x, "."); split(b, y, ".");
		for (i = 1; i <= 3; i++) {
			if (x[i] + 0 < y[i] + 0) exit 0;
			if (x[i] + 0 > y[i] + 0) exit 1;
		}
		exit 1;
	}'
}

prepare_winget_dir() {
	local root=$1 target_version=$2 target_dir=$3
	local latest_version="" latest_dir="" d base src f ifile

	for d in "$root"/*; do
		[ -d "$d" ] || continue
		base=${d##*/}
		case "$base" in
			[0-9]*.[0-9]*.[0-9]*) ;;
			*) continue ;;
		esac
		if [ -z "$latest_version" ] || version_lt "$latest_version" "$base"; then
			latest_version=$base
			latest_dir=$d
		fi
	done
	[ -n "$latest_dir" ] || die "no existing winget manifest directory to use as a template under $root"

	mkdir "$target_dir" || die "could not create $target_dir"
	for src in "$latest_dir"/*.yaml; do
		[ -f "$src" ] || continue
		cp "$src" "$target_dir/${src##*/}" || die "could not copy $src"
	done

	for f in "$target_dir"/*.yaml; do
		[ -f "$f" ] || continue
		sed -e "s/v${latest_version}/v${target_version}/g" \
			-e "s/${latest_version}/${target_version}/g" \
			"$f" > "$f.tmp" || die "sed failed on $f"
		mv "$f.tmp" "$f"
	done

	ifile="$target_dir/ruddro-roy.sindook.installer.yaml"
	[ -f "$ifile" ] || die "$target_dir: installer manifest missing after template copy"
	sed -e 's/^\([[:space:]]*InstallerSha256: \)[0-9a-fA-F]\{64\}.*$/\1'"$placeholder_hash"'/' \
		-e 's/^\([[:space:]]*ReleaseDate: \).*$/\11970-01-01/' \
		"$ifile" > "$ifile.tmp" || die "sed failed on $ifile"
	mv "$ifile.tmp" "$ifile"

	printf 'Prepared winget/%s manifests from winget/%s template.\n' "$target_version" "$latest_version"
}

# ---------------------------------------------------------------- Homebrew
formula="$repo_dir/packaging/homebrew/sindook.rb"
[ -f "$formula" ] || die "missing $formula"
grep -q '^[[:space:]]*version "' "$formula" || die "$formula: no version line"
grep -q 'sha256 "' "$formula" || die "$formula: no sha256 lines"

for pair in "darwin_amd64" "darwin_arm64" "linux_amd64" "linux_arm64"; do
	arch=$pair
	h=$(lookup_hash "sindook_${version}_${arch}.tar.gz")
	ctx="sindook_#{version}_${arch}\.tar\.gz"
	require_next "$formula" "$ctx" 'sha256 "'
	replace_after "$ctx" "$formula" \
		's/sha256 "[0-9a-fA-F]\{64\}"/sha256 "'"$h"'"/'
done
sed -e 's/^\([[:space:]]*version "\)[^"]*/\1'"$version"'/' "$formula" > "$formula.tmp" &&
	mv "$formula.tmp" "$formula"

# -------------------------------------------------------------------- Scoop
manifest="$repo_dir/packaging/scoop/sindook.json"
[ -f "$manifest" ] || die "missing $manifest"
grep -q '^[[:space:]]*"version": "' "$manifest" || die "$manifest: no version field"
old_version=$(grep '^[[:space:]]*"version": "' "$manifest" |
	sed -e 's/.*"version": "\([^"]*\)".*/\1/' | head -n 1)
[ -n "$old_version" ] || die "$manifest: could not read the current version"

if [ "$old_version" != "$version" ]; then
	sed -e "s/v${old_version}/v${version}/g" \
		-e "s/sindook_${old_version}_/sindook_${version}_/g" \
		"$manifest" > "$manifest.tmp" || die "sed failed on $manifest"
	mv "$manifest.tmp" "$manifest"
fi

h64=$(lookup_hash "sindook_${version}_windows_amd64.zip")
harm=$(lookup_hash "sindook_${version}_windows_arm64.zip")
require_next "$manifest" 'sindook_[0-9][0-9.]*_windows_amd64\.zip' '"hash"'
require_next "$manifest" 'sindook_[0-9][0-9.]*_windows_arm64\.zip' '"hash"'
replace_after 'sindook_[0-9][0-9.]*_windows_amd64\.zip' "$manifest" \
	's/"hash": "sha256:[0-9a-fA-F]*"/"hash": "sha256:'"$h64"'"/'
replace_after 'sindook_[0-9][0-9.]*_windows_arm64\.zip' "$manifest" \
	's/"hash": "sha256:[0-9a-fA-F]*"/"hash": "sha256:'"$harm"'"/'
sed -e 's/^\([[:space:]]*"version": "\)[^"]*/\1'"$version"'/' "$manifest" > "$manifest.tmp" &&
	mv "$manifest.tmp" "$manifest"

# -------------------------------------------------------------------- winget
winget_root="$repo_dir/packaging/winget/manifests/r/ruddro-roy/sindook"
winget_dir="$winget_root/$version"
if [ ! -d "$winget_dir" ]; then
	prepare_winget_dir "$winget_root" "$version" "$winget_dir"
fi
vfile="$winget_dir/ruddro-roy.sindook.yaml"
ifile="$winget_dir/ruddro-roy.sindook.installer.yaml"
lfile="$winget_dir/ruddro-roy.sindook.locale.en-US.yaml"
for f in "$vfile" "$ifile" "$lfile"; do
	[ -f "$f" ] || die "missing $f"
	grep -q '^PackageVersion: ' "$f" || die "$f: no PackageVersion line"
done

w64=$(lookup_hash "sindook_${version}_windows_amd64.zip")
warm=$(lookup_hash "sindook_${version}_windows_arm64.zip")

grep -q "releases/download/v${version}/sindook_${version}_windows_amd64\.zip" "$ifile" ||
	die "$ifile: no amd64 InstallerUrl for v$version"
grep -q "releases/download/v${version}/sindook_${version}_windows_arm64\.zip" "$ifile" ||
	die "$ifile: no arm64 InstallerUrl for v$version"
require_next "$ifile" "sindook_${version}_windows_amd64\.zip" 'InstallerSha256:'
require_next "$ifile" "sindook_${version}_windows_arm64\.zip" 'InstallerSha256:'
grep -q '^[[:space:]]*ReleaseDate: ' "$ifile" || die "$ifile: no ReleaseDate line"

replace_after "sindook_${version}_windows_amd64\.zip" "$ifile" \
	's/^\([[:space:]]*InstallerSha256: \)[0-9a-fA-F]\{64\}.*$/\1'"$w64"'/'
replace_after "sindook_${version}_windows_arm64\.zip" "$ifile" \
	's/^\([[:space:]]*InstallerSha256: \)[0-9a-fA-F]\{64\}.*$/\1'"$warm"'/'

# ReleaseDate is set to today only where the 1970-01-01 placeholder is still
# present; a real (already-filled) date is left untouched.
# ReleaseDate is set only when the placeholder is present.
# For pre-release testing with a local checksums file, the user may set
# SINDOOK_RELEASE_DATE explicitly; otherwise the date is taken from the
# release tag's published time via the GitHub API when operating
# post-publication, or kept as placeholder for staged artifacts.
if grep -q '^[[:space:]]*ReleaseDate: 1970-01-01' "$ifile"; then
	if [ -n "${SINDOOK_RELEASE_DATE:-}" ]; then
		release_date="$SINDOOK_RELEASE_DATE"
	else
		# Try to obtain authoritative UTC date from GitHub release info
		release_date=$(curl -fsSL --retry 2 "https://api.github.com/repos/$repo/releases/tags/v$version" 2>/dev/null | python3 -c 'import sys, json; d=json.load(sys.stdin); print(d.get("published_at", "").split("T")[0])' 2>/dev/null || echo "1970-01-01")
	fi
	if [ "$release_date" = "1970-01-01" ] || ! printf '%s' "$release_date" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
		die "ReleaseDate must be a valid YYYY-MM-DD (set SINDOOK_RELEASE_DATE explicitly for pre-release testing)"
	fi
	sed -e 's/^\([[:space:]]*ReleaseDate: \)1970-01-01.*$/\1'"$release_date"'/' \
		"$ifile" > "$ifile.tmp" || die "sed failed on $ifile"
	mv "$ifile.tmp" "$ifile"
fi

for f in "$vfile" "$ifile" "$lfile"; do
	sed -e 's/^\(PackageVersion: \).*$/\1'"$version"'/' "$f" > "$f.tmp" ||
		die "sed failed on $f"
	mv "$f.tmp" "$f"
done

# --------------------------------------------- fail-closed final verification
if grep -Eq 'sha256 "0{64}"|"hash": "sha256:0{64}"|InstallerSha256: 0{64}' "$formula" "$manifest" "$vfile" "$ifile" "$lfile"; then
	die "an all-zero placeholder hash remains in an updated manifest"
fi
if grep -q '^[[:space:]]*ReleaseDate: 1970-01-01' "$ifile"; then
	die "$ifile still contains the 1970-01-01 placeholder release date"
fi

grep -q "sha256 \"$(lookup_hash "sindook_${version}_darwin_amd64.tar.gz")\"" "$formula" ||
	die "$formula: darwin_amd64 hash was not written"
grep -q "sha256 \"$(lookup_hash "sindook_${version}_darwin_arm64.tar.gz")\"" "$formula" ||
	die "$formula: darwin_arm64 hash was not written"
grep -q "sha256 \"$(lookup_hash "sindook_${version}_linux_amd64.tar.gz")\"" "$formula" ||
	die "$formula: linux_amd64 hash was not written"
grep -q "sha256 \"$(lookup_hash "sindook_${version}_linux_arm64.tar.gz")\"" "$formula" ||
	die "$formula: linux_arm64 hash was not written"
grep -q "version \"$version\"" "$formula" || die "$formula: version was not written"

grep -q '"version": "'"$version"'"' "$manifest" || die "$manifest: version was not written"
grep -q '"sha256:'"$h64"'"' "$manifest" || die "$manifest: amd64 hash was not written"
grep -q '"sha256:'"$harm"'"' "$manifest" || die "$manifest: arm64 hash was not written"

for f in "$vfile" "$ifile" "$lfile"; do
	grep -q "^PackageVersion: $version$" "$f" || die "$f: PackageVersion was not written"
done
grep -q "InstallerSha256: $w64" "$ifile" || die "$ifile: amd64 hash was not written"
grep -q "InstallerSha256: $warm" "$ifile" || die "$ifile: arm64 hash was not written"

printf 'Filled Homebrew, Scoop and winget/%s manifests from %s.\n' "$version" "$checksums"
