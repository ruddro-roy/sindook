#!/bin/sh
# Install a released Sindook binary for Linux or macOS without administrator
# privileges. The matching SHA-256 checksum is verified before installation;
# a cosign keyless signature check runs when cosign is available (best-effort,
# clearly announced). This script is meant to be downloaded and run directly;
# it never pipes curl into sh.
set -eu

repo="${SINDOOK_REPO:-ruddro-roy/sindook}"
version="${SINDOOK_VERSION:-}"
install_dir="${SINDOOK_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
	cat <<'EOF'
usage: install.sh [--version vX.Y.Z] [--yes] [--install-dir DIR] [--repo OWNER/REPO]

Downloads a verified Linux or macOS Sindook release into a user-writable
directory. Defaults: latest release, ~/.local/bin, ruddro-roy/sindook.

  --version vX.Y.Z   install a pinned release instead of the latest
  --yes              answer yes to any prompt (none currently; reserved)
  --install-dir DIR  install directory (default ~/.local/bin)
  --repo OWNER/REPO  GitHub repository (default ruddro-roy/sindook)

Environment overrides: SINDOOK_VERSION, SINDOOK_INSTALL_DIR, SINDOOK_REPO.
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--version)
		[ "$#" -ge 2 ] || { usage >&2; exit 2; }
		version=$2
		shift 2
		;;
	--yes|-y)
		# Accepted for scripted runs; the installer never prompts today.
		shift
		;;
	--install-dir)
		[ "$#" -ge 2 ] || { usage >&2; exit 2; }
		install_dir=$2
		shift 2
		;;
	--repo)
		[ "$#" -ge 2 ] || { usage >&2; exit 2; }
		repo=$2
		shift 2
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		printf 'sindook installer: unknown option %s\n' "$1" >&2
		usage >&2
		exit 2
		;;
	esac
done

command -v curl >/dev/null 2>&1 || {
	printf 'sindook installer: curl is required\n' >&2
	exit 1
}
command -v tar >/dev/null 2>&1 || {
	printf 'sindook installer: tar is required\n' >&2
	exit 1
}

if [ -z "$version" ]; then
	latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")
	tag=${latest_url##*/}
	download_base="https://github.com/$repo/releases/latest/download"
else
	case "$version" in
	v*) tag=$version ;;
	*) tag="v$version" ;;
	esac
	download_base="https://github.com/$repo/releases/download/$tag"
fi
asset_version=${tag#v}

case "$(uname -s)" in
Darwin) os=darwin ;;
Linux) os=linux ;;
*)
	printf 'sindook installer: this script supports Linux and macOS; use install.ps1 on Windows\n' >&2
	exit 1
	;;
esac
case "$(uname -m)" in
x86_64|amd64) arch=amd64 ;;
arm64|aarch64) arch=arm64 ;;
*)
	printf 'sindook installer: unsupported architecture %s\n' "$(uname -m)" >&2
	exit 1
	;;
esac

asset="sindook_${asset_version}_${os}_${arch}.tar.gz"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/sindook.XXXXXX")
archive="$tmpdir/$asset"
checksums="$tmpdir/checksums.txt"
cleanup() {
	rm -f "$archive" "$checksums" "$tmpdir/checksums.txt.sigstore.json" "$tmpdir/cosign.log" "$tmpdir/sindook"
	rmdir "$tmpdir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

printf 'Downloading Sindook %s for %s/%s...\n' "$tag" "$os" "$arch"
curl -fsSL --retry 3 -o "$archive" "$download_base/$asset"
curl -fsSL --retry 3 -o "$checksums" "$download_base/checksums.txt"

expected=$(awk -v file="$asset" '$2 == file || $2 == "*" file { print $1; exit }' "$checksums")
[ -n "$expected" ] || {
	printf 'sindook installer: %s was not listed in checksums.txt\n' "$asset" >&2
	exit 1
}
if command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "$archive" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "$archive" | awk '{print $1}')
else
	printf 'sindook installer: shasum or sha256sum is required\n' >&2
	exit 1
fi
if [ "$actual" != "$expected" ]; then
	printf 'sindook installer: checksum mismatch for %s\n' "$asset" >&2
	printf '  expected %s\n  got      %s\n' "$expected" "$actual" >&2
	printf 'Do not trust this download; report the incident.\n' >&2
	exit 1
fi
printf 'SHA-256 verified: %s\n' "$expected"

# Best-effort cosign keyless verification of checksums.txt. The SHA-256 check
# above is authoritative for installation; cosign additionally binds the
# checksums to the repository's GitHub Actions identity when it is present.
if command -v cosign >/dev/null 2>&1; then
	printf 'cosign found; verifying keyless signature (best-effort)...\n'
	if curl -fsSL --retry 3 -o "$tmpdir/checksums.txt.sigstore.json" \
			"$download_base/checksums.txt.sigstore.json" \
		&& cosign verify-blob "$checksums" --bundle "$tmpdir/checksums.txt.sigstore.json" \
			--certificate-identity-regexp 'github.com/ruddro-roy/sindook' \
			--certificate-oidc-issuer https://token.actions.githubusercontent.com \
			> "$tmpdir/cosign.log" 2>&1; then
		printf 'cosign verification succeeded.\n'
	else
		printf 'warning: cosign verification failed; continuing because the SHA-256 check passed.\n' >&2
		printf 'Review manually with: cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json\n' >&2
	fi
else
	printf 'cosign not found; skipping keyless signature verification.\n'
	printf 'The archive SHA-256 was verified against checksums.txt.\n'
fi

tar -xzf "$archive" -C "$tmpdir" sindook
mkdir -p "$install_dir"
if command -v install >/dev/null 2>&1; then
	install -m 755 "$tmpdir/sindook" "$install_dir/sindook"
else
	cp "$tmpdir/sindook" "$install_dir/sindook"
	chmod 755 "$install_dir/sindook"
fi

printf '\nInstalled Sindook %s to %s/sindook\n' "$tag" "$install_dir"
case ":${PATH:-}:" in
*":$install_dir:"*) ;;
*)
	printf 'Add %s to your PATH, e.g.:\n  export PATH="%s:$PATH"\n' "$install_dir" "$install_dir"
	;;
esac
printf 'Post-install check:\n  sindook version\n'
printf 'Optional shell completions:\n  bash:  sindook completion bash >> ~/.bash_completion\n  zsh:   sindook completion zsh > "${fpath[1]}/_sindook"\n  fish:  sindook completion fish > ~/.config/fish/completions/sindook.fish\n'
