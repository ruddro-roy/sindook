#!/usr/bin/env bash
# Verify a sindook release end to end.
#
#   usage: verify-release.sh <TAG> <VERSION> [SIGSTORE_IDENTITY_REGEXP]
#
# <TAG>                    the annotated tag that triggered the release
#                          (e.g. v0.7.0)
# <VERSION>                the release version without the leading v
#                          (e.g. 0.7.0)
# <SIGSTORE_IDENTITY_REGEXP>
#                          cosign --certificate-identity-regexp for the
#                          keyless signing workflow; defaults to the sindook
#                          release.yml workflow identity pinned to <TAG>
#
# The artifact directory defaults to ./dist (what the release workflow
# uploads and the verify job downloads back as the "dist" artifact);
# override with DIST=... .
#
# Local smoke testing only (never set these in CI):
#   SKIP_SIGNATURE_VERIFY=1    skip the cosign keyless signature check
#   SKIP_ATTESTATION_VERIFY=1  skip the gh attestation (provenance) checks
# CI runs strict by default.
set -euo pipefail

TAG="${1:-}"
VERSION="${2:-}"
IDENTITY_REGEXP="${3:-^https://github.com/ruddro-roy/sindook/.github/workflows/release.yml@refs/tags/${TAG}\$}"
DIST="${DIST:-dist}"
REPO="${REPO:-ruddro-roy/sindook}"
SKIP_SIGNATURE_VERIFY="${SKIP_SIGNATURE_VERIFY:-0}"
SKIP_ATTESTATION_VERIFY="${SKIP_ATTESTATION_VERIFY:-0}"

if [ -z "$TAG" ] || [ -z "$VERSION" ]; then
  echo "usage: verify-release.sh <TAG> <VERSION> [SIGSTORE_IDENTITY_REGEXP]" >&2
  exit 2
fi

FAILED=0
TOTAL=0

pass() {
  TOTAL=$((TOTAL + 1))
  echo "PASS: $1"
}

fail() {
  TOTAL=$((TOTAL + 1))
  FAILED=$((FAILED + 1))
  echo "FAIL: $1"
}

# sha256_of FILE -> hex digest (sha256sum or shasum, whatever exists)
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# verify_sha256 FILE EXPECTED -> 0 on match, nonzero on mismatch (or error)
verify_sha256() {
  [ "$(sha256_of "$1")" = "$2" ]
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ ! -d "$DIST" ]; then
  echo "artifact directory $DIST not found" >&2
  exit 1
fi
cd "$DIST"

echo "== verify-release: $TAG (version $VERSION) =="

# ---- archives present ------------------------------------------------------
ARCHIVES=""
for f in ./*.tar.gz ./*.zip; do
  [ -f "$f" ] || continue
  ARCHIVES="$ARCHIVES $f"
done
ARCHIVES="${ARCHIVES# }"
if [ -n "$ARCHIVES" ]; then
  pass "archives present"
else
  fail "no archives found under $DIST"
fi

# ---- checksums.txt verifies every artifact --------------------------------
echo "-- checksums --"
if [ ! -f checksums.txt ]; then
  fail "checksums.txt present"
else
  pass "checksums.txt present"
  ok=0
  if command -v sha256sum >/dev/null 2>&1 && sha256sum -c checksums.txt >/dev/null 2>&1; then
    ok=1
  elif command -v shasum >/dev/null 2>&1 && shasum -a 256 -c checksums.txt >/dev/null 2>&1; then
    ok=1
  fi
  if [ "$ok" = "1" ]; then
    pass "sha256 of every artifact matches checksums.txt"
  else
    fail "sha256 mismatch against checksums.txt"
  fi
fi

# ---- fail-closed proof: a tampered archive MUST be detected ----------------
echo "-- fail-closed checksum proof --"
first_archive="$(printf '%s' "$ARCHIVES" | awk '{print $1}')"
if [ -z "$first_archive" ]; then
  fail "fail-closed: no archive to tamper"
else
  expected="$(awk -v f="$(basename "$first_archive")" '$2 == f {print $1}' checksums.txt)"
  if [ -z "$expected" ]; then
    fail "fail-closed: $first_archive has no entry in checksums.txt"
  else
    tampered="$tmp/tampered-$(printf '%s' "$first_archive" | tr '/' '_')"
    cp "$first_archive" "$tampered"
    printf 'X' >> "$tampered"
    if verify_sha256 "$tampered" "$expected"; then
      fail "fail-closed: tampered archive hash still matches checksums.txt"
    else
      pass "fail-closed: tampered archive detected as hash mismatch"
    fi
  fi
fi

# ---- sigstore keyless signature --------------------------------------------
echo "-- sigstore signature --"
if [ "$SKIP_SIGNATURE_VERIFY" = "1" ]; then
  echo "SKIP: sigstore signature verification (SKIP_SIGNATURE_VERIFY=1)"
elif [ ! -f checksums.txt.sigstore.json ]; then
  fail "checksums.txt.sigstore.json bundle present"
else
  if ! command -v cosign >/dev/null 2>&1; then
    fail "cosign available for signature verification"
  elif cosign verify-blob \
      --bundle checksums.txt.sigstore.json \
      --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
      --certificate-identity-regexp="$IDENTITY_REGEXP" \
      checksums.txt >/dev/null 2>&1; then
    pass "sigstore signature of checksums.txt verified (issuer and identity pinned)"
  else
    fail "sigstore signature of checksums.txt"
  fi
fi

# ---- GitHub provenance attestations ----------------------------------------
echo "-- provenance attestations --"
if [ "$SKIP_ATTESTATION_VERIFY" = "1" ]; then
  echo "SKIP: provenance attestation verification (SKIP_ATTESTATION_VERIFY=1)"
elif ! command -v gh >/dev/null 2>&1; then
  fail "gh CLI available for attestation verification"
else
  attested=0
  for f in $ARCHIVES ./*.deb ./*.rpm ./*.apk checksums.txt; do
    [ -f "$f" ] || continue
    if gh attestation verify "$f" --repo "$REPO" >/dev/null 2>&1; then
      attested=$((attested + 1))
    else
      fail "provenance attestation for $f"
    fi
  done
  if [ "$attested" -gt 0 ]; then
    pass "provenance attestations verified ($attested artifacts)"
  fi
fi

# ---- SBOMs: every archive needs a valid sibling .sbom.json -----------------
echo "-- sboms --"
for archive in $ARCHIVES; do
  sbom="${archive}.sbom.json"
  if [ ! -f "$sbom" ]; then
    fail "SBOM for $archive (${sbom} missing)"
    continue
  fi
  valid=1
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$sbom" 2>/dev/null || valid=0
  elif command -v jq >/dev/null 2>&1; then
    jq empty "$sbom" >/dev/null 2>&1 || valid=0
  else
    valid=0
  fi
  if [ "$valid" = "1" ] && grep -Eq '"(bomFormat|spdxVersion)"' "$sbom"; then
    pass "SBOM for $archive parses as JSON and declares a format"
  else
    fail "SBOM for $archive (missing bomFormat/spdxVersion or invalid JSON)"
  fi
done

# ---- archive contents ------------------------------------------------------
echo "-- archive contents --"
for archive in $ARCHIVES; do
  case "$archive" in
    *.zip)
      listing="$(unzip -l "$archive" | awk '{print $4}')"
      want_bin="sindook.exe"
      ;;
    *)
      listing="$(tar -tzf "$archive")"
      want_bin="sindook"
      ;;
  esac
  if printf '%s\n' "$listing" | grep -qx 'LICENSE' \
     && printf '%s\n' "$listing" | grep -qx 'README.md' \
     && printf '%s\n' "$listing" | grep -qx "$want_bin" \
     && printf '%s\n' "$listing" | grep -Eq '^docs/man/[^/]+\.1$'; then
    pass "contents of $archive (LICENSE, README.md, $want_bin, man pages)"
  else
    fail "contents of $archive"
  fi
done

# ---- executable: version, selftest, doctor, seal/open round trip -----------
echo "-- executable --"
case "$(uname -s)" in
  Linux) host_os=linux ;;
  Darwin) host_os=darwin ;;
  *) host_os= ;;
esac
case "$(uname -m)" in
  x86_64) host_arch=amd64 ;;
  arm64|aarch64) host_arch=arm64 ;;
  *) host_arch= ;;
esac

exec_archive=""
for cand in "sindook_${VERSION}_${host_os}_${host_arch}.tar.gz" "sindook_${VERSION}_linux_amd64.tar.gz"; do
  if [ -f "$cand" ]; then
    exec_archive="$cand"
    break
  fi
done

if [ -z "$exec_archive" ]; then
  fail "no runnable archive found for version $VERSION"
else
  execdir="$tmp/exec"
  mkdir -p "$execdir"
  tar -xzf "$exec_archive" -C "$execdir"
  bin="$execdir/sindook"
  [ -x "$bin" ] || chmod +x "$bin"

  out="$("$bin" version)"
  case "$out" in
    "sindook $VERSION"*)
      pass "sindook version reports $VERSION ($out)"
      ;;
    *)
      fail "sindook version (got: $out, wanted prefix 'sindook $VERSION')"
      ;;
  esac

  if "$bin" selftest >/dev/null 2>&1; then
    pass "sindook selftest"
  else
    fail "sindook selftest"
  fi

  # Hermetic doctor: point HOME (and XDG_CONFIG_HOME for Linux) at a
  # scratch root and generate a default identity first, so the check
  # cannot pass or fail depending on the verifying machine's state.
  dr="$tmp/doctor-home"
  mkdir -p "$dr/cfg" "$dr/work"
  if ( cd "$dr/work" && HOME="$dr" XDG_CONFIG_HOME="$dr/cfg" "$bin" init >/dev/null 2>&1 ) \
     && ( cd "$dr/work" && HOME="$dr" XDG_CONFIG_HOME="$dr/cfg" "$bin" doctor >/dev/null 2>&1 ); then
    pass "sindook doctor (hermetic: scratch HOME, generated identity)"
  else
    fail "sindook doctor (hermetic: scratch HOME, generated identity)"
  fi

  rt="$tmp/roundtrip"
  mkdir -p "$rt"
  printf 'verify-release round trip payload\n' > "$rt/secret.txt"
  cp "$rt/secret.txt" "$tmp/secret.orig"
  if "$bin" keygen -o "$rt/alice.key" >/dev/null 2>&1 \
     && "$bin" seal -r "$rt/alice.key.pub" "$rt/secret.txt" >/dev/null 2>&1 \
     && rm "$rt/secret.txt" \
     && "$bin" open -i "$rt/alice.key" "$rt/secret.txt.sindook" >/dev/null 2>&1 \
     && cmp -s "$tmp/secret.orig" "$rt/secret.txt"; then
    pass "seal/open round trip (keygen -> seal -> open -> byte-identical)"
  else
    fail "seal/open round trip"
  fi
fi

# ---- man pages declare the released version --------------------------------
echo "-- man pages --"
if [ -z "$exec_archive" ]; then
  fail "man pages (no archive to extract)"
else
  mandir="$tmp/man"
  mkdir -p "$mandir"
  tar -xzf "$exec_archive" -C "$mandir" docs 2>/dev/null || true
  mancount=0
  manbad=0
  for m in "$mandir"/docs/man/*.1; do
    [ -f "$m" ] || continue
    mancount=$((mancount + 1))
    if grep -Eq '^\.TH .*"sindook '"$VERSION"'"' "$m"; then
      :
    else
      manbad=$((manbad + 1))
      echo "  $m: .TH line does not declare \"sindook $VERSION\""
    fi
  done
  if [ "$mancount" -eq 0 ]; then
    fail "man pages present in $exec_archive"
  elif [ "$manbad" -eq 0 ]; then
    pass "all $mancount man pages declare sindook $VERSION"
  else
    fail "$manbad of $mancount man pages declare the wrong version"
  fi
fi

# ---- summary ---------------------------------------------------------------
echo
echo "== verify-release summary: $((TOTAL - FAILED))/$TOTAL checks passed =="
if [ "$FAILED" -ne 0 ]; then
  echo "verify-release: FAILED ($FAILED check(s))" >&2
  exit 1
fi
echo "verify-release: OK"
