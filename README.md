# sindook

[![ci](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml/badge.svg)](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ruddro-roy/sindook/badge)](https://scorecard.dev/viewer/?uri=github.com/ruddro-roy/sindook)
[![Go Reference](https://pkg.go.dev/badge/github.com/ruddro-roy/sindook/xwing.svg)](https://pkg.go.dev/github.com/ruddro-roy/sindook/xwing)

Hybrid post-quantum file encryption with key rotation built in. Sindook is the Bengali word for a strongbox.

Sindook is a usable pre-1.0 command-line tool for encrypting files for recipients, passphrases, or both. Recipient key establishment uses [X-Wing draft-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/10/), the hybrid KEM combining X25519 with ML-KEM-768 from [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). The repository's X-Wing implementation is verified byte-for-byte against the draft's published vectors and cross-tested against independent implementations. The hybrid design is intended to require an attacker to defeat both components, subject to the draft's security model and the implementation assumptions described below.

Each sealed file carries key slots, following the LUKS model. `rewrap` can rotate recipients, passphrases, and format versions without decrypting or re-encrypting the payload in fast mode. Fast rewrap writes a new header and copies the existing ciphertext into a replacement file. Deep rewrap generates a fresh file key and re-encrypts the replacement payload, so removed recipients cannot open that replacement through an old slot. Neither mode can invalidate copies already held by an attacker.

> **Status:** Sindook is pre-1.0 and has not received an independent security audit. It is not FIPS validated and does not claim to be quantum-proof. Read the [threat model](docs/THREAT_MODEL.md), [security model](docs/SECURITY.md), and [security policy](SECURITY.md) before using it for sensitive data. The v1.0 readiness checklist is in [docs/V1_READINESS.md](docs/V1_READINESS.md).

## Install

Tagged releases ship native, CGO-free binaries for Linux, macOS, and Windows
on both amd64 and arm64 (FreeBSD builds from source). Every archive includes
a checksum, SBOM, Sigstore bundle, and GitHub build provenance.

Install the current release from source on any supported operating system
(Go 1.26.6+; the Go toolchain auto-downloads it if needed):

    go install github.com/ruddro-roy/sindook/cmd/sindook@v0.7.1
    sindook version
    # sindook 0.7.1 -- tagged installs report the exact release version

`@latest` also works; `@v0.7.1` pins the release. A build from a source
checkout reports `sindook 0.7.1-dev` with commit provenance instead.

Or install a verified release binary without Go. From a checked-out Sindook
source tree, run one of the included user-local installers:

    # macOS or Linux
    ./scripts/install.sh

    # Windows PowerShell
    .\scripts\install.ps1

The installers choose the current OS and architecture, verify the matching
entry in `checksums.txt`, install without administrator privileges, and print
the PATH action if one is needed. Pass `--version vX.Y.Z` to select a release
and `--yes` to skip prompts. Release assets are named
`sindook_X.Y.Z_linux_amd64.tar.gz`, `sindook_X.Y.Z_darwin_arm64.tar.gz`, and
`sindook_X.Y.Z_windows_amd64.zip` (with the appropriate OS/architecture).

### Install matrix

| Method | How |
| --- | --- |
| Go toolchain | `go install github.com/ruddro-roy/sindook/cmd/sindook@v0.7.1` (Go 1.26.6+) |
| macOS / Linux installer | `curl -fsSLO https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.sh && sh install.sh` |
| Windows installer | Download `scripts/install.ps1` from the repository and run it in PowerShell |
| Homebrew | `brew install --formula packaging/homebrew/sindook.rb` from this checkout, or publish `packaging/homebrew` as a tap |
| Scoop | `scoop install .\packaging\scoop\sindook.json` from this checkout, or publish `packaging/scoop` as a bucket |
| winget | `winget install ruddro-roy.sindook` once `packaging/winget/manifests/r/ruddro-roy/sindook/0.7.1/` is published to winget-pkgs |
| Docker | `docker build .` from this checkout; the image is minimal distroless and runs `sindook` as its entrypoint |
| Source | `git clone` and `go build ./cmd/sindook` |

The Homebrew, Scoop, and winget manifests carry the latest already-published
release checksums until the next release exists. After publishing v0.7.1, run
`scripts/fill-package-hashes.sh 0.7.1` to refresh them from the verified
`checksums.txt`; see [docs/RELEASING.md](docs/RELEASING.md).

Requires Go 1.26.6 or newer when installing from source. A minimal
distroless container image builds from the included Dockerfile.

Release binaries for Linux, macOS, and Windows carry an SBOM, a cosign
keyless signature, and GitHub build provenance. Verify before use:

    shasum -a 256 -c checksums.txt
    cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
      --certificate-identity-regexp 'github.com/ruddro-roy/sindook' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify sindook_*.tar.gz --owner ruddro-roy

Compatibility policy and tested file-format support: [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

On Windows, an unsigned release can trigger SmartScreen. Verify the archive
before overriding a platform warning; macOS Gatekeeper/notarization support
will require a future Developer ID signing process.

### Upgrading from v0.6.0

Upgrades are drop-in: the sealed-file format (v2), the configuration schema
(v1), and identity and contact files are unchanged. Replace the binary and
run `sindook doctor` and `sindook selftest`; no re-encryption, rewrap, or
re-import is needed. Files sealed by v0.6.0 are pinned as test fixtures, so
every release is proven to open them.

### Known limitations

- No independent security audit yet; the file format and key-management
  design are unaudited until an external review is completed.
- `shred` cannot defeat SSD wear leveling, journaling, snapshots, or copies
  an attacker already made.
- Memory locking is best-effort: on macOS and under low `RLIMIT_MEMLOCK`,
  key material may reach swap.
- Fast `rewrap` is not retroactive revocation; only `-deep` rotates the
  file key of the replacement.
- No guaranteed secret zeroization in Go; see the threat model.
- No full-disk encryption, hidden volumes, deniability, or recipient
  anonymity.

See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for the complete product
contract, including supported platforms and what pre-1.0 means for users.

## Use

### First-time setup and named contacts

Create an identity at an explicit location and make it the opt-in default:

    sindook init -o personal.key -p
    sindook seal -r @default report.pdf
    sindook open -i @default report.pdf.sindook

Save public recipient keys once, then use names instead of remembering file
paths. The portable per-user config contains only public contacts and the
path to the chosen default identity, never a private key or passphrase.

    sindook contacts add alice alice.key.pub
    sindook contacts list
    sindook seal -r @alice project-plan.pdf
    sindook paths

Generate an identity:

    sindook keygen -o my.key
    # on POSIX, writes my.key (secret, mode 0600) and my.key.pub (shareable)

Seal to one or more recipients, optionally with a recovery passphrase, and open:

    sindook seal -r my.key.pub report.pdf
    sindook seal -r alice.pub -r bob.pub -p budget.xlsx
    sindook open -i my.key report.pdf.sindook

Passphrase only:

    sindook seal -p notes.txt
    sindook open -p notes.txt.sindook

Rotate access in place. Fast mode preserves the payload ciphertext, but still copies it into a replacement file:

    # replace the key slots: alice stays, bob is added
    sindook rewrap -i my.key -r alice.pub -r bob.pub archive.tar.sindook

    # someone left and must lose access to the replacement file
    sindook rewrap -i my.key -r alice.pub -deep archive.tar.sindook

Fast rewrap also upgrades v1 files to the current format in place. Removing a slot without `-deep` does not retroactively revoke someone who kept a copy of the old file; [docs/SECURITY.md](docs/SECURITY.md) spells out exactly what each mode guarantees.

Streams work, every command takes many files, and `-R` reads a recipient list (concatenated .pub files work as-is):

    tar cz src | sindook seal -r my.key.pub -o src.tgz.sindook
    sindook rewrap -i old.key -R team.keys backups/*.sindook

For the same batch behavior in Windows `cmd.exe` and PowerShell, or when a
shell does not expand a wildcard, use Sindook's portable `-glob` flag:

    sindook verify -i @default -glob "backups/*.sindook"
    sindook seal -r @alice -glob "reports/*.pdf"

Armor produces ASCII that survives email and copy-paste; open detects it automatically:

    sindook seal -r alice.pub -a -o - secret.txt | pbcopy

Prove backups still open without writing plaintext anywhere, and read a sealed file's metadata with no credentials at all:

    sindook verify -i my.key backups/*.sindook
    sindook inspect -json archive.tar.sindook

Run a fast in-process sanity check after a fresh install or unusual runtime
failure. It validates the published X-Wing vectors plus a sealed-file round
trip and tamper rejection; it is not a replacement for the full test suite:

    sindook selftest

Overwrite plaintext files before deleting them, and diagnose an installation:

    sindook shred -n 3 old-plaintext.txt
    sindook doctor -check-version

`shred` overwrites before unlink, but it cannot defeat SSD wear leveling,
filesystem journaling, copy-on-write snapshots, backups, or copies an
attacker already made. `doctor` checks the installation and configuration
and, with `-check-version`, looks for a newer release. See
[docs/USER_GUIDE.md](docs/USER_GUIDE.md) for details and caveats.

For scripts, `-passfile` replaces the payload prompt and
`-identity-passfile` replaces a protected identity prompt. `keygen -p` seals
the identity file itself under a passphrase, so a stolen key file alone opens
nothing. `sindook completion bash|zsh|fish|powershell` prints shell
completions, and `sindook help <command>` shows flags and examples. The
[user guide](docs/USER_GUIDE.md) covers safe output behavior, backup
verification, streams, and recovery.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | operational failure (I/O error, malformed input, validation, or payload corruption) |
| `2` | usage error (unknown command or flag, missing operand, malformed credential on the command line) |
| `3` | authentication failure (wrong identity or passphrase, missing credential, header tampering — historical note: split from `1` in v0.6.0) |

Machine-facing output (`-json`, exit codes) is stable within a major version;
see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for the exit-code contract
and [docs/USER_GUIDE.md#troubleshooting](docs/USER_GUIDE.md#troubleshooting) for memory-lock diagnostics.

## Design

The underlying primitives come from the Go standard library or golang.org/x/crypto: ML-KEM-768 (crypto/mlkem), X25519 (crypto/ecdh), SHA-3 and SHAKE-256 (crypto/sha3), ChaCha20-Poly1305, HKDF-SHA-256, HMAC, and Argon2id. Sindook does not implement these underlying primitives. It does implement the X-Wing draft's expansion and combiner, plus its documented file format and keyslot composition; these project-level constructions have not received an independent audit.

The X-Wing integration is the main project-level cryptographic code, about 60 lines of expansion and combiner logic. It is validated against the draft's Appendix C vectors on every CI run and is importable as `github.com/ruddro-roy/sindook/xwing`. X-Wing is still an Internet-Draft, so treat that API as draft-stable until the RFC.

One random file key per file is wrapped once per slot, each wrap bound to the file and the slot's own KDF parameters as associated data, the whole header sealed by a MAC only a file key holder can compute. Slots are length-prefixed so future slot types (new algorithms) can ship without breaking old readers. Payloads are sealed in 64 KiB ChaCha20-Poly1305 chunks with the chunk counter and a final-chunk flag bound into the nonce, so truncation, reordering and extension all fail authentication. Passphrase slots use Argon2id with RFC 9106 parameters, capped on read so hostile files cannot demand unbounded work.

Byte-level layout: [docs/FORMAT.md](docs/FORMAT.md). Security design and rotation semantics: [docs/SECURITY.md](docs/SECURITY.md). Threat-model boundaries: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Verification

    go test ./...

runs the draft-10 key generation, derandomized encapsulation and decapsulation vectors, round trips at chunk boundaries, multi-recipient and mixed-slot cases, golden v1 fixture files, rewrap payload-preservation and revocation checks, and a tamper suite covering bit flips, truncation, extension, slot stripping, wrong keys, hostile headers, forced-output safety, and symbolic-link refusal. The CI configuration adds race detection, vet, formatting, fuzz smoke tests, `govulncheck`, interoperability checks, and CodeQL on Go 1.26.

The `interop` module cross-tests the X-Wing implementation against Cloudflare's CIRCL and filippo.io/mlkem768/xwing on every CI run: the draft vectors through each implementation, seed-for-seed key agreement, and shared-secret agreement with encapsulation and decapsulation on each side in turn.

## Project documentation

- [User guide](docs/USER_GUIDE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security model](docs/SECURITY.md) and [security reporting policy](SECURITY.md)
- [Format specification](docs/FORMAT.md) and [compatibility promise](docs/COMPATIBILITY.md)
- [Release process](docs/RELEASING.md)
- [Roadmap](docs/ROADMAP.md)
- [Changelog](docs/CHANGELOG.md) and [v1 readiness](docs/V1_READINESS.md)
- [Contributing](CONTRIBUTING.md)

## Non-goals

No new cryptographic primitives. Sindook favors established components, but users should treat its complete file format and key-management design as unaudited until an independent review is completed.

## License

Apache-2.0
