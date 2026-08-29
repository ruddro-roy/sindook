# sindook

[![ci](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml/badge.svg)](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ruddro-roy/sindook/badge)](https://scorecard.dev/viewer/?uri=github.com/ruddro-roy/sindook)
[![Go Reference](https://pkg.go.dev/badge/github.com/ruddro-roy/sindook/xwing.svg)](https://pkg.go.dev/github.com/ruddro-roy/sindook/xwing)

Encrypt files with one command, using hybrid post-quantum keys, and rotate
access later without re-encrypting everything. Sindook is the Bengali word
for a strongbox.

## Quick start

Install the latest release (no admin rights, checksum verified):

    # Linux or macOS
    curl -fsSL https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.sh | sh

    # Windows PowerShell
    irm https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.ps1 | iex

Encrypt your first file in three commands:

    sindook init
    sindook seal report.pdf
    sindook open report.pdf.sindook

`init` creates your identity, a small key pair, and remembers it as your
default. After that, everyday sealing and opening need no flags. Add `-p` to
`init` if you also want a passphrase on the identity file itself.

Everything else is still one line:

    # compress while sealing, good for logs and tar archives
    sindook seal -z photos.tar

    # seal for other people, they open with their own identity
    sindook contacts add alice alice.key.pub
    sindook seal -r @alice project-plan.pdf

    # add a recovery passphrase to any file
    sindook seal -r @alice -p budget.xlsx

    # prove a backup still opens, without writing plaintext anywhere
    sindook verify backups/*.sindook

    # rotate who can open a file, fast mode does not re-encrypt the payload
    sindook rewrap -r @alice archive.tar.sindook

## What sindook gives you

- One static binary, no runtime, no daemon. Linux, macOS, and Windows,
  amd64 and arm64.
- Hybrid post-quantum recipients: [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/10/)
  combines X25519 with ML-KEM-768 from [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
  An attacker has to break both the classical and the post-quantum
  component. The X-Wing implementation is checked byte-for-byte against
  the draft's published vectors on every CI run and cross-tested against
  independent implementations.
- Key slots per file, following the LUKS model. Up to 32 recipients plus
  passphrase slots, and any one of them opens the file.
- `rewrap` rotates access later: add or remove people, switch passphrases,
  or upgrade old format versions without decrypting the payload in fast
  mode. `-deep` re-encrypts under a fresh file key when someone must lose
  access to the replacement.
- Compression built in with `seal -z` and `open -z`, bounded at 1 TiB of
  expansion by default (`-max-decompressed`). A 1.5 MB server log seals
  to a few kilobytes, and a hostile archive cannot fill the disk.
- ASCII armor that survives email and copy-paste, stream mode for pipes,
  batch mode for whole directories, portable `-glob` for shells that do
  not expand wildcards.
- Stable exit codes and JSON output for scripts, `doctor` and `selftest`
  for diagnosing an installation.
- Release binaries are checksummed, signed with Sigstore, and carry an
  SBOM plus GitHub build provenance; anyone can rebuild a release from
  its tag byte-for-byte (`scripts/verify-reproducibility.sh`).

## When to use it

- Cold backups and offsite archives that must stay unreadable to others
  for decades, including if large quantum computers appear.
- Protecting documents on a laptop that might be stolen.
- Sending sensitive files over email or chat as plain text (armor mode).
- Team archives where people join and leave: rewrap rotates the recipient
  list without touching the encrypted payload.
- Nightly backup jobs that check restorability with `verify` and exit
  codes.

## Install

| Method | How |
| --- | --- |
| One-liner (macOS/Linux) | `curl -fsSL https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.sh \| sh` |
| One-liner (Windows) | `irm https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.ps1 \| iex` |
| Homebrew | `brew install ruddro-roy/sindook/sindook` |
| Go toolchain | `go install github.com/ruddro-roy/sindook/cmd/sindook@v0.10.0` (Go 1.26.6+) |
| Scoop | `scoop bucket add sindook https://github.com/ruddro-roy/scoop-bucket` then `scoop install sindook` |
| winget | `winget install ruddro-roy.sindook` once the manifest is published to winget-pkgs |
| Docker | `docker build .` from this checkout; minimal distroless image |
| Source | `git clone` and `go build ./cmd/sindook` |

Both installers verify the release SHA-256 before installing and print the
PATH action when one is needed. Pass `--version vX.Y.Z` to pin a release.
FreeBSD builds from source.

Release binaries for Linux, macOS, and Windows carry an SBOM, a cosign
keyless signature, and GitHub build provenance. Verify before use:

    shasum -a 256 -c checksums.txt
    cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
      --certificate-identity-regexp 'github.com/ruddro-roy/sindook' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify sindook_*.tar.gz --owner ruddro-roy

On Windows, an unsigned release can trigger SmartScreen. Verify the archive
before overriding a platform warning.

## How it compares

| | sindook | age | GPG |
| --- | --- | --- | --- |
| Recipient keys | X25519 + ML-KEM-768 hybrid | X25519 | RSA / ECC |
| Safe against harvest-now-decrypt-later | Yes, hybrid by default | No | No |
| Rotate recipients without re-encrypting | Yes, `rewrap` fast mode | No | No |
| Compression built in | Yes, `-z`, with an expansion cap | Pipe it yourself | Yes |
| Passphrase KDF | Argon2id | scrypt | iterated KDF |
| Multi-recipient | Up to 32 slots | Yes | Yes |
| Streams and armor | Yes | Yes | Yes |
| Single static binary, CGO-free | Yes | Yes | No, full toolkit |
| Signed releases, SBOM, provenance | Yes | Varies | Varies |

age and GPG are good tools. sindook exists for the case that needs hybrid
post-quantum recipients and rotation without a full re-encrypt.

## Everyday commands

    sindook init                          # create your identity (once)
    sindook seal FILE                     # encrypt to yourself
    sindook seal -z FILE                  # encrypt with compression
    sindook seal -r @alice FILE           # encrypt for a contact
    sindook seal -p FILE                  # passphrase only
    sindook open FILE.sindook             # decrypt (add -z for compressed)
    sindook verify FILE.sindook           # check it opens, write nothing
    sindook inspect FILE.sindook          # metadata, no credentials needed
    sindook rewrap -r @bob FILE.sindook   # rotate access
    sindook config get default-identity   # inspect saved settings
    sindook doctor                        # check the installation
    sindook help seal                     # flags and examples

Save other people's public keys once, then use names. A group seals to
every member, deduplicated, and membership rotates with one command:

    sindook contacts add alice alice.key.pub
    sindook seal -r @alice -r @bob budget.xlsx
    sindook contacts group add team alice bob
    sindook seal -r @team budget.xlsx
    sindook contacts group add-member team carol

Rotate access in place. Fast mode keeps the payload ciphertext as is; use
`-deep` when a removed recipient must not open the replacement file:

    sindook rewrap -r @alice -r bob.pub archive.tar.sindook
    sindook rewrap -r @alice -deep archive.tar.sindook

Streams, batches, and portable wildcard expansion for shells without it:

    tar cz src | sindook seal -o src.tgz.sindook
    sindook rewrap -R team.keys backups/*.sindook
    sindook verify -glob "backups/*.sindook"

Armor output as ASCII text, detected automatically on open:

    sindook seal -a -o - secret.txt

For scripts, `-passfile` replaces the passphrase prompt and
`-identity-passfile` unlocks a protected identity. `keygen -p` seals the
identity file itself under a passphrase, so a stolen key file alone opens
nothing. Shell completions: `sindook completion bash|zsh|fish|powershell`.
The [user guide](docs/USER_GUIDE.md) covers safe output behavior, backup
verification, streams, and recovery.

`shred` overwrites before deleting but cannot defeat SSD wear leveling,
journaling, snapshots, or copies an attacker already made. `doctor
-check-version` looks for a newer release. `selftest` runs the built-in
X-Wing vectors plus a round trip and tamper check after a fresh install.

## Audit your crypto posture

`scan` reports which of your endpoints and key files rely on
cryptography that is expiring, misconfigured, or quantum-vulnerable.
Scan endpoints you operate or are authorized to assess. It is
read-only: no exploit payloads, no credential guessing, no traffic
capture.

    sindook scan tls example.com mail.example.com:993
    sindook scan files ~/.ssh /etc/ssl/private
    sindook scan tls -json api.example.com | jq '.errors'

`scan tls` checks certificate expiry and key strength, chain and
hostname validity, deprecated TLS 1.0/1.1 acceptance (RFC 8996), and
whether the server supports a hybrid post-quantum key exchange
(X25519MLKEM768 or the SECP+ML-KEM groups). Recorded traffic from
endpoints without one may be decryptable by a future quantum computer.
Probes that cannot reach a conclusion say so instead of guessing.
`scan files` finds private keys stored without a passphrase, key files
with permissive file modes (best effort, platform dependent), expired
certificates, and weak key sizes in commonly named key and certificate
files. Findings come with remediations, and sealing the exposed file
is one command away in the same binary.

Scope is deliberate: scan answers the post-quantum readiness question.
For an exhaustive cipher-suite audit, use a dedicated tool such as
[testssl.sh](https://testssl.sh) alongside it.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | operational failure (I/O error, malformed input, validation, payload corruption) |
| `2` | usage error (unknown command or flag, missing operand, malformed credential on the command line) |
| `3` | authentication failure (wrong identity or passphrase, missing credential, header tampering) |

Machine-facing output (`-json`, exit codes) is stable within a major
version; see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for the full
product contract and
[docs/USER_GUIDE.md#troubleshooting](docs/USER_GUIDE.md#troubleshooting)
for memory-lock diagnostics.

## Security posture, honestly

Sindook is pre-1.0 and has not received an independent security audit. It
is not FIPS validated and does not claim to be quantum-proof; no honest
tool can. Read the [threat model](docs/THREAT_MODEL.md),
[security model](docs/SECURITY.md), and [security policy](SECURITY.md)
before using it for sensitive data. The v1.0 readiness checklist is in
[docs/V1_READINESS.md](docs/V1_READINESS.md).

The primitives come from the Go standard library and golang.org/x/crypto:
ML-KEM-768, X25519, SHA-3 and SHAKE-256, ChaCha20-Poly1305, HKDF-SHA-256,
HMAC, and Argon2id. Sindook does not implement these primitives. It does
implement the X-Wing expansion and combiner, about 60 lines, validated
against the draft's Appendix C vectors on every CI run and importable as
`github.com/ruddro-roy/sindook/xwing` (draft-stable until the RFC).

The sealing engine is also a public Go library:
`github.com/ruddro-roy/sindook/box` exposes Seal, Open, Rewrap, and
Inspect for embedding in other tools, with the same compatibility policy
as the CLI ([docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)).

One random file key per file, wrapped once per slot and bound to the file
as associated data. The whole header is sealed by a MAC that only a file
key holder can compute, and slots are length-prefixed so future algorithms
can ship without breaking old readers. Payloads are sealed in 64 KiB
ChaCha20-Poly1305 chunks with the counter and a final-chunk flag bound
into the nonce, so truncation, reordering, and extension all fail
authentication. Passphrase slots use Argon2id with RFC 9106 parameters,
capped on read so hostile files cannot demand unbounded work.

Byte-level layout: [docs/FORMAT.md](docs/FORMAT.md). Security design and
rotation semantics: [docs/SECURITY.md](docs/SECURITY.md). Threat-model
boundaries: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Known limitations: fast `rewrap` is not retroactive revocation; `shred`
cannot defeat SSD wear leveling or copies an attacker already made; memory
locking is best-effort on some platforms; Go does not guarantee
zeroization. The full list is in the threat model.

## Verification

    go test ./...

runs draft-10 key generation, encapsulation, and decapsulation vectors,
round trips at chunk boundaries, multi-recipient and mixed-slot cases,
golden fixtures from released versions, rewrap revocation checks, and a
tamper suite covering bit flips, truncation, extension, slot stripping,
wrong keys, hostile headers, forced-output safety, and symlink refusal.
CI adds race detection, vet, formatting, fuzzing, `govulncheck`, CodeQL,
and interoperability tests against Cloudflare's CIRCL and filippo.io's
X-Wing implementation.

## Project documentation

- [Engineering practices](docs/ENGINEERING.md)
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
