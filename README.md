# sindook

[![ci](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml/badge.svg)](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ruddro-roy/sindook/badge)](https://scorecard.dev/viewer/?uri=github.com/ruddro-roy/sindook)
[![Go Reference](https://pkg.go.dev/badge/github.com/ruddro-roy/sindook/xwing.svg)](https://pkg.go.dev/github.com/ruddro-roy/sindook/xwing)

Hybrid post-quantum file encryption with key rotation built in. Sindook is the Bengali word for a strongbox.

Sindook is a usable pre-1.0 command-line tool for encrypting files for recipients, passphrases, or both. Recipient key establishment uses [X-Wing draft-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/10/), the hybrid KEM combining X25519 with ML-KEM-768 from [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). The repository's X-Wing implementation is verified byte-for-byte against the draft's published vectors and cross-tested against independent implementations. The hybrid design is intended to require an attacker to defeat both components, subject to the draft's security model and the implementation assumptions described below.

Each sealed file carries key slots, following the LUKS model. `rewrap` can rotate recipients, passphrases, and format versions without decrypting or re-encrypting the payload in fast mode. Fast rewrap writes a new header and copies the existing ciphertext into a replacement file. Deep rewrap generates a fresh file key and re-encrypts the replacement payload, so removed recipients cannot open that replacement through an old slot. Neither mode can invalidate copies already held by an attacker.

> **Status:** Sindook is pre-1.0 and has not received an independent security audit. It is not FIPS validated and does not claim to be quantum-proof. Read the [threat model](docs/THREAT_MODEL.md), [security model](docs/SECURITY.md), and [security policy](SECURITY.md) before using it for sensitive data.

## Install

    go install github.com/ruddro-roy/sindook/cmd/sindook@latest

Requires Go 1.26 or newer. A minimal distroless container image builds from the included Dockerfile.

Release binaries for Linux, macOS, and Windows carry an SBOM, a cosign keyless signature, and GitHub build provenance. Verify before use:

    cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
      --certificate-identity-regexp 'github.com/ruddro-roy/sindook' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify sindook_*.tar.gz --owner ruddro-roy

Compatibility policy and tested file-format support: [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Use

Generate an identity:

    sindook keygen -o my.key
    # writes my.key (secret, 0600) and my.key.pub (shareable)

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

Armor produces ASCII that survives email and copy-paste; open detects it automatically:

    sindook seal -r alice.pub -a -o - secret.txt | pbcopy

Prove backups still open without writing plaintext anywhere, and read a sealed file's metadata with no credentials at all:

    sindook verify -i my.key backups/*.sindook
    sindook inspect -json archive.tar.sindook

For scripts, `-passfile` replaces the interactive prompt. `keygen -p` seals the identity file itself under a passphrase, so a stolen key file alone opens nothing. `sindook completion bash|zsh|fish` prints shell completions, and `sindook help <command>` shows flags and examples. The [user guide](docs/USER_GUIDE.md) covers safe output behavior, backup verification, streams, and recovery.

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
- [Contributing](CONTRIBUTING.md)

## Non-goals

No new cryptographic primitives. Sindook favors established components, but users should treat its complete file format and key-management design as unaudited until an independent review is completed.

## License

Apache-2.0
