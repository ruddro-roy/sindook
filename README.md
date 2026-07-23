# sindook

[![ci](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml/badge.svg)](https://github.com/ruddro-roy/sindook/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ruddro-roy/sindook/badge)](https://scorecard.dev/viewer/?uri=github.com/ruddro-roy/sindook)
[![Go Reference](https://pkg.go.dev/badge/github.com/ruddro-roy/sindook/xwing.svg)](https://pkg.go.dev/github.com/ruddro-roy/sindook/xwing)

Post-quantum file encryption with key rotation built in. Sindook is the Bengali word for a strongbox.

sindook seals files so that an adversary who records the ciphertext today cannot decrypt it with a quantum computer later. Key establishment uses X-Wing, the hybrid KEM combining X25519 with ML-KEM-768 (NIST FIPS 203), implemented from draft-connolly-cfrg-xwing-kem-10 and verified byte for byte against the draft's published test vectors. Breaking a sealed file requires breaking both components.

What sets it apart is crypto-agility: sealed files carry key slots (the LUKS model), and `rewrap` rotates recipients, passphrases, formats, and eventually algorithms across any amount of data by rewriting only the header. Payload bytes are untouched and plaintext never exists anywhere. That is the operation every post-quantum migration needs and most file encryption tools cannot do.

## Install

    go install github.com/ruddro-roy/sindook/cmd/sindook@latest

Requires Go 1.26 or newer. A container image builds from the included Dockerfile (distroless, under 10 MB).

Release binaries for Linux, macOS, and Windows carry an SBOM, a cosign keyless signature, and SLSA build provenance. Verify before use:

    cosign verify-blob checksums.txt --signature checksums.txt.sig --certificate checksums.txt.pem \
      --certificate-identity-regexp 'github.com/ruddro-roy/sindook' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    gh attestation verify sindook_*.tar.gz --owner ruddro-roy

Stability guarantees, including the promise that sealed files stay openable forever: [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

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

Rotate access in place. Fast mode rewrites only the header, so it costs the same for a kilobyte or a terabyte:

    # replace the key slots: alice stays, bob is added
    sindook rewrap -i my.key -r alice.pub -r bob.pub archive.tar.sindook

    # someone left and must actually lose access: re-encrypt the payload too
    sindook rewrap -i my.key -r alice.pub -deep archive.tar.sindook

Fast rewrap also upgrades v1 files to the current format in place. Removing a slot without `-deep` does not retroactively revoke someone who kept a copy of the old file; docs/SECURITY.md spells out exactly what each mode guarantees.

Streams work, every command takes many files, and `-R` reads a recipient list (concatenated .pub files work as-is):

    tar cz src | sindook seal -r my.key.pub -o src.tgz.sindook
    sindook rewrap -i old.key -R team.keys backups/*.sindook

Armor produces ASCII that survives email and copy-paste; open detects it automatically:

    sindook seal -r alice.pub -a -o - secret.txt | pbcopy

Prove backups still open without writing plaintext anywhere, and read a sealed file's metadata with no credentials at all:

    sindook verify -i my.key backups/*.sindook
    sindook inspect -json archive.tar.sindook

For scripts, `-passfile` replaces the interactive prompt. `keygen -p` seals the identity file itself under a passphrase, so a stolen key file alone opens nothing. `sindook completion bash|zsh|fish` prints shell completions, and `sindook help <command>` shows flags and examples.

## Design

Every primitive comes from the Go standard library or golang.org/x/crypto: ML-KEM-768 (crypto/mlkem), X25519 (crypto/ecdh), SHA-3 and SHAKE-256 (crypto/sha3), ChaCha20-Poly1305, HKDF-SHA-256, HMAC, Argon2id. This project implements no primitives and invents no protocols: the keyslot model is LUKS, the header MAC and chunked payload are age, the KEM is the IETF draft.

The one piece of specification-level cryptography here is the X-Wing key expansion and combiner, about 60 lines, validated against the draft's Appendix C vectors on every CI run. It is importable on its own as `github.com/ruddro-roy/sindook/xwing`; X-Wing is still an Internet-Draft, so treat that API as draft-stable until the RFC.

One random file key per file is wrapped once per slot, each wrap bound to the file and the slot's own KDF parameters as associated data, the whole header sealed by a MAC only a file key holder can compute. Slots are length-prefixed so future slot types (new algorithms) can ship without breaking old readers. Payloads are sealed in 64 KiB ChaCha20-Poly1305 chunks with the chunk counter and a final-chunk flag bound into the nonce, so truncation, reordering and extension all fail authentication. Passphrase slots use Argon2id with RFC 9106 parameters, capped on read so hostile files cannot demand unbounded work.

Byte-level layout: [docs/FORMAT.md](docs/FORMAT.md). Threat model and rotation semantics: [docs/SECURITY.md](docs/SECURITY.md).

## Verification

    go test ./...

runs the draft-10 key generation, derandomized encapsulation and decapsulation vectors, round trips at chunk boundaries, multi-recipient and mixed-slot cases, golden v1 fixture files that must stay readable forever, rewrap payload-preservation and revocation checks, and a tamper suite covering bit flips, truncation, extension, slot stripping, wrong keys and hostile headers. CI adds -race, vet, gofmt and govulncheck. The suite also passes in a clean golang:1.26 container.

The `interop` module cross-tests the X-Wing implementation against Cloudflare's CIRCL and filippo.io/mlkem768/xwing on every CI run: the draft vectors through each implementation, seed-for-seed key agreement, and shared-secret agreement with encapsulation and decapsulation on each side in turn.

## Roadmap

- ML-DSA signatures for sealed-file provenance
- OPAQUE so passwords can authenticate without ever being sent
- Hardware-backed identities (passkey PRF, FIDO2 hmac-secret)

## Non-goals

No homemade primitives and no protocol invention. Where a well-audited construction exists, sindook uses that construction.

## License

Apache-2.0
