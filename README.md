# sindook

Post-quantum file encryption. Sindook is the Bengali word for a strongbox.

sindook seals files so that an adversary who records the ciphertext today cannot decrypt it with a quantum computer later. Key establishment uses X-Wing, the hybrid KEM combining X25519 with ML-KEM-768 (NIST FIPS 203), implemented from draft-connolly-cfrg-xwing-kem-10 and verified byte for byte against the draft's published test vectors. Breaking a sealed file requires breaking both components.

## Install

    go install github.com/ruddro-roy/sindook/cmd/sindook@latest

Requires Go 1.26 or newer.

## Use

Generate an identity:

    sindook keygen -o my.key
    # writes my.key (secret, 0600) and my.key.pub (shareable)

Seal a file to a recipient and open it:

    sindook seal -r my.key.pub report.pdf     # writes report.pdf.sindook
    sindook open -i my.key report.pdf.sindook # writes report.pdf

Passphrase mode, no keys involved:

    sindook seal -p notes.txt
    sindook open -p notes.txt.sindook

Streams work:

    tar cz src | sindook seal -r my.key.pub -o src.tgz.sindook

## Design

Every primitive comes from the Go standard library or golang.org/x/crypto: ML-KEM-768 (crypto/mlkem), X25519 (crypto/ecdh), SHA-3 and SHAKE-256 (crypto/sha3), ChaCha20-Poly1305, HKDF-SHA-256, Argon2id. This project implements no primitives of its own.

The one piece of specification-level cryptography here is the X-Wing key expansion and combiner, about 60 lines, validated against the draft's Appendix C vectors on every CI run.

Payloads are sealed in 64 KiB ChaCha20-Poly1305 chunks with the chunk counter and a final-chunk flag bound into the nonce, the STREAM construction age uses, so truncation, reordering and extension all fail authentication. Passphrase mode uses Argon2id with RFC 9106 recommended parameters, and the parameters are authenticated so a tampered header cannot downgrade them.

Byte-level layout: [docs/FORMAT.md](docs/FORMAT.md). Threat model and rationale: [docs/SECURITY.md](docs/SECURITY.md).

## Verification

    go test ./...

runs the draft-10 key generation, derandomized encapsulation and decapsulation vectors, round trips at chunk boundaries, and a tamper suite covering bit flips, truncation, extension, wrong keys and hostile headers. CI adds -race, vet, gofmt and govulncheck.

## Roadmap

- ML-DSA signatures for sealed-file provenance
- OPAQUE so passwords can authenticate without ever being sent
- Hardware-backed identities (passkey PRF, FIDO2 hmac-secret)

## Non-goals

No homemade primitives and no protocol invention. Where a well-audited construction exists, sindook uses that construction.

## License

Apache-2.0
