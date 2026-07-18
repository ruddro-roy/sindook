# Security model

## What sindook protects against

- Harvest now, decrypt later. Every key in a sealed file descends from the X-Wing shared secret. Recovering it requires breaking both X25519 and ML-KEM-768.
- Tampering. The header is bound as associated data to the wrapped file key, and every payload chunk carries its position and finality in the nonce. Decryption emits plaintext incrementally, so what has been emitted is always an authenticated prefix of the original file, and any modification is detected at the damaged chunk.
- Hostile files. Headers are fixed-size fields, no attacker-controlled lengths. Argon2id parameters found in a file are capped (64 passes, 1 GiB, 64 lanes) before any work is done.
- Parameter downgrade. KDF parameters travel inside the authenticated header, so weakening them breaks the file key unwrap.

## What it does not protect against

- Traffic shape. File size, mode byte and chunk structure are visible.
- Compromised endpoints. A keylogger or a copy of the identity file defeats any encryption tool.
- Memory forensics. Go does not guarantee zeroization, so secrets may persist in memory or swap.
- Deniability and recipient anonymity are non-goals.

## Primitive provenance

| Primitive | Source | Standard |
|---|---|---|
| ML-KEM-768 | crypto/mlkem | FIPS 203 |
| X25519 | crypto/ecdh | RFC 7748 |
| SHA3-256, SHAKE-256 | crypto/sha3 | FIPS 202 |
| ChaCha20-Poly1305 | golang.org/x/crypto | RFC 8439 |
| HKDF-SHA-256 | crypto/hkdf | RFC 5869 |
| Argon2id | golang.org/x/crypto | RFC 9106 |
| X-Wing expansion and combiner | this repo, internal/xwing | draft-connolly-cfrg-xwing-kem-10 |

The X-Wing code is validated against the draft's Appendix C test vectors on every CI run.

One deliberate deviation: the draft's Decapsulate uses raw RFC 7748 X25519, which returns an all-zero output for low-order inputs. crypto/ecdh rejects that case with an error, so sindook treats such ciphertexts as invalid. Honest senders never produce them.

## Known limitations

- Young project, no external audit. The design copies audited constructions (age's STREAM chunking, RFC 9106 parameters, FIPS 203 via the standard library) to keep novel surface near zero.
- Side-channel resistance is inherited from the underlying library implementations.

## Reporting

Mail roy@ruddro.com.
