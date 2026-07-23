# Security model

## What sindook protects against

- Harvest now, decrypt later. Every key in a sealed file descends from the X-Wing shared secret. Recovering it requires breaking both X25519 and ML-KEM-768.
- Tampering. Every slot wrap is bound to the file and its own parameters as associated data, the whole header is authenticated by a MAC keyed by the file key, and every payload chunk carries its position and finality in the nonce. Decryption emits plaintext incrementally, so what has been emitted is always an authenticated prefix of the original file, and any modification is detected at the damaged chunk.
- Slot manipulation. Adding, removing, or reordering key slots breaks the header MAC, which every open verifies before touching the payload.
- Hostile files. Headers are fixed-structure fields with capped lengths, slot count at most 32, slot bodies at most 4096 bytes. Argon2id parameters found in a file are capped (64 passes, 1 GiB, 64 lanes) before any work is done.
- Parameter downgrade. KDF parameters live inside their slot's associated data, so weakening them breaks that slot's unwrap.

## Key slots and rotation

Format v2 uses the LUKS keyslot model: one random file key, wrapped once per recipient or passphrase. The rewrap command replaces the slot set. Two honest properties to understand:

- Fast rewrap rotates access without re-encrypting the payload and without plaintext ever existing. It is the right tool for adding people, algorithm migration, and format upgrades.
- Fast rewrap is not retroactive revocation. A removed recipient who kept a copy of the old file still knows the file key. Deep rewrap re-encrypts the payload under a fresh key and is the right tool when someone must actually lose access.

## What it does not protect against

- Traffic shape. File size, slot count, slot types and chunk structure are visible.
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
| HMAC-SHA-256 | crypto/hmac | RFC 2104 |
| Argon2id | golang.org/x/crypto | RFC 9106 |
| X-Wing expansion and combiner | this repo, internal/xwing | draft-connolly-cfrg-xwing-kem-10 |

The X-Wing code is validated against the draft's Appendix C test vectors on every CI run. The header MAC and STREAM payload constructions follow age; the keyslot model follows LUKS. Nothing in this project is a novel primitive or a novel protocol.

One deliberate deviation: the draft's Decapsulate uses raw RFC 7748 X25519, which returns an all-zero output for low-order inputs. crypto/ecdh rejects that case with an error, so sindook treats such ciphertexts as invalid. Honest senders never produce them.

## Operational notes

- `keygen -p` seals the identity file itself under a passphrase, so a stolen key file alone opens nothing. The .pub file stays public by design.
- `-passfile` reads passphrases from a file rather than argv or the environment, which are visible in process listings. The file's permissions are the caller's responsibility.
- Armor is transport encoding, not a security layer; armored and binary files carry identical ciphertext.
- `inspect` reveals only the traffic-shape metadata listed above, which any holder of the file already has. Slot metadata is authenticated by the header MAC only once a credential opens the file, so until then it is a claim.

## Known limitations

- Young project, no external audit. The design copies audited constructions to keep novel surface near zero.
- Side-channel resistance is inherited from the underlying library implementations.
- v1 files remain readable; their golden fixtures are part of the test suite.

## Reporting

Mail roy@ruddro.com.
