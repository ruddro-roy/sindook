# sindook file formats

Integers are big-endian, sizes in bytes. Format v2 is written by sindook 0.2.0 and later; v1 files remain readable forever, proven by golden fixtures in the test suite.

## Format v2

A sealed file is header, header MAC, payload, in that order.

### Header

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `SINDOOK2` |
| 8 | 16 | file nonce |
| 24 | 1 | slot count, 1 to 32 |
| 25 | ... | key slots |

Each key slot is `[type: 1][body length: 2][body]`. The length prefix lets a reader skip slot types it does not know, so future algorithms can be added without breaking old readers. Body length is capped at 4096.

Slot type `0x01`, X-Wing recipient, body 1168:

| offset | size | field |
|---|---|---|
| 0 | 1120 | X-Wing ciphertext: ML-KEM-768 ciphertext (1088), then X25519 ephemeral public key (32) |
| 1120 | 48 | wrapped file key |

Slot type `0x02`, Argon2id passphrase, body 73:

| offset | size | field |
|---|---|---|
| 0 | 4 | Argon2id passes |
| 4 | 4 | Argon2id memory, KiB |
| 8 | 1 | Argon2id lanes |
| 9 | 16 | salt |
| 25 | 48 | wrapped file key |

Parsing enforces passes in [1, 64], memory in [8 x lanes, 1048576] KiB and lanes in [1, 64], so a hostile header cannot demand unbounded work. Writers cap passphrase slots at 4.

### Wrapped file key

Every slot wraps the same random 32-byte file key with ChaCha20-Poly1305, nonce all zero, associated data `magic || file nonce || slot type || slot public part` (the body minus the wrapped key). The zero nonce is safe because each wrap key is single use, derived from a fresh KEM shared secret or a fresh salt. The associated data pins a slot to this exact file and its own KDF parameters, so slots cannot be transplanted between files and parameters cannot be downgraded.

Wrap key derivation:

- X-Wing slot: HKDF-SHA-256(secret = X-Wing shared secret, salt = file nonce, info = `sindook/v2/wrap`)
- passphrase slot: Argon2id(passphrase, salt, slot parameters), 32 bytes

### Header MAC

32 bytes directly after the last slot: HMAC-SHA-256 over every header byte before it, keyed by HKDF-SHA-256(secret = file key, salt = file nonce, info = `sindook/v2/hdr-mac`). Only a holder of the file key can compute it, so adding, removing, or reordering slots is detected the moment any legitimate credential opens the file. This is the approach age uses for its header.

### Payload

Payload key: HKDF-SHA-256(secret = file key, salt = file nonce, info = `sindook/v1/payload`). The info string is shared with v1 deliberately: the payload construction never changed, which is what allows rewrap to replace a header while carrying payload bytes over verbatim, including upgrading a v1 file to v2 in place.

Plaintext is split into 64 KiB chunks. The final chunk may be shorter, and an empty plaintext is one empty chunk. Each chunk is sealed with ChaCha20-Poly1305 under the nonce

    3 zero bytes || 8-byte big-endian chunk counter || final-chunk flag (0x00 or 0x01)

This is the STREAM construction as used by age. Truncation, chunk reordering, chunk deletion and appended data each fail authentication at the affected chunk.

## Rewrap

Rewrap parses a header (either version), recovers the file key with any valid credential, verifies header integrity, and writes a fresh v2 header for the new slot set.

- Fast mode keeps the file key and file nonce, so the payload bytes are copied through untouched. Rotating recipients across any amount of data costs one header per file and plaintext never exists anywhere, not even in memory beyond the file key.
- Deep mode draws a fresh file key and nonce and re-encrypts the payload by streaming decrypt and re-encrypt, one chunk in memory at a time.

Fast mode does not retroactively revoke a removed recipient who kept a copy of the old file, because the file key is unchanged. Deep mode exists for exactly that case.

## Format v1, legacy

Read support only. A v1 file is header, wrapped file key (48 bytes, ChaCha20-Poly1305, zero nonce, associated data the entire header), payload as above.

Recipient mode header: magic `SINDOOK1` (8), mode `0x01` (1), X-Wing ciphertext (1120), file nonce (16). Wrap key: HKDF-SHA-256(shared secret, salt = file nonce, info = `sindook/v1/wrap`).

Passphrase mode header: magic `SINDOOK1` (8), mode `0x02` (1), Argon2id passes (4), memory KiB (4), lanes (1), salt (16), file nonce (16). Wrap key: Argon2id(passphrase, salt, parameters). Same parameter caps as v2.

## ASCII armor

Optional transport encoding for any sealed file, produced by `seal -a` and detected automatically on read:

    -----BEGIN SINDOOK ENCRYPTED FILE-----
    base64, standard alphabet, 64-column lines, padding on the final line only
    -----END SINDOOK ENCRYPTED FILE-----

The armored bytes are exactly the binary file; armor adds no security and removes none. Readers are strict: ragged or blank body lines, padding before the final line, a missing end marker, and non-whitespace after it are all rejected. CRLF line endings and blank lines outside the markers are tolerated.

## Protected identities

`keygen -p` stores the identity as a standard sindook file with one passphrase slot whose plaintext is the ordinary identity text. Any sindook reader can decrypt it; tooling recognizes it by the file magic.
