# sindook v1 format

A sealed file is header, wrapped file key, payload, in that order. Integers are big-endian, sizes in bytes.

## Header, recipient mode

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `SINDOOK1` |
| 8 | 1 | mode `0x01` |
| 9 | 1120 | X-Wing ciphertext: ML-KEM-768 ciphertext (1088), then X25519 ephemeral public key (32) |
| 1129 | 16 | file nonce |

## Header, passphrase mode

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `SINDOOK1` |
| 8 | 1 | mode `0x02` |
| 9 | 4 | Argon2id passes |
| 13 | 4 | Argon2id memory, KiB |
| 17 | 1 | Argon2id lanes |
| 18 | 16 | Argon2id salt |
| 34 | 16 | file nonce |

Opening enforces passes in [1, 64], memory in [8 x lanes, 1048576] KiB and lanes in [1, 64], so a hostile header cannot demand unbounded work.

## Wrapped file key

48 bytes directly after the header: ChaCha20-Poly1305 over a random 32-byte file key, nonce all zero, associated data the entire header.

Wrap key derivation:

- recipient mode: HKDF-SHA-256(secret = X-Wing shared secret, salt = file nonce, info = `sindook/v1/wrap`)
- passphrase mode: Argon2id(passphrase, salt, header parameters), 32 bytes

The zero nonce is safe because every wrap key is single use, derived from a fresh KEM shared secret or a fresh salt. The associated data binds the mode byte and all parameters, so any header tampering, including Argon2id parameter downgrades, fails the unwrap.

## Payload

Payload key: HKDF-SHA-256(secret = file key, salt = file nonce, info = `sindook/v1/payload`).

Plaintext is split into 64 KiB chunks. The final chunk may be shorter, and an empty plaintext is one empty chunk. Each chunk is sealed with ChaCha20-Poly1305 under the nonce

    3 zero bytes || 8-byte big-endian chunk counter || final-chunk flag (0x00 or 0x01)

This is the STREAM construction as used by age. Truncation, chunk reordering, chunk deletion and appended data each fail authentication at the affected chunk.
