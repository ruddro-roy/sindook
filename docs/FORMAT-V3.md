# sindook format v3

Status: specification, implemented behind `seal -format 3`. Integers are big-endian, sizes in bytes.

v3 exists for one reason: to make a policy rotation touch a fixed number of bytes, independent of payload size. v2 rotations already avoid all payload cryptography, but they still copy the payload ciphertext to move the header, so the file is fully rewritten. v3 reserves a fixed header arena so the payload begins at a stable offset and never moves, and a rotation reads and writes only the arena.

The guarantee v2 established is preserved exactly: payload ciphertext is neither decrypted nor re-encrypted during a fast rotation.

## Layout

    offset 0                superblock, 64 bytes, immutable after seal
    offset 64               header slot 0, `slot capacity` bytes
    offset 64 + C           header slot 1, `slot capacity` bytes
    offset 64 + 2C          payload, chunked as in v1 and v2, to end of file

## Superblock

Written once at seal time and never modified afterwards. Every field is covered by each header slot's MAC, so a superblock swap is detected the moment a credential opens the file.

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `SINDOOK3` |
| 8 | 2 | format version, 3 |
| 10 | 2 | superblock length, 64 |
| 12 | 4 | file feature flags |
| 16 | 16 | file identifier, random |
| 32 | 4 | arena offset, 64 |
| 36 | 4 | slot capacity, multiple of 4096, in [4096, 1048576] |
| 40 | 8 | payload offset, equal to arena offset + 2 x slot capacity |
| 48 | 4 | CRC32C of the superblock with these four bytes zeroed |
| 52 | 12 | reserved, zero |

The file identifier is the domain-separation salt for key wrapping and header authentication. It is not secret and it is not the payload salt.

Readers reject a superblock whose magic, version, superblock length, arena offset, or payload offset does not match the values above, whose slot capacity is out of range or not a multiple of 4096, or whose CRC does not match.

## Header slot

Two slots hold the same logical header. Rotation writes one, verifies it, then writes the other, so a crash at any point leaves at least one authorized policy readable.

| offset | size | field |
|---|---|---|
| 0 | 4 | magic `SLT3` |
| 4 | 2 | slot format version, 3 |
| 6 | 1 | slot index, 0 or 1, must equal the slot's position in the arena |
| 7 | 1 | content algorithm identifier |
| 8 | 8 | generation, monotonic |
| 16 | 4 | used length, in [116, slot capacity] |
| 20 | 4 | capacity, must equal the superblock's slot capacity |
| 24 | 4 | CRC32C of `slot[0:used length]` with these four bytes zeroed |
| 28 | 4 | slot feature flags |
| 32 | 16 | content nonce |
| 48 | 32 | policy digest, all zero when no policy is bound |
| 80 | 2 | key slot count, 1 to 32 |
| 82 | 2 | reserved, zero |
| 84 | ... | key slots |
| used length - 32 | 32 | slot MAC |

Key slots use the v2 framing, `[type: 1][body length: 2][body]`, and the v2 slot types and bodies: `0x01` X-Wing recipient, `0x02` Argon2id passphrase. Their total encoded length must be exactly `used length - 84 - 32`; any surplus or shortfall is a malformed slot.

Every byte from `used length` to `capacity` is zero. A writer that leaves stale bytes there has failed, because those bytes could be a superseded wrapped file key.

### CRC32C is not authenticity

The CRC field detects a torn write: a slot half-written when power was lost. It is unkeyed and an attacker can recompute it. Authenticity comes only from the slot MAC, and the MAC can only be checked after a credential recovers the file key. Between parsing and unwrapping, everything in a slot is a claim.

### Slot MAC

    macKey = HKDF-SHA-256(secret = file key, salt = file identifier, info = "sindook/v3/hdr-mac")
    slot MAC = HMAC-SHA-256(macKey, superblock[0:64] || slot[0:used length - 32] with slot[24:28] zeroed)

The CRC field is zeroed for the MAC because the CRC is computed last, over a region that includes the MAC. Authenticating it as well would make each depend on the other. Nothing is lost: the CRC carries no information that is not derivable from the bytes the MAC already covers.

Covering the superblock binds the file identifier and the arena geometry to the header. Covering the slot index defeats a verbatim copy of one slot over the other: the copy carries the source index and fails the position check before the MAC is even reached.

### Key wrapping

As in v2, one random 32-byte file key is wrapped once per key slot with ChaCha20-Poly1305 under an all-zero nonce, safe because each wrap key is single use. Associated data is `"SINDOOK3" || file identifier || slot type || slot public part`, which pins a wrap to this file and to its own KDF parameters.

    X-Wing slot:     wrap key = HKDF-SHA-256(secret = X-Wing shared secret, salt = file identifier, info = "sindook/v3/wrap")
    passphrase slot: wrap key = Argon2id(passphrase, salt, slot parameters), 32 bytes

### Payload

    payload key = HKDF-SHA-256(secret = file key, salt = content nonce, info = "sindook/v1/payload")

Chunking, nonce construction, and the final-chunk flag are unchanged from v1 and v2. The info string is deliberately shared across all three formats: the payload construction never changed, which is what lets a v1 or v2 file migrate to v3 with its payload ciphertext copied verbatim, and what lets a fast rotation leave the payload untouched.

The payload ends at end of file. There is no payload length field, so appended garbage is caught by chunk authentication rather than by a length check.

## Algorithm registry

Cryptographic behaviour is selected by explicit identifiers, never inferred from the format version. Adding an algorithm adds a row; it does not bump the format version.

| field | value | meaning |
|---|---|---|
| content algorithm | 1 | ChaCha20-Poly1305, STREAM chunking, 64 KiB chunks |
| key slot type | 0x01 | X-Wing, draft-connolly-cfrg-xwing-kem-10, ML-KEM-768 + X25519 |
| key slot type | 0x02 | Argon2id, RFC 9106, parameters in the slot body |

A reader that does not recognise a content algorithm identifier rejects the file. A reader that does not recognise a key slot type skips that slot; unknown slot types remain covered by the slot MAC, so they cannot be used to smuggle bytes past authentication.

## Feature flags

Both flag fields split into a critical half and an advisory half.

- bits 0 to 15, critical: a reader that does not understand a set bit must refuse the file.
- bits 16 to 31, advisory: a reader that does not understand a set bit ignores it.

No flags are defined at v3.0. Both fields are zero in files written today, and a set critical bit is an unsupported-feature error.

## Reading

1. Read and structurally validate the superblock. Reject unknown critical file flags.
2. Read both slots. A slot is *structurally complete* when its magic, version, and capacity match, its index equals its position, its used length is in range, its CRC matches, its key slots exactly fill the declared space, and it carries no unknown critical flags.
3. Select the structurally complete slot with the highest generation. On a tie, select slot 0.
4. Try credentials against the selected slot only.
5. Verify the slot MAC before touching the payload.
6. Derive the payload key and read from the payload offset.

Step 4 is deliberate. A reader never falls back to a lower generation because the supplied identity failed to open the selected one. Falling back would let anyone whose access was just revoked recover it by presenting the old identity, which is precisely the property rotation is supposed to remove. Inspecting or opening a lower generation requires the explicit `recover` command, which warns that it may restore superseded access.

## Rotation

A rotation holds an exclusive lock on the file for its whole duration and commits in two phases.

1. Acquire an exclusive file lock. A second writer that cannot take the lock fails rather than waiting forever.
2. Read the superblock and both slots. Select the active slot, recover the file key, verify its MAC.
3. If the caller supplied an expected generation, compare it with the active generation and fail with a stale-generation error on mismatch.
4. Let G be the highest generation of any structurally complete slot, including a slot that is not the active one. Build the new header at generation G+1.
5. If the new header does not fit in the slot capacity, fail with a capacity error that reports both the required and the available size. Never fall back to rewriting the payload.
6. Write the new header, zero-filled to the full capacity, over the slot that is *not* active. Sync.
7. Re-read that slot and verify its structure, CRC, and MAC. A failure here aborts with the original policy still intact.
8. Write the same header, with the index field adjusted, over the previously active slot. Sync.
9. Release the lock.

Payload bytes are never read and never written. Bytes touched are exactly `2 x slot capacity` written and at most `64 + 2 x slot capacity` read.

### What an interrupted rotation leaves behind

Honest statement of the crash model, phase by phase.

| interrupted during | what a reader sees | what remains recoverable |
|---|---|---|
| step 6 | torn slot fails CRC, old slot selected | old policy only |
| between 6 and 8 | both slots complete, new generation selected | new policy by normal open, old policy by `recover` |
| step 8 | torn slot fails CRC, new slot selected | new policy only |

So a crash may leave the old policy, the new policy, or both logically recoverable, until an authorized operation completes the scrub. `sindook repair` performs that scrub: it rewrites both slots at the highest generation, after which no superseded wrapped key material exists anywhere in the arena. A rotation that returns success has already completed the scrub.

### Concurrent writers

The exclusive lock prevents two rotations from interleaving their writes. The generation compare-and-swap covers the case the lock cannot: a writer that read the header, lost its lock, and came back. A stale writer is rejected rather than silently overwriting a newer policy.

### Capacity

The slot capacity is chosen at seal time and cannot grow in place, because growing it would move the payload. A rotation that needs more room than the arena provides returns a typed capacity error carrying the required byte count. Recovering from it is an explicit one-time migration to a larger arena, which does rewrite the whole file and is never performed implicitly.

Default capacity is the space the initial key slots need plus room for four more X-Wing recipients, rounded up to a multiple of 4096. An X-Wing key slot costs 1171 bytes encoded, a passphrase slot 79.

## Limits

These are properties of the format, not defects to be worked around.

- **Rollback is undetectable locally.** An attacker who can write the file can restore an entire older copy, arena and payload together, and a reader has no local state that would contradict it. Detecting rollback requires monotonic state outside the file: a receipt chain, a transparency log, or an adopter-controlled append-only store.
- **Logical erasure is not physical erasure.** Overwriting a slot removes the wrapped key from the logical file. Filesystem snapshots, copy-on-write media, journaled or log-structured filesystems, SSD wear levelling, object versions, backups, and any retained copy of the ciphertext are all outside that boundary and may still carry a superseded slot.
- **Fast rotation is not retroactive revocation.** A removed recipient who kept the old file still knows the file key and can decrypt that copy forever. Removing future access is what rotation does; removing past access requires deep re-encryption, and even then only for the copy that was re-encrypted.
- **The arena is fixed.** Files sealed with a small arena cannot grow one without a full rewrite.

## Compatibility

v1 and v2 files remain readable, proven by golden fixtures in the test suite. `sindook migrate` converts them to v3, preserving modification time and permissions where the operating system allows, and copies payload ciphertext verbatim without decrypting it. Migration is a full-file rewrite because the payload must move to make room for the arena; it is a one-time cost per file, after which rotations are bounded.
