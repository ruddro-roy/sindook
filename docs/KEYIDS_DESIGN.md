# Key IDs — design proposal

Status: PROPOSAL. Not implemented, not scheduled before the 1.0 format
freeze. This document exists so the v1.x format work starts from a
reviewed design instead of a blank page. Everything here is open to
revision; the open decisions are listed as open at the end.

Related: [FORMAT.md](FORMAT.md) (current v2 layout),
[COMPATIBILITY.md](COMPATIBILITY.md) (stability policy), the rotate
command (attempt-driven rotation shipped in v0.11.1, which this
proposal would extend, not replace).

## Problem

A sealed file's slots carry encapsulated key material but no public-key
identifier. Given only the ciphertext, there is no cheap way to answer
"is this file sealed to identity X?" Three operations that users of a
maturing tool eventually need are impossible in format v2:

1. **Inventory.** List which identities appear in which files, without
   holding any private key. Needed for fleet audits and key hygiene.
2. **Metadata rotation.** Find files sealed to a retired identity
   without attempting an authenticated open of each one (rotate today
   requires holding the retired key and attempting every candidate).
3. **Partial revocation.** Remove or replace one slot in place without
   rewrapping the whole slot set.

## Proposal

Add a key ID to every recipient slot: the first 16 bytes of
SHA-256 over the 1216-byte X-Wing public key, stored alongside the
encapsulated key. A slot then reads as (key ID, encapsulated file key).
The contact list already displays this exact digest as a fingerprint
(16 bytes, `sha256:` prefix, `contacts list`), so operators can match a
slot to a contact by eye. 128-bit truncation gives 2^64 collision
resistance, which is recognition, not authentication; matching always
remains subject to the header MAC, and a collision cannot make an
unrelated key open a file.

What this enables:

- `inspect` lists slot key IDs with no credentials (it already reads
  unauthenticated metadata; the header MAC still gates everything
  operational).
- Inventory mode: walk a tree, report files by slot key ID, no private
  keys involved.
- Rotation by metadata: select files whose slots include the retired
  key ID, then rewrap or rotate them; the authenticated open stays as
  the proof of authority, but the candidate set comes from metadata.
- Partial slot surgery in deep tooling: with the file key (via any
  slot), rewrite the slot set without re-encrypting the payload — this
  is what rewrap already does; key IDs just make the slot-level
  reasoning visible.

## Wire layout and migration

Format version bumps v2 → v3, additively:

- Slot records in v3 carry a one-byte type tag distinguishing
  `xwing-slot-v3` (key ID + encapsulated key) from the v2 layout.
- v3 writers emit only v3 slots for X-Wing recipients. Passphrase slots
  gain a key ID over the Argon2 KDF context or stay untagged; open
  decision.
- v3 readers must open v1 and v2 files unchanged. The fixture chain
  (every release opens files sealed by all previous released binaries)
  extends to v3; the interop module and fuzz corpus grow v3 seeds.
- v2 readers presented a v3 file fail with the existing version error.
  Because rotation and rewrap rewrite headers, a v2 reader's operator
  can convert by rewrapping with a v3 binary — the migration path is a
  normal rotate, not a tool.

## Privacy review

Key IDs leak the recipient set to anyone who holds the file. That is a
real regression from v2, where a sealed file reveals the slot count and
nothing about who. Three mitigating facts, stated plainly rather than
argued away:

- The leak is bounded by the recipient's hygiene, not the file's: the
  key ID is a hash of a public key. An attacker who guesses a candidate
  public key can confirm membership; an attacker who cannot enumerate
  candidates learns little. Widely published keys (team keys, well-known
  contacts) are confirmable.
- Anyone the file was sealed to, and anyone they forwarded it to, can
  already derive the same information by attempting opens.
- The design still does not include any sender or device identifier,
  and `inspect` output remains free of network lookups; key IDs are
  local hex strings.

Open mitigation option: a per-file salt folded into the key-ID hash,
making IDs unlinkable across files at the cost of inventory matching by
digest only (you can still recognize your own keys by computing the
salted digest; third parties cannot correlate files without the public
key). This trades confirmability for unlinkability and is the central
open decision below.

## Fixture and interop plan

1. Extend FORMAT.md with the v3 layout before any code lands.
2. Implement reader support first (v3 slots parse, fixture chain green),
   then writer support behind the version bump, then inventory and
   metadata rotation commands, in that order, each with its own release.
3. Per-release fixtures: a v3 round adds v3 fixtures to the chain; v2
   and v1 fixtures keep proving backward reads.
4. The interop module checks key-ID derivation against CIRCL and
   filippo.io public keys (digest agreement), and the fuzz corpus gains
   v3 seed headers.

## Why this waits for the 1.0 freeze

Format changes are the one class of mistake this project cannot cheaply
undo: files sealed today must open for decades, the compatibility
promise and the fixture chain exist precisely to make format evolution
expensive and deliberate, and rotate (v0.11.1) already covers the
operational need for identity retirement without any format change.
Shipping key IDs before the audit and the 1.0 format review would add
an unaudited format feature to a format about to be frozen. The
sequence is: audit → 1.0 freeze of v3-less v2 → key IDs as the first
reviewed v3 change.

## Open decisions

1. Salted (unlinkable) versus unsalted (confirmable) key IDs — privacy
   trade-off described above; decide before the format RFC-style review,
   not during implementation.
2. Do passphrase slots get key IDs (over what digest input), or remain
   untagged?
3. Key-ID length: 16 bytes (matches the contacts fingerprint) versus 8
   (smaller headers, 2^32 collision space, weaker recognition).
4. Whether `inspect` shows key IDs by default or behind a flag, given
   the privacy review.
5. Whether v3 also carries a slot-creation timestamp, which some
   rotation audits want and some threat models reject.
