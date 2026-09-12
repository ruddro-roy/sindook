# Design rationale

Status: reference. Records which parts of format v2 follow the published
literature and which are project decisions, so a reviewer can tell
established constructions from local choices. Synthesized from a
literature survey of hybrid KEMs, envelope encryption, recipient
rotation, chunked AEAD, and password-based protection.

Related: [FORMAT.md](FORMAT.md) (the wire format this motivates),
[SECURITY.md](SECURITY.md) (what the composition defends against),
[KEYIDS_DESIGN.md](KEYIDS_DESIGN.md) (the deferred v3 extension).

## What the literature establishes

**Envelope encryption is the settled architecture.** File encryption is
a payload problem with a recipient-management layer on top: generate a
random data-encryption key, encrypt the payload once, and wrap that key
once per recipient. Because the wrap layer and the payload layer are
independent, recipient changes touch only wrapped keys, not ciphertext.
This is the structure sindook calls the LUKS keyslot model.

**Hybrid KEMs belong in the recipient layer, not the data path.** The
literature's reason for combining a classical and a post-quantum
component is migration safety: a harvest-now-decrypt-later adversary can
record ciphertext today and wait for quantum capability, and combiner
results show the composed KEM stays secure as long as either constituent
holds. Hybrid beats classical-only for files with multi-year
confidentiality horizons, and beats post-quantum-only during the
transition because it preserves current interoperability and avoids
betting on a single new family.

**Rotation has three cost classes.** Wrap-only updates re-wrap the file
key and leave the payload untouched. Transform-only updates (proxy
re-encryption, updatable encryption) let an untrusted party re-target
ciphertext without seeing plaintext. Deep re-encryption is required when
the payload's own cryptographic structure changes: AEAD mode, nonce
rules, chunk layout, stream format. The first and third classes exist in
sindook; the second is deliberately absent, as explained below.

**Chunked AEAD trades end-to-end integrity for scalability.** A chunked
stream gives bounded memory and constant-cost processing, but integrity
is per chunk rather than one tag over the whole object, so position and
finality have to be authenticated some other way. The literature
consistently flags nonce discipline and sequencing as the load-bearing
parts of such a construction.

**Derive separate keys per role.** HKDF-style extract-then-expand is the
standard tool for turning one shared secret into independent wrap,
header-authentication, and payload keys instead of reusing raw material.

**Passwords are a different branch.** Argon2id-style KDFs slow offline
guessing of low-entropy secrets. The literature places them in local
unlock, escrow, and recovery roles, not in recipient management; a weak
password stays weak regardless of KDF.

## How format v2 instantiates it

| Literature element | Format v2 choice |
|---|---|
| Random DEK | 32-byte file key per file |
| Chunked payload AEAD | ChaCha20-Poly1305, 64 KiB chunks, counter and final-chunk flag in the nonce (STREAM layout, from age) |
| Hybrid KEM per recipient | X-Wing (X25519 + ML-KEM-768), one slot each |
| Key separation | HKDF-SHA-256, salted by the file nonce, infos `sindook/v2/wrap`, `sindook/v2/hdr-mac`, `sindook/v1/payload` |
| Wrap integrity | ChaCha20-Poly1305 with AAD `magic ‖ fileNonce ‖ slot type ‖ slot public parameters`, so a slot is bound to its file and its own KDF settings |
| Header authentication | HMAC-SHA-256 over all header bytes, keyed by a file-key-derived subkey (the age approach), checked after some slot unlocks |
| Sequencing | Chunk counter and last-chunk flag inside the nonce; tampering, truncation, reorder, and extension all fail authentication at the damaged chunk |
| Password branch | Argon2id (RFC 9106 parameters), at most 4 slots per file, parameters capped on read |
| Wrap-only rotation | `rewrap` fast mode and `RewrapEdit`: kept slots copied verbatim, payload untouched |
| Deep re-encryption | `rewrap -deep` / `rotate -deep`: fresh file key and nonce, streaming re-encrypt |

## Decisions the literature does not settle

- **The exact X-Wing combiner.** The survey corpus does not recover the
  SHA3-256 mixing formula or the malformed-ciphertext handling. Sindook
  takes both from draft-connolly-cfrg-xwing-kem-10 directly: the
  combiner input `ss_MLKEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label`,
  validated byte-for-byte against the draft's Appendix C vectors and
  cross-tested against the CIRCL and filippo.io implementations. One
  deliberate deviation, crypto/ecdh rejecting low-order X25519 inputs
  that raw RFC 7748 maps to an all-zero output, is documented in
  [SECURITY.md](SECURITY.md).
- **Header MAC over AAD-only.** Authenticating the header with a MAC
  keyed by the file key is the age construction, not a literature
  requirement. Its useful property is that header integrity is
  checkable only by a file key holder.
- **Transform-only updates.** Proxy re-encryption assumes an untrusted
  transformer. A local CLI already holds the file key, so PRE would add
  machinery without adding a trust boundary.
- **Caps and budgets.** 32 slots, 4 passphrase slots, 4096-byte slot
  bodies, Argon2id read caps, 64 KiB chunks: DoS and usability choices,
  not literature.
- **No key IDs.** Slots carry no recipient identifier, so a credential
  you do not hold cannot be matched to a slot. That privacy choice
  blocks inventory and named-slot removal;
  [KEYIDS_DESIGN.md](KEYIDS_DESIGN.md) is the deferred v3 answer.
- **age and OpenPGP comparisons.** The survey contains essentially no
  age evidence, and its OpenPGP evidence concerns certificate lifecycle
  rather than payload rewrap. Sindook's comparisons to those tools rest
  on the project's own reading of their formats, not on this literature.

## Open questions

- **Benchmarks.** No file-format benchmark in the corpus compares a
  hybrid recipient header against pure X25519 and pure ML-KEM baselines.
  Locally the effect is bounded: an X-Wing slot adds 1168 bytes and two
  KEM operations, and Argon2id dominates open-time cost whenever a
  passphrase slot exists.
- **Formal verification.** The composition of keyslots, STREAM payload,
  and the X-Wing combiner has no machine-checked proof. Risk is
  contained by copying audited constructions (age, LUKS, the X-Wing
  draft) instead of inventing new ones.
- **A standardized public-key keyslot format.** The survey infers that
  such a format would be the cleanest way to operationalize hybrid
  recipient rotation, but finds no single standardized design. Format v2
  plus `RewrapEdit` is sindook's instantiation; whether an interoperable
  standard emerges is worth tracking.

## Primary sources

- Connolly, Hövelmanns, Hülsing, et al., "Starfighters: On the General
  Applicability of X-Wing," IEEE S&P 2026, and
  draft-connolly-cfrg-xwing-kem-10.
- Giacon, Heuer, Poettering, "KEM Combiners," PKC 2018.
- Bindel, Brendel, Fischlin, et al., "Hybrid key encapsulation
  mechanisms and authenticated key exchange," 2019.
- Hirose, Minematsu, "A Formal Treatment of Envelope Encryption," 2025.
- Everspaugh, Paterson, Ristenpart, Scott, "Key rotation for
  authenticated encryption," 2017.
- Biryukov, Dinu, Khovratovich, "Argon2: New generation of memory-hard
  functions," IEEE EuroS&P 2016, and RFC 9106.
- Mosca, "Cybersecurity in an era with quantum computers," IEEE Security
  & Privacy 2018 (the harvest-now-decrypt-later framing).
- Design precedents rather than literature: the age file format spec
  (header MAC, STREAM chunking) and LUKS (the keyslot model).
