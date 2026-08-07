# Threat model

This document states the security boundary for Sindook. It is a design statement, not an independent security audit or a guarantee that future cryptography will remain secure.

## Intended protection

Sindook is designed for encrypting files at rest and in transit. It uses a hybrid X-Wing recipient slot built from X25519 and ML-KEM-768, plus authenticated encrypted payload chunks. The aim is to protect ciphertext recorded today against a future attack that compromises only one component of the hybrid key establishment.

Sindook also aims to detect modification, truncation, reordering, extension, and unauthorised key-slot changes when a legitimate credential opens the file. The exact format is documented in [FORMAT.md](FORMAT.md).

## Assets and trust boundaries

The protected assets are plaintext file contents, the random per-file key, recipient identities, and passphrases.

The following inputs are untrusted and must be treated as hostile:

- sealed files received from another system;
- ASCII-armored sealed data;
- recipient lists and public-key files supplied by another party;
- storage that can corrupt, replay, truncate, or replace ciphertext.

The endpoint that seals or opens a file is trusted. Its operating system, random-number source, installed Sindook binary, and the way it handles plaintext after opening are outside the file format's protection.

## Attacker capabilities considered

Sindook is intended to handle an attacker who can copy ciphertext now, retain it for later cryptanalysis, alter ciphertext, remove or rearrange key slots, or provide malformed file headers.

The parser places limits on slot count, slot size, and Argon2id parameters before expensive work. The armor parser also limits line size. These limits reduce, but do not eliminate, denial-of-service risk from attacker-controlled input.

## What remains visible

A holder of a sealed file can observe its approximate size, encoding, format version, slot count, slot types, chunk structure, and declared passphrase KDF parameters. Sindook does not provide traffic-flow secrecy, recipient anonymity, deniability, or filename hiding outside the encrypted file itself.

`inspect` exposes only this already-visible metadata. Until a credential verifies the header MAC, metadata from an untrusted file is not authenticated.

## Key compromise and rotation

A stolen identity or correct passphrase can open every file for which it has a matching key slot. Protect identities and passphrases separately from ciphertext and back them up carefully.

Fast rewrap changes key slots but retains the file key and payload ciphertext. It copies that ciphertext into a replacement file without decrypting or re-encrypting it. It does not revoke someone who retained an old copy of the file. Deep rewrap creates a new file key and payload, but it cannot erase copies already held by an attacker or recipient.

## Streaming behavior

Sindook authenticates each payload chunk before emitting that chunk. A modified file can therefore yield an authenticated prefix before a later damaged chunk causes the command to fail. `verify` is the complete-file check because it writes no plaintext. When opening to a new file path fails, Sindook removes the partial output; output already sent to stdout cannot be recalled.

## Out of scope

Sindook does not protect against:

- malware, keyloggers, or an attacker controlling the endpoint;
- compromise of a private identity, passphrase, backup, or plaintext after it is opened;
- memory forensics, swap, or guaranteed secret zeroization in Go;
- weak or reused passphrases;
- malicious or substituted release binaries;
- availability attacks, storage deletion, or rollback of an old ciphertext copy;
- side-channel resistance beyond the guarantees of Go and the imported cryptographic libraries.

## Operational guidance

Verify a release before use, keep the executable and its dependencies updated, use high-entropy passphrases, and run `sindook verify` on backups. For higher-risk deployments, obtain an independent security review and use operating-system controls, hardware-backed keys, and a tested backup and recovery process in addition to Sindook.

Security reports belong in the [security policy](../SECURITY.md), not in a public issue.