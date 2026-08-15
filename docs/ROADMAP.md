# Roadmap

This is a direction for the project, not a promise of dates or completed features.

## Current v0.x baseline

- Hybrid X-Wing recipient slots using X25519 and ML-KEM-768.
- Documented v1 and v2 file formats with compatibility fixtures.
- Recipient and passphrase slots, armor, inspection, fast rewrap, and deep rewrap.
- Unit, race, fuzz-smoke, interoperability, vulnerability, and release checks in CI.
- Signed release checksums, SBOMs, and build provenance for releases from v0.4.0 onward.
- Native Linux/macOS/Windows installer scripts, PowerShell completion, and
  portable CLI-side glob expansion.
- Opt-in default identity paths and named public-recipient contacts without
  placing private identities or passphrases in application configuration.

## Before a 1.0 decision

- Keep compatibility fixtures and documented format behavior stable.
- Resolve user-facing issues found through real use and cross-platform testing.
- Obtain an independent security review or audit appropriate to the intended deployment risk.
- Document a repeatable release and recovery process.
- Reassess the X-Wing draft status and interoperability vectors if the IETF specification changes.

## Future, subject to design and review

- Additional documented recipient or provenance mechanisms, only with format compatibility and security review.
- Hardware-backed identity integrations where platform APIs provide a suitable security boundary.
- More package-manager distribution options after release verification remains repeatable.

Sindook will not add new cryptographic primitives or incompatible file formats merely for feature breadth. Security, interoperability, and long-term file readability take priority.
