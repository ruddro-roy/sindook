# Roadmap

This is a direction for the project, not a promise of dates or completed
features. Each version below states what it must deliver for the people
who rely on sindook; the order is deliberate.

Sindook's funding model is the one used by established open-source
security products: the CLI, the Go library, and the file format stay
free and open under Apache-2.0, permanently; organizations that depend
on sindook fund continued development through support and services.

## v0.9 — Foundations

Make sindook dependable for people building on top of it.

- A public, versioned Go library API: the `box` sealing engine beside
  the already-public `xwing` package, so other tools can embed
  post-quantum file encryption instead of shelling out to the CLI.
- Reproducible release builds and installer validation on real
  Windows, macOS, and Linux hosts, not only syntax checks.
- The continuous-fuzzing pipeline (fifteen targets, daily runs with a
  persistent, pruned corpus) accumulating history.
- FreeBSD: release artifacts or an explicit source-only decision,
  documented in docs/COMPATIBILITY.md.

## v1.0 — The long-term promise

Earn the trust that decades-long storage requires.

- An independent security audit of the file format, key management,
  and X-Wing construction, funded and published.
- A frozen, documented file format with an explicit compatibility
  contract and enforced fixtures across every released version.
- An exercised security-response process: private reporting, response
  timelines, and at least one coordinated disclosure cycle.
- Stable CLI and Go API commitments, as described in
  docs/COMPATIBILITY.md.

## v1.x — Team operations

Serve the workflows of teams and organizations with long-lived data.

- Team key directories: shared recipient lists that stay in sync
  without trading private keys.
- Machine-readable `verify` reports for backup-compliance jobs, and
  rotation-due awareness so rewrap happens before people leave.
- Signed policy manifests for organizations that must prove which
  algorithms and format versions their archives use.
- A desktop application for people who should not need a terminal;
  the CLI remains fully supported and free.

## Beyond

- Additional recipient or provenance mechanisms, only with format
  compatibility and security review.
- Hardware-backed identity integrations where platform APIs provide a
  suitable security boundary.
- More package-manager distribution options once release verification
  is repeatable.

Sindook will not add new cryptographic primitives or incompatible file
formats merely for feature breadth. Security, interoperability, and
long-term file readability take priority.
