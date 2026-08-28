---
iteration: 1
max_iterations: 25
completion_promise: "SCAN V1 SHIPPED: hardening committed, sindook scan (TLS endpoint + filesystem crypto audit) implemented, tested, documented, all quality gates green, committed on feature branch"
---

Evolve sindook (post-quantum file encryption CLI at /Users/ruddroroy/Downloads/sindook) into a daily tool for IT professionals. Work autonomously on branch feat/scan; never push to main, never tag releases, never create external repos, never modify packaging version numbers.

Priority order:

1. Commit the already-verified Windows build hardening (modified: .gitignore, .goreleaser.yaml, scripts/verify-reproducibility.sh; new: packaging/winres/winres.json) as the first commit on the feature branch. Commit author must be Ruddro Roy; no AI/agent mentions or trailers anywhere in commit messages.

2. Implement `sindook scan` v1, the crypto-posture scanner:
   - `sindook scan tls HOST[:PORT] ...` — read-only TLS endpoint audit: certificate expiry (warn <30d), chain validity, protocol versions (flag <TLS1.2), weak cipher suites, key strength (flag RSA<3072, note ECC), and post-quantum readiness: whether the server negotiates hybrid key exchange X25519MLKEM768 (probe with a restricted CurvePreferences handshake). Human output + `-json` following the doctorCheck/doctorReport pattern in cmd/sindook/doctor.go (name/status/detail/remediation).
   - `sindook scan files [PATH ...]` — filesystem crypto audit: find private keys/certs (PEM/OpenSSH/PKCS), flag expired or soon-expiring certs, weak RSA (<3072), unencrypted private keys, world/group-readable key files. Reuse expandInputs/multiFlag conventions from cmd/sindook.
   - Constraints: read-only scanning only (no exploitation, no brute force, no traffic capture); stdlib + golang.org/x only; connection timeouts; concurrency bounded.
   - Register the command in cmd/sindook/main.go alongside existing commands, matching existing usage-string style.
   - Unit tests for parsing/classification logic; integration-style tests using in-process TLS servers (crypto/tls) and tempdir fixtures for the file audit. Match the repo's exhaustive table-test style.
   - Docs: docs/man/sindook-scan.1 matching existing man page format (.TH line must say "sindook 0.8.2-dev"-consistent version per scripts/check-version-consistency.sh dev-mode rules — inspect existing man pages first), plus README section.

3. Every iteration: run gofmt -l ., go vet ./..., go test ./... (needs required_permissions all for toolchain cache), and bash scripts/check-version-consistency.sh (dev mode). Fix regressions immediately. Commit completed logical units with focused messages.

Standing constraints discovered in iteration 1 (do not violate):
- Windows hardening + winres.json were ALREADY committed by the user in c89c056; priority 1 is done. Scoop bucket repo already live.
- A concurrent session is bumping the repo to 0.9.0-dev (main.go version var, all man page .TH lines, README pins, CHANGELOG, V1_READINESS are modified in the working tree — NOT mine). Never revert, stage, or commit those files except the specific hunks I author (main.go command registration). Stage explicit paths only; never git add -A / git commit -a.
- Branch feat/scan contains one mislabeled commit (6007d2d); abandoned, user will delete. Work happens on branch scan-v1.
- History rewrites (amend/reset) are blocked by policy without user approval. Get commits right the first time; if one goes wrong, add a corrective commit instead.
- New man page .TH must match the 0.9.0 pattern: .TH SINDOOK-SCAN 1 "2026-08-27" "sindook 0.9.0" "User Commands" — verify against check-version-consistency.sh dev mode before committing.

Progress notes (append each iteration, newest last):
- [it1] Loop initialized. Hardening found already committed (c89c056). Created scan-v1 branch. Detected concurrent 0.9.0-dev bump. Next: read main.go/doctor.go/util.go patterns, design cmd/sindook/scan.go.
