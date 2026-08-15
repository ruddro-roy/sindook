# Compatibility promise

## Sealed files

Sindook's compatibility policy is to keep files sealed by released versions readable in later releases. Golden fixtures for the supported format versions are committed to the test suite and checked in CI. A format change must preserve those fixtures or provide a documented migration path. Format evolution is additive: new slot types and versions extend the header, readers skip slot types they do not know, and existing files are never rewritten except by an explicit rewrap.

## CLI

Within a major version, existing commands, flags, and exit codes keep their meaning; new ones may appear in minor versions. Machine-facing output (`-json`, exit codes) is stable. Human-readable text is not an interface and may change in any release.

### Exit codes (stable within a major version)

| Code | Meaning | Since |
| --- | --- | --- |
| `0` | success | v0.1.0 |
| `1` | operational failure: I/O error, malformed input, validation failure, payload corruption (`ErrNotSindook`, `ErrPayloadCorrupted`), or missing file | v0.1.0 |
| `2` | usage error: unknown command, flag-parsing failure, missing positional argument, or malformed credential supplied on the command line | v0.1.0 |
| `3` | authentication failure: wrong identity or passphrase, missing credential, or header tampering (`ErrWrongKey`, `ErrNeedIdentity`, `ErrNeedPassphrase`, `ErrHeaderTampered`) — split from code `1` in v0.6.0 for scripting | v0.6.0 |

Before v0.6.0, authentication failures exited with `1`. From v0.6.0 they exit with `3` so scripts can distinguish "wrong key" from "corrupted file" without parsing text. A joined error containing both a usage and an authentication failure exits with `2`.

### Memory locking (`internal/memguard`)

`memguard.LockAll()` is best-effort and never fatal:

| Platform | Behavior | Doctor status |
| --- | --- | --- |
| Linux, FreeBSD | Tries `mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT)` etc.; if `RLIMIT_MEMLOCK` is below 96 MiB, downgrades to `MCL_CURRENT` only to avoid pinning every future heap page and triggering a 64 MiB Argon2id OOM under low limits (e.g. GitHub Actions ~8 MiB) | `ok` when locked, `warning` with remediation when denied |
| darwin (macOS) | Raw `mlockall` returns `ENOSYS` in pure Go; reported as unsupported rather than a configuration problem | `ok` with note that swapping is not prevented (use full-disk encryption) |
| Windows | Walks committed regions with `VirtualLock` | `ok` or `warning` |
| Other | No memory-locking primitive | `ok` with unsupported note |

This behavior is not a compatibility promise; only the diagnostic output and exit codes are. See `docs/USER_GUIDE.md#troubleshooting` for `RLIMIT_MEMLOCK` remediation.

## Go API

`github.com/ruddro-roy/sindook/xwing` tracks the X-Wing Internet-Draft and is draft-stable: a wire-format change in the draft before RFC publication is the one event that may break it, and it will be a major-version event. `internal/` packages are not an API.

## Releases

From v0.4.0 onward, releases include an SBOM, a Sigstore keyless signature over the checksums, and GitHub build provenance. The latest release receives fixes; there is no LTS branch yet.

## Supported operating systems

Official release binaries and CI coverage target current macOS on Intel and
Apple Silicon, Windows 10/11 on amd64 and arm64, and mainstream Linux on
amd64 and arm64. The command surface, managed-contact config, `-glob` batch
selection, installers, and shell completion are designed for those targets.
Other Go platforms may compile from source but are not a release-support
promise yet.
