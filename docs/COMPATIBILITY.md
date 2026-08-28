# Compatibility promise

This document is the product contract for Sindook 0.8.1: what is stable,
what may change, and what is explicitly not promised. It is accurate for the
v0.8.1 release and updated on every release. Historical behavior is marked
as such.

## Supported operating systems and architectures

Official release binaries and CI coverage target:

| OS | Architectures | Notes |
| --- | --- | --- |
| Linux | amd64, arm64 | mainstream distributions |
| macOS | amd64, arm64 | current macOS on Intel and Apple Silicon |
| Windows | amd64, arm64 | Windows 10/11; arm64 ships and is CI-tested, but it has seen less real-world use than amd64, report issues |
| FreeBSD | amd64, arm64 | source-only by decision (v0.9): the pure-Go memory-locking and filesystem code paths support it, but there is no CI runner or maintainer hardware to guarantee artifacts, so no official archive is shipped; `go install github.com/ruddro-roy/sindook/cmd/sindook@vX.Y.Z` or building from source is the supported path |

The command surface, managed-contact config, `-glob` batch selection,
installers, and shell completion are designed for those targets. Other Go
platforms may compile from source but are not a release-support promise yet.

## Supported Go version

`go.mod` declares `go 1.26.6`. Building from source requires Go 1.26.6 or
newer. `go install github.com/ruddro-roy/sindook/cmd/sindook@v0.8.1` works
with any toolchain meeting the module requirement; if the local toolchain
is older, the Go toolchain's `GOTOOLCHAIN=auto` behavior downloads the
required toolchain automatically. A binary installed from a release tag
reports that tag from its module build info:

```sh
go install github.com/ruddro-roy/sindook/cmd/sindook@v0.8.1
sindook version   # "sindook 0.8.1"
```

Source-tree builds report `sindook 0.8.1-dev` plus commit provenance, and
release binaries built by the release workflow carry the exact tag.

## CLI

Within a major version, existing commands, flags, and exit codes keep their
meaning; new ones may appear in minor versions. Machine-facing output
(`-json`, exit codes) is stable. Human-readable text is not an interface and
may change in any release.

`verify -json` reports one array of `{file, status, error?, sha256?, size?,
baseline_sha256?}`; `sha256` (of the sealed ciphertext) and `size` appear
only with `-save` or `-baseline`, and `baseline_sha256` only in `-baseline`
comparisons. Status is `ok` or `failed` in plain runs; baseline runs may
additionally report `changed` (restores cleanly but the sealed bytes differ
from the baseline), `new` (not in the baseline), and `missing` (in the
baseline but absent from disk). Baseline drift is report-only: only failed
decryption changes the exit code. A `-save`/`-baseline` file is JSON with
`version: 1`, `created_at`, and `entries: [{file, sha256, size?,
verified_at}]`; loading rejects an unknown `version`, and future changes
are additive like the config file.

`scan -json` (added during v0.10 development) reports one object
`{version, platform, mode, targets, errors, warnings}` where `targets` is
one `{target, checks, errors, warnings}` per operand and `checks` follows
the doctor check shape `{name, status, detail, remediation?}`. `status` is
`ok`, `warning`, or `error`; the report's `errors`/`warnings` counts drive
the exit code the same way `doctor -json` does. `scan files` never emits
key material; `scan tls` records endpoint metadata only. Findings and
check names are human-facing labels and may gain entries in any release;
the envelope shape is stable within a major version.

Before 1.0, the CLI is still maturing: a future minor release may add
flags, extend `-json` output with new fields (additive), or rename a
command, but any user-visible change is announced in the changelog
([docs/CHANGELOG.md](CHANGELOG.md)) and the renamed spelling is kept as a
deprecated alias where practical.

### Credential defaults (since v0.8.0)

After `sindook init`, `seal`, `open`, `verify`, and `rewrap` use the
configured default identity when no credential flag is given:

- `seal FILE` with no `-r`, `-R`, or `-p` seals to the default identity.
- `open`, `verify`, and `rewrap` with no `-i`, `-p`, or `-passfile` unlock
  with the default identity.
- Each command prints which identity it used to stderr, so automation logs
  stay explicit. `-json` output goes to stdout and is unchanged.
- With no default identity configured, the commands keep failing with a
  usage error (exit `2`) and name `sindook init` in the message.

Explicit flags always win and keep their exact prior meaning; `-i @default`
also still works. This is a behavior change from v0.7.x, where bare
credential-less commands always failed; scripts that relied on that failure
should set `SINDOOK_CONFIG_DIR` to an empty directory, which restores it.

### Exit codes (stable within a major version)

| Code | Meaning | Since |
| --- | --- | --- |
| `0` | success | v0.1.0 |
| `1` | operational failure: I/O error, malformed input, validation failure, payload corruption (`ErrNotSindook`, `ErrPayloadCorrupted`), or missing file | v0.1.0 |
| `2` | usage error: unknown command, flag-parsing failure, missing positional argument, or malformed credential supplied on the command line | v0.1.0 |
| `3` | authentication failure: wrong identity or passphrase, missing credential, or header tampering (`ErrWrongKey`, `ErrNeedIdentity`, `ErrNeedPassphrase`, `ErrHeaderTampered`), split from code `1` in v0.6.0 for scripting | v0.6.0 |

Before v0.6.0, authentication failures exited with `1`. From v0.6.0 they exit with `3` so scripts can distinguish "wrong key" from "corrupted file" without parsing text. A joined error containing both a usage and an authentication failure exits with `2`.

### Memory locking (`internal/memguard`)

`memguard.LockAll()` is best-effort and never fatal:

| Platform | Behavior | Doctor status |
| --- | --- | --- |
| Linux, FreeBSD | Tries `mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT)` etc.; if `RLIMIT_MEMLOCK` is below 96 MiB, downgrades to `MCL_CURRENT` only to avoid pinning every future heap page and triggering a 64 MiB Argon2id OOM under low limits (e.g. GitHub Actions ~8 MiB) | `ok` when locked, `warning` with remediation when denied |
| darwin (macOS) | Raw `mlockall` returns `ENOSYS` in pure Go; reported as unsupported rather than a configuration problem | `warning` with note that swapping is not prevented (use full-disk encryption) |
| Windows | Walks committed regions with `VirtualLock` | `ok` or `warning` |
| Other | No memory-locking primitive | `warning` with unsupported note |

This behavior is not a compatibility promise; only the diagnostic output and exit codes are. See `docs/USER_GUIDE.md#troubleshooting` for `RLIMIT_MEMLOCK` remediation.

## Configuration file

`config.json` lives in the per-user configuration directory
(`os.UserConfigDir()/sindook`, overridable with `SINDOOK_CONFIG_DIR` for
portable installs and isolated automation). Schema, version 1:

```json
{
  "version": 1,
  "default_identity": "/absolute/path/to/identity.key",
  "contacts": {
    "alice": {
      "public_key": "sindookpk1:...",
      "added_at": "2026-08-16T00:00:00Z"
    }
  },
  "groups": {
    "team": {
      "members": ["alice"],
      "added_at": "2026-08-27T00:00:00Z"
    }
  }
}
```

- `default_identity` is an optional absolute path to a user-owned identity file. Sindook stores the path; it never copies, moves, or rewrites the identity.
- `contacts` maps portable, case-insensitive names to full public keys.
- `groups` (added during v0.9 development) maps names to member lists of saved contact names. A group seals to one key slot per distinct member key, in sorted member order. Groups never nest and share the contact namespace, so a name is either a contact or a group, never both. Older binaries ignore the field; configs without it load unchanged.

Migration policy: changes are additive, new optional fields with defaults
that older versions can ignore. The loader rejects a `version` it does not
know rather than guessing. Unknown fields are ignored when loading; when
Sindook next writes the file it writes only the fields it knows, so
hand-edited extras are not preserved across a save. Contact names are
validated for portability (no Windows-reserved names) on load.

## Identity and contact storage

- Private identity files never enter the configuration directory. The config contains only public keys and the default identity's path.
- Identities are ordinary files (`keygen -o`); their permissions are the user's responsibility, and `keygen` creates them mode `0600` with a mode `0644` `.pub` sidecar on POSIX.
- `contacts list` prints each contact as `@name` plus a short fingerprint: SHA-256 over the decoded 1216-byte public key, first 16 bytes, lowercase hex, `sha256:` prefix (128-bit collision space; 2^64 collision resistance, for recognition, not authentication). `contacts show NAME` and `contacts list -json` print the full public key.
- `-r @group` and `rewrap -r @group` expand a saved group to its members' keys, deduplicated; the expansion error for a member whose contact was deleted names the group and member. Removing a contact that any group lists is refused until the group is repaired.
- `config list -json` reports `default_identity`, `default_identity_set`, `contacts`, and `groups`; `config get default-identity` prints the configured path, and `config set` validates that the identity file exists before storing its absolute path.

## Sealed files

Sindook's compatibility policy is to keep files sealed by released versions readable in later releases. Golden fixtures for the supported format versions are committed to the test suite and checked in CI. A format change must preserve those fixtures or provide a documented migration path. Format evolution is additive: new slot types and versions extend the header, readers skip slot types they do not know, and existing files are never rewritten except by an explicit rewrap.

### Format versions and deprecation policy

| Version | Status | Since |
| --- | --- | --- |
| v2 | current; written by all releases since v0.2.0 | v0.2.0 |
| v1 | legacy; read-only support, covered by golden fixtures | v0.1.0 |

The byte layout is specified in [docs/FORMAT.md](FORMAT.md). Deprecation
means "still readable, no longer written"; no version has been removed from
the reader. Removing read support for a format version would require a
major version and an explicit migration window, there is no plan to remove
v1 read support. Compatibility is proven by committed fixtures: v1 golden
files, and files produced by the released v0.6.0 binary (`box/testdata/v060-*.sindook`),
opened by the current test suite.

### Rewrap security properties

Rewrap parses a header (either version), recovers the file key with any
valid credential, verifies header integrity, and writes a fresh v2 header
for the new slot set.

- Fast mode keeps the file key and file nonce, so the payload bytes are copied through unchanged into a replacement file. It does not decrypt or re-encrypt the payload and does not materialize payload plaintext. It is the right tool for adding recipients, changing passphrases, and upgrading v1 files to v2 in place.
- Fast mode is not revocation: a removed recipient who kept a copy of the old file still knows the file key.
- Deep mode draws a fresh file key and nonce and re-encrypts the payload by streaming decrypt and re-encrypt, one chunk in memory at a time. A removed recipient cannot open the newly produced replacement through an old slot, but neither mode can invalidate copies already held by an attacker or recipient.

### Symlink and filesystem-safety behavior

Output handling refuses to overwrite a symbolic link or a non-regular file
at the destination path (`writeOutputStaged` checks with `Lstat`). With
`-f`, output is staged beside the destination and renamed into place only
after a successful write, so a failed operation never destroys the previous
file. On POSIX, new output files are mode `0600`; public key files `0644`.

Not protected (documented limitations, not bugs): symlinked or attacker-
controlled parent directories (staging happens beside the destination, so a
hostile directory can race the rename), symlinked *input* paths (read
inputs are opened as given), and TOCTOU races on the destination itself.
Same-directory rename behavior is platform-dependent. The threat model
assumes the endpoint and its filesystem are trusted ([docs/THREAT_MODEL.md](THREAT_MODEL.md)).

## Go API

The public Go API is two packages: `github.com/ruddro-roy/sindook/box`
(seal, open, rewrap, inspect, selftest) and
`github.com/ruddro-roy/sindook/xwing` (the X-Wing hybrid KEM).
Everything under `internal/` is not an API and may change freely in any
release.

While the module is v0.x, the `box` and `xwing` APIs may change between
minor releases with a changelog entry; breaking changes are avoided where
practical. From v1.0, both packages follow the same compatibility promise
as the CLI and the file format: no breaking changes within a major
version. `xwing` remains draft-stable: a wire-format change in the draft
before RFC publication is the one event that may break it, and it will be
a major-version event. Installing the CLI by module path
(`go install .../cmd/sindook@vX.Y.Z`) is supported.

## X-Wing draft status

Recipient key establishment uses [X-Wing draft-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/10/). If the final RFC changes the wire format, Sindook will not silently switch: a new slot type or format version will be introduced, the change will ship in a new release with a changelog entry and a migration path (rewrap), and old files remain readable. No release will re-interpret existing ciphertext under changed semantics.

## Releases

From v0.4.0 onward, releases include an SBOM, a Sigstore keyless signature over the checksums, and GitHub build provenance. The release workflow is gated: the GitHub release is created only after the full CI suite has passed on the tagged commit, and a verification job validates checksums, Sigstore signatures, SBOM, and provenance before the release is promoted. The latest release receives fixes; there is no LTS branch yet. Tags are immutable: a broken release is fixed by a new patch version, never by moving a tag.

## Threat model and non-goals

The security boundary is [docs/THREAT_MODEL.md](THREAT_MODEL.md); the
security model and primitive provenance are [docs/SECURITY.md](SECURITY.md).

Explicit non-goals: no full-disk encryption, no hidden volumes, no
deniability, no recipient anonymity, no traffic-flow secrecy, no guaranteed
secret zeroization in Go, and no protection against a compromised endpoint.
Sindook has not received an independent security audit; treat the complete
file format and key-management design as unaudited until an independent
review is completed. The v1.0 gate for external evidence is tracked in
[docs/V1_READINESS.md](V1_READINESS.md).

Suspected vulnerabilities go through the private reporting process in
[SECURITY.md](../SECURITY.md), never a public issue.

## What pre-1.0 means for users

- Files you seal today will remain openable by later releases; compatibility fixtures and the documented format make that a test-enforced promise, not a hope.
- CLI flags and JSON output are stable within major version 0, but commands may be added or renamed with changelog notice before 1.0. Pin scripts to the exit-code and `-json` contract.
- No independent audit yet: treat Sindook as a young project and keep the executable, its dependencies, and your backups current. Verify a backup with `sindook verify` before you need it, and test upgrades with synthetic data first.
- Upgrades within v0.x are drop-in: format v2 is unchanged, config schema v1 is unchanged, and identities/contacts are untouched. v0.6.0 and v0.7.0 users upgrade to v0.8.1 by replacing the binary.
