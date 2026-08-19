# User guide

Sindook encrypts a file to one or more X-Wing recipients, a passphrase, or both. A recipient needs its identity file to open the data. A passphrase slot is useful for recovery or a small personal archive.

## Install

The fastest way, no administrator rights needed:

```sh
# macOS or Linux
curl -fsSL https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.sh | sh
```

```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/ruddro-roy/sindook/main/scripts/install.ps1 | iex
```

Or install from source with Go 1.26 or newer:

```sh
go install github.com/ruddro-roy/sindook/cmd/sindook@latest
sindook version
```

The installers verify the release SHA-256 entry before copying the binary
and print a PATH reminder when one is needed. Downloading them and running
directly works too, with `--version vX.Y.Z` to pin a release. Release
archives include checksums, an SBOM, a Sigstore bundle for `checksums.txt`,
and GitHub build provenance. See the verification commands in the
[README](../README.md#install) before trusting a downloaded binary.

## First-time setup: init, then no flags

`sindook init` creates an identity and remembers it as your default. After
that, the everyday commands need no flags:

```sh
sindook init
sindook seal report.pdf
sindook open report.pdf.sindook
```

Each command prints which identity it used. `init` stores only the
identity's path in the Sindook configuration directory, never the identity
itself or a passphrase. Use `sindook init -p` to also put a passphrase on
the identity file, or `sindook init -i existing.key` to make an existing
identity the default. `SINDOOK_CONFIG_DIR` overrides the config location
for portable installs and automation, and `sindook paths` shows it.

## Contacts

Save another person's public key under a portable contact name, then use
`@name` anywhere a recipient is accepted:

```sh
sindook contacts add alice alice.key.pub
sindook contacts list
sindook seal -r @alice project-plan.pdf
```

`contacts list` prints each contact as `@name` plus a short fingerprint:
SHA-256 over the decoded 1216-byte public key, first 16 bytes, lowercase
hex with a `sha256:` prefix, a 128-bit collision space. Use it to spot
that you are looking at the contact you expect, not to authenticate a key
(the collision resistance is 2^64). `contacts show NAME` and
`contacts list -json` print the full public key for real comparison.

`sindook paths` shows the platform-specific config location. It follows the
normal user configuration location for each OS, and `SINDOOK_CONFIG_DIR` can
override it for a portable installation or an isolated automation run. The
config contains only public keys and the default identity's path.

## Create and back up an identity

```sh
sindook keygen -o personal.key
# personal.key is secret; personal.key.pub is shareable
```

Keep the identity file out of cloud-sync folders and back it up separately from the sealed data. Anyone holding both a sealed file and the matching identity can open it.

To require a passphrase before the identity itself can be used:

```sh
sindook keygen -o personal.key -p
```

For non-interactive use, put the passphrase in a file with restrictive permissions and use `-passfile`. Never put a passphrase in a command line, environment variable, shell history, or repository.

`-passfile` supplies a passphrase used for a sealed file. A separately
protected identity uses `-identity-passfile`:

```sh
sindook open -i personal.key -identity-passfile identity.pass report.pdf.sindook
sindook verify -i personal.key -identity-passfile identity.pass backups/archive.sindook
```

## Seal a file for a recipient

```sh
sindook seal -r personal.key.pub report.pdf
# creates report.pdf.sindook

sindook open -i personal.key report.pdf.sindook
# restores report.pdf
```

Multiple recipients can each open the same file:

```sh
sindook seal -r alice.pub -r bob.pub budget.xlsx
```

When an identity is selected with `sindook init`, that identity is used
automatically by `seal`, `open`, `verify`, and `rewrap` when no credential
flag is given, and `@default` still names it explicitly anywhere `-r` or
`-i` accepts a key. Every such command prints which identity it used.

A recipient list accepts one `sindookpk1:` public key per line. Blank lines and `#` comments are ignored:

```sh
sindook seal -R team.keys plans.tar
```

## Compress while sealing

`-z` compresses with gzip before encrypting, and `open -z` reverses it:

```sh
sindook seal -z photos.tar
sindook open -z photos.tar.sindook
```

Logs, CSV, and tar archives shrink a lot; JPEG and ZIP files barely change.
Compression happens before encryption, so file sizes and padding reveal
nothing about content beyond the compressed length. `rewrap` rotates
compressed files unchanged, `verify -z` authenticates and decompresses
them like `open -z` would, proving the archive is fully recoverable, and
armor combines with `-z` as usual.

Decompression is bounded: `open -z` and `verify -z` refuse to expand past
1 TiB by default, so a hostile sealed archive cannot fill the disk. Raise,
lower, or lift the cap with `-max-decompressed`:

```sh
sindook open -z -max-decompressed 10G photos.tar.sindook
sindook open -z -max-decompressed 0 huge-dataset.tar.sindook   # unlimited
```

Opening a compressed file without `-z` writes the raw gzip stream, which
`gunzip` or a second `sindook open -z` still recovers; opening an
uncompressed file with `-z` fails with a clear message instead of writing
bad output.

## Use a passphrase slot

```sh
sindook seal -p notes.txt
sindook open -p notes.txt.sindook
```

A passphrase can be combined with recipients as a recovery path:

```sh
sindook seal -r personal.key.pub -p archive.tar
```

A `-passfile` reads only the first line of a file. On POSIX systems, keep that file readable only by its owner, for example with `chmod 600 recovery.pass`. On Windows, restrict the file with an appropriate ACL.

## Check a backup before you need it

`verify` fully decrypts and authenticates a file without writing plaintext:

```sh
sindook verify -i personal.key backups/*.sindook
```

POSIX shells normally expand `*`. For Windows `cmd.exe`, PowerShell, and any
script where you want the CLI itself to expand a filesystem pattern, use the
repeatable `-glob` flag instead:

```powershell
sindook verify -i @default -glob "backups/*.sindook"
sindook seal -r @alice -glob "reports/*.pdf"
```

This is the right command for backup checks. `open` streams authenticated chunks. If a file is damaged late in the stream, bytes already emitted are authenticated, but the command still fails because the complete file did not authenticate. When opening to a file path, Sindook removes a partial new output on failure. Do not treat a failed stdout pipeline as a complete file.

## Inspect without credentials

```sh
sindook inspect archive.tar.sindook
sindook inspect -json archive.tar.sindook
```

Inspection reports the format, slots, and KDF parameters. It cannot authenticate those metadata fields without a credential, so treat the report as a claim until `open` or `verify` succeeds.

## Rotate access

Fast rewrap replaces key slots without decrypting or re-encrypting the payload:

```sh
sindook rewrap -i personal.key -r alice.pub -r bob.pub archive.tar.sindook
```

This is appropriate for adding recipients, changing recovery passphrases, and migrating the file header. It writes a replacement file and copies the existing ciphertext. It is not retroactive revocation. Someone who kept an older copy still has the old file key.

Use `-deep` when a removed recipient must lose access to the replacement file:

```sh
sindook rewrap -i personal.key -r alice.pub -deep archive.tar.sindook
```

Deep rewrap creates a fresh file key and streams a new payload. Keep the old ciphertext inaccessible if revocation matters.

## Shred plaintext files

`shred` overwrites a file with pseudorandom data and then unlinks it, so the
plaintext is not recoverable from the deleted file through ordinary means:

```sh
sindook shred old-plaintext.txt
sindook shred -n 3 *.docx
sindook shred -glob "old/*.docx"   # portable to cmd.exe and PowerShell
```

It does not destroy every trace of a file. On SSDs, wear leveling and the
flash translation layer decide which physical blocks actually receive the
overwrites, and TRIM does not run on a schedule you control. Journaling
filesystems, copy-on-write filesystems (APFS, ZFS, btrfs), snapshots,
backups, and cloud-sync folders can all retain earlier copies that `shred`
cannot reach. Shredding a file also cannot destroy copies an attacker
already made. For stronger guarantees, use full-disk encryption before data
is written, or destroy the medium.

## Self-test and installation checks

`selftest` runs the X-Wing draft vectors and sealed-file round trips compiled
into the binary:

```sh
sindook selftest
```

It reports pass or fail per check and exits non-zero on any failure. Passing
it shows the shipped build agrees with the published vectors; it is not a
security audit and not a substitute for `go test ./...` before a release.

`doctor` checks the health of the installation: the running binary, the
configuration directory, and the platform properties the commands rely on:

```sh
sindook doctor
sindook doctor -check-version   # also compare against the latest release
sindook doctor -json            # machine-readable output
```

Run both after a fresh install or before filing a bug report.

## Streams and safe output handling

```sh
tar cz project | sindook seal -r personal.key.pub -o project.tgz.sindook
sindook open -i personal.key -o - project.tgz.sindook | tar xz
```

PowerShell treats pipelines as objects and can change binary data. Use an
explicit `-o` path for binary streams there, or use `-a` when the output is
intentionally ASCII armored text.

By default, Sindook refuses to overwrite a destination. Use `-f` only when replacement is intentional. With `-f`, it stages output beside the destination and replaces it only after a successful write; symbolic links and non-regular destinations are refused. On POSIX systems, new sealed and plaintext output files are mode `0600`; public key files are mode `0644`. On Windows, Sindook does not set an owner-only ACL. Access follows Windows and the destination directory's ACL.

Same-directory rename behavior is platform-dependent. Keep backups of important files and use `verify` after a storage migration or rewrap.

## Scripting and exit codes

For non-interactive use, `-passfile` replaces a payload passphrase prompt and
`-identity-passfile` replaces a protected identity prompt; neither should
appear in a command line or environment. Commands exit with a machine-checkable
status:

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | operational failure (I/O error, malformed input, validation, or payload corruption) |
| `2` | usage error (unknown command, bad flag, missing operand, malformed credential on the command line) |
| `3` | authentication failure (wrong identity or passphrase, missing credential, or header tampering, `ErrWrongKey`, `ErrNeedIdentity`, `ErrNeedPassphrase`, `ErrHeaderTampered`); split from code `1` in v0.6.0 |

Before v0.6.0, authentication failures exited with `1`. Batch commands check every file even if an earlier one fails and exit non-zero if any did (joined usage+authentication errors prefer `2`). Treat exit codes and `-json` output as the stable scripting interface; human-readable text is not one.

## Troubleshooting

### `sindook doctor` reports a memory-lock warning

`sindook doctor` runs `memguard.LockAll()` and reports:

- `ok` on Linux/FreeBSD/Windows when pages were locked.
- `warning` on macOS and other platforms where `mlockall` has no pure-Go
  path (the process keeps running without locked memory; hardware
  full-disk encryption is the mitigation). Since v0.8.1 this is reported
  honestly as a warning instead of `ok`.
- `warning` on Linux/FreeBSD when `RLIMIT_MEMLOCK` is too low or privileges are insufficient. Remediation: `ulimit -l unlimited` (per-shell) or raise the limit in `/etc/security/limits.conf` or the systemd unit with `LimitMEMLOCK=infinity`.

### CI OOM: `cannot allocate 67108864-byte block`

On GitHub Actions `ubuntu-latest`, `RLIMIT_MEMLOCK` is ~8 MiB. Locking future mappings (`MCL_FUTURE`) would mark every new heap page `VM_LOCKED`, so the next 64 MiB Argon2id allocation (RFC 9106 parameters 64 MiB) hits the limit and the Go runtime aborts:

```
runtime: out of memory: cannot allocate 67108864-byte block (45088768 in use)
fatal error: out of memory
```

From v0.6.0, Sindook checks the limit first: if `RLIMIT_MEMLOCK` is below 96 MiB it uses only `MCL_CURRENT`, which locks the existing pages and avoids pinning every future allocation. This prevents the OOM while still protecting the current working set. No action is needed for normal CI runs; if you raise the limit intentionally, the full `MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT` chain is tried again.

If you see the OOM in your own runners, raise the limit before testing:

```sh
ulimit -l unlimited   # or LimitMEMLOCK=infinity in systemd
go test -race ./...
```

Verify the fix with:

```sh
sindook doctor        # should show [ok] memory lock or a warning with remediation
sindook selftest      # 3 checks: x-wing vectors, round trip, tamper detection
```

If `doctor` still shows a warning and you cannot raise the limit, the process keeps running without locked memory; protect the host with full-disk encryption and restrict swap.

### Other diagnostics

- Run `sindook doctor -json` for machine-readable health, `sindook doctor -check-version` to compare against the latest GitHub release.
- Run `sindook selftest` after any unusual runtime failure; it exercises the exact X-Wing draft-10 vectors compiled into the binary.

## Get help

```sh
sindook help
sindook help seal
sindook completion zsh > "${fpath[1]}/_sindook"
```

PowerShell completion can be loaded for the current profile with:

```powershell
sindook completion powershell | Add-Content $PROFILE
```

For the security boundary, read the [threat model](THREAT_MODEL.md) and [security model](SECURITY.md).
