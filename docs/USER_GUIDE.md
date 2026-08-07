# User guide

Sindook encrypts a file to one or more X-Wing recipients, a passphrase, or both. A recipient needs its identity file to open the data. A passphrase slot is useful for recovery or a small personal archive.

## Install

Use a signed release binary when one is available, or install from source with Go 1.26 or newer:

```sh
go install github.com/ruddro-roy/sindook/cmd/sindook@latest
sindook version
```

Release archives include checksums, an SBOM, a Sigstore bundle for `checksums.txt`, and GitHub build provenance. See the verification commands in the [README](../README.md#install) before trusting a downloaded binary.

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

A recipient list accepts one `sindookpk1:` public key per line. Blank lines and `#` comments are ignored:

```sh
sindook seal -R team.keys plans.tar
```

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

## Streams and safe output handling

```sh
tar cz project | sindook seal -r personal.key.pub -o project.tgz.sindook
sindook open -i personal.key -o - project.tgz.sindook | tar xz
```

By default, Sindook refuses to overwrite a destination. Use `-f` only when replacement is intentional. With `-f`, it stages output beside the destination and replaces it only after a successful write; symbolic links and non-regular destinations are refused. On POSIX systems, new sealed and plaintext output files are mode `0600`; public key files are mode `0644`. On Windows, Sindook does not set an owner-only ACL. Access follows Windows and the destination directory's ACL.

Same-directory rename behavior is platform-dependent. Keep backups of important files and use `verify` after a storage migration or rewrap.

## Get help

```sh
sindook help
sindook help seal
sindook completion zsh > "${fpath[1]}/_sindook"
```

For the security boundary, read the [threat model](THREAT_MODEL.md) and [security model](SECURITY.md).