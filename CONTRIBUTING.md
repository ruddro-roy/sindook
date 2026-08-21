# Contributing to Sindook

Thank you for improving Sindook. This project handles encryption keys and hostile input, so small changes can have security consequences.

## Before opening a pull request

1. Open an issue first for a format, cryptographic, compatibility, or command-line behavior change.
2. Keep each change focused and include tests for changed behavior.
3. Do not put real keys, passphrases, customer data, or decrypted fixtures in an issue, commit, or pull request.
4. Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Local checks

Sindook requires Go 1.26 or newer.

```sh
gofmt -w $(git ls-files '*.go')
go vet ./...
go test ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
(cd interop && go vet ./... && go test ./...)
```

The CI workflow also runs short fuzz smoke tests. To run one locally:

```sh
go test ./box -run='^$' -fuzz='^FuzzOpenRecipient$' -fuzztime=30s
```

## Security-sensitive changes

Do not change the file format, X-Wing construction, KDF defaults, chunk framing, or compatibility guarantees without all of the following:

- a clear design rationale;
- tests that fail before the change and pass after it;
- updated format and security documentation;
- compatibility fixtures or a documented migration path;
- independent review where the change affects cryptographic assumptions.

The `xwing` package tracks an Internet-Draft. Any update to its draft version needs refreshed vectors and interoperability checks against the independent implementations used by `interop`.

## Pull requests

Use a concise title that explains the user-visible change. State the checks you ran and any limitation that remains. By contributing, you agree that your contribution is licensed under the repository's Apache-2.0 license.