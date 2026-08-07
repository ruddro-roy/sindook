# Security policy

Sindook is a young cryptographic file-encryption project. It has not received an independent security audit. Do not report suspected vulnerabilities in a public issue.

## Supported versions

Security fixes are made against the latest released version and the current `main` branch. The project is pre-1.0, so users should keep their installation current and verify backups after upgrading.

## Reporting a vulnerability

Send a short report to roy@ruddro.com with:

- the affected Sindook version and operating system;
- a clear description of the security impact;
- reproducible steps using synthetic data where possible;
- any proposed mitigation.

Do not include private keys, passphrases, real plaintext, or unreleased exploit details in a public issue. If encrypted transfer is needed, ask for a secure channel in the initial report. Reports are handled privately and response times are best effort.

Please allow time to investigate and coordinate a fix before public disclosure. The project will credit reporters who want attribution after a fix is available.

For intended guarantees, operational limits, and threat-model boundaries, read [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).