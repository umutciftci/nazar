# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| latest release | yes |
| `main` branch | yes (best-effort) |
| older releases | no |

## Reporting a vulnerability in nazar

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of these channels:

1. **GitHub Security Advisories** (preferred): open a [private vulnerability report](https://github.com/umutciftci/nazar/security/advisories/new) on this repository.
2. **Email**: contact the maintainer at **umutciftci@users.noreply.github.com** with the subject `nazar security`.

Include as much detail as you can:

- Affected version (`nazar --version` output)
- Steps to reproduce
- Impact assessment (what an attacker could achieve)
- Proof of concept if available

## What to expect

- **Acknowledgement** within 72 hours.
- **Status update** within 7 days with a rough timeline.
- **Coordinated disclosure** — we will agree on a release date before publishing details.
- **Credit** in the release notes / advisory (unless you prefer to stay anonymous).

## Scope

In scope:

- Remote code execution, path traversal, or privilege escalation bugs in nazar itself.
- Issues where crafted lockfiles or config files cause unsafe behavior beyond normal filesystem reads.
- Credential leakage from nazar's cache, config, or webhook integrations.

Out of scope:

- Vulnerabilities **found by nazar** in your third-party dependencies — report those to the upstream package maintainers or OSV.
- Social engineering, denial of service against OSV.dev, or issues in dependencies that do not affect nazar's threat model.
- Reports from automated scanners with no demonstrated impact on nazar.

## Secure usage notes

nazar is designed to be **read-only by default** (`nazar scan`, `nazar diff`, `nazar ci`). The only command that modifies project files is `nazar fix`, which backs up lockfiles before changing them.

- Run `nazar fix` only on directories you trust.
- Review `.nazarignore` rules before committing them — overly broad ignores can hide real issues.
- When using `--webhook`, treat the URL as a secret (it can leak scan summaries).

## Verifying release artifacts

Official releases are built by GitHub Actions and signed with [cosign](https://docs.sigstore.dev/). See the **Verifying releases** section in [README.md](README.md) for instructions.
