# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Community files: CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue/PR templates
- CI: multi-OS test matrix, golangci-lint, CodeQL, OpenSSF Scorecard, Dependabot
- Release pipeline: SBOM, cosign signatures, Docker image (GHCR), Homebrew tap + Scoop bucket, deb/rpm packages
- Integration examples under `examples/`

## [0.1.0] - 2026-05-23

### Added

- `nazar scan` — multi-project filesystem walk with consolidated vulnerability report
- `nazar ci` — CI-mode scan with `--fail-on high` default
- `nazar fix` — interactive package upgrades with backup and rollback
- `nazar diff` — compare current scan against last snapshot
- `nazar watch` — scheduled re-scan with new-vuln alerts
- `nazar show` — look up a single CVE/GHSA
- `nazar ignore` — manage `.nazarignore` suppression rules
- `nazar cache` — inspect and manage the local OSV cache
- `nazar config` — view and edit user config
- Ecosystem support: npm, PyPI, Go, Rust, Ruby, PHP, .NET
- Output formats: terminal table, JSON, CSV, SARIF 2.1.0, Markdown, HTML
- OSV.dev integration with on-disk cache
- Cross-project hotspot detection
- Webhook notifications (Slack-compatible)

[Unreleased]: https://github.com/umutciftci/nazar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/umutciftci/nazar/releases/tag/v0.1.0
