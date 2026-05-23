# Contributing to nazar

Thanks for your interest in making nazar better! This document covers everything you need to know to land a change.

If you are looking for something to work on, the [`good first issue`](https://github.com/umutciftci/nazar/labels/good%20first%20issue) and [`help wanted`](https://github.com/umutciftci/nazar/labels/help%20wanted) labels are the best place to start.

## Table of contents

- [Code of Conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Project layout](#project-layout)
- [Adding a new ecosystem](#adding-a-new-ecosystem)
- [Running tests and lint](#running-tests-and-lint)
- [Commit messages](#commit-messages)
- [Submitting a pull request](#submitting-a-pull-request)
- [Reporting bugs and requesting features](#reporting-bugs-and-requesting-features)
- [Security reports](#security-reports)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold it.

## Ways to contribute

- **Add support for a new ecosystem** (see [Adding a new ecosystem](#adding-a-new-ecosystem)).
- **Improve an existing parser** — better edge-case handling, performance, fixtures.
- **Add or improve a report format** (`internal/report/`).
- **Improve docs** — examples, integration guides, fixes to the README.
- **Triage issues** — reproduce bug reports, suggest labels, point to related issues.

## Development setup

Requirements:

- Go (the version pinned in [`go.mod`](go.mod), currently `1.24.1`)
- `git`
- Optional but recommended: [`golangci-lint`](https://golangci-lint.run/welcome/install/) for local linting

```bash
git clone https://github.com/umutciftci/nazar.git
cd nazar

# Build the binary
go build -o nazar ./cmd/nazar

# Smoke test
./nazar --version
./nazar scan .
```

`go build` is enough for day-to-day work. There are no code generation steps.

## Project layout

```
cmd/nazar/      CLI commands (cobra). One file per top-level command.
internal/
  scanner/      Filesystem walker that detects projects across ecosystems
  parser/       Per-ecosystem lockfile parsers (npm, pypi, go, rust, ...)
  osv/          OSV.dev API client + on-disk cache
  report/       Output renderers (table, json, csv, sarif, markdown, html)
  fixer/        Interactive upgrade + rollback
  ignore/       .nazarignore / --ignore rule engine
  history/      Snapshot store used by `nazar diff` / `nazar watch`
  config/       Config file loader (~/.config/nazar/config.json)
```

## Adding a new ecosystem

This is the most common contribution. A new ecosystem typically needs:

1. **A parser** in `internal/parser/<ecosystem>.go` + a `_test.go` next to it with at least one realistic fixture lockfile.
2. **A detector** in [`internal/scanner/scanner.go`](internal/scanner/scanner.go) — add a `detect<Ecosystem>Project` function and call it from `ScanWithOptions`.
3. **An `Ecosystem` constant** in the same file plus the matching OSV identifier string (see [OSV ecosystems](https://ossf.github.io/osv-schema/#defined-ecosystems)).
4. **A row in the README** "Supported ecosystems" table.
5. **A fixer adapter** in `internal/fixer/` *only if* the package manager supports automated upgrades non-interactively. Otherwise leave `nazar fix` as a TODO and note it in the PR.

Take a look at [`internal/parser/golang.go`](internal/parser/golang.go) + [`internal/parser/golang_test.go`](internal/parser/golang_test.go) for a small, self-contained example to copy.

## Running tests and lint

```bash
# Unit tests with the race detector
go test -race ./...

# Vet
go vet ./...

# Lint (matches the CI configuration in .golangci.yml)
golangci-lint run

# Coverage report
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

CI runs these on Linux, macOS and Windows for every PR — please make sure they pass locally first.

### Updating golden output

A handful of report tests use golden files under `internal/report/testdata/`. Regenerate with:

```bash
go test ./internal/report/... -update
```

Review the diff carefully before committing.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/) so that release notes can be generated automatically:

```
feat:     a new user-visible feature
fix:      a bug fix
docs:     documentation only
refactor: code change with no behavior change
test:     adding or fixing tests
chore:    tooling, deps, CI
perf:     performance improvement
```

Examples:

```
feat(parser): add Maven (pom.xml) support
fix(osv): retry batch query on transient 5xx
docs(readme): document docker install
```

Keep commits focused. If you have unrelated changes, split them into separate PRs.

## Submitting a pull request

1. Fork the repo and create a feature branch off `master`.
2. Make your changes (with tests).
3. Run `go test -race ./...`, `go vet ./...`, `golangci-lint run`.
4. Update [`README.md`](README.md) if you added a user-visible flag, command, ecosystem or output format.
5. Add an entry under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md).
6. Push and open a PR. The PR template will guide you through the checklist.
7. A maintainer will review. Small, focused PRs get merged faster.

CI will run the test matrix (Linux/macOS/Windows), lint, and the dogfood scan (`nazar ci .`). All three must be green before merge.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/umutciftci/nazar/issues/new/choose):

- **Bug report** — please include `nazar --version`, your OS, the exact command, and a minimal lockfile that reproduces.
- **Feature request** — describe the problem first, the solution second.
- **Ecosystem support** — has a dedicated form because it is the most common request.

## Security reports

**Do not** open a public issue for security vulnerabilities in nazar itself. See [SECURITY.md](SECURITY.md) for the private reporting process.

---

Thanks again — every fixture, parser, doc fix and triage comment makes nazar better for the next person who runs it.
