# nazar 🧿

[![test](https://github.com/umutciftci/nazar/actions/workflows/test.yml/badge.svg)](https://github.com/umutciftci/nazar/actions/workflows/test.yml)
[![lint](https://github.com/umutciftci/nazar/actions/workflows/lint.yml/badge.svg)](https://github.com/umutciftci/nazar/actions/workflows/lint.yml)
[![release](https://github.com/umutciftci/nazar/actions/workflows/release.yml/badge.svg)](https://github.com/umutciftci/nazar/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/umutciftci/nazar)](https://goreportcard.com/report/github.com/umutciftci/nazar)
[![Go Version](https://img.shields.io/github/go-mod/go-version/umutciftci/nazar)](https://github.com/umutciftci/nazar/blob/master/go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/umutciftci/nazar/badge)](https://securityscorecards.dev/viewer/?uri=github.com/umutciftci/nazar)

> The evil eye that watches over your dependencies.

**nazar** is a multi-project, zero-config, local-first vulnerability scanner. One command — every project on your machine, every ecosystem, one consolidated report.

```bash
nazar scan ~/Projects ~/Desktop ~/Work
```

## Why nazar?

Tools like Trivy, Snyk CLI and `osv-scanner` scan **one project at a time**. Most developers have dozens of projects — old prototypes, side projects, archived clones — each with its own dependency tree quietly rotting.

nazar walks your filesystem, finds every project across multiple ecosystems, and reports known vulnerabilities — with severity, fix hints, and cross-project hotspots — in a single table. No account, no telemetry, no SaaS.

## Install

### Homebrew (macOS / Linux) — recommended

One command (tap is resolved automatically):

```bash
brew install umutciftci/nazar/nazar
```

After the first install, you can add the tap once and use shorter commands next time:

```bash
brew tap umutciftci/nazar
brew install nazar    # first time via tap
brew upgrade nazar    # later updates
```

The tap repo [`homebrew-nazar`](https://github.com/umutciftci/homebrew-nazar) is updated automatically on each release (`Formula/nazar.rb`).

### Scoop (Windows) — recommended on Windows

```powershell
scoop bucket add nazar https://github.com/umutciftci/scoop-nazar
scoop install nazar
scoop update nazar
```

The bucket repo [`scoop-nazar`](https://github.com/umutciftci/scoop-nazar) is updated automatically on each release.

On Windows you can also use [GitHub Releases](https://github.com/umutciftci/nazar/releases) or `go install` below.

### Go install

```bash
go install github.com/umutciftci/nazar/cmd/nazar@latest
```

Requires Go 1.24+ (see [`go.mod`](go.mod)).

### Docker

```bash
docker run --rm -v "$PWD:/scan" ghcr.io/umutciftci/nazar:latest scan /scan
```

### Pre-built binaries

Download the archive for your platform from [GitHub Releases](https://github.com/umutciftci/nazar/releases), extract, and put `nazar` on your `PATH`.

### Build from source

```bash
git clone https://github.com/umutciftci/nazar.git
cd nazar
go build -o nazar ./cmd/nazar
sudo mv nazar /usr/local/bin/nazar   # optional
```

## How does nazar compare?

| | **nazar** | Trivy | Snyk CLI | osv-scanner |
|---|:---:|:---:|:---:|:---:|
| Multi-project filesystem walk | yes | manual | manual | manual |
| Zero-config (no account) | yes | partial | no | yes |
| Local-first / no telemetry | yes | partial | no | yes |
| Ecosystems in one report | 7+ | many | many | many |
| CI exit codes (`--fail-on`) | yes | yes | yes | yes |
| Interactive `fix` with rollback | yes | no | yes | no |
| Cross-project hotspot view | yes | no | no | no |

nazar is not a replacement for container/image scanners — it focuses on **dependency lockfiles across many projects on disk**.

## Commands

| Command | What it does |
|---------|-------------|
| `nazar scan <path...>` | Scan one or more directories, report all vulnerabilities |
| `nazar ci [path]` | CI-mode scan — exits 2 on HIGH+ vulns by default |
| `nazar fix <path>` | Interactively upgrade vulnerable packages |
| `nazar diff <path>` | Show what changed since the last scan |
| `nazar watch <path>` | Continuously re-scan and alert on new vulns |
| `nazar show <vuln-id>` | Fetch and display full details for a single CVE/GHSA |
| `nazar ignore` | Manage `.nazarignore` suppression rules |
| `nazar cache` | Inspect and manage the local OSV cache |
| `nazar config` | View and edit the nazar config file |

---

## nazar scan

```
nazar scan <path> [path...] [flags]
```

### Default output — summary table

```
$ nazar scan ~/Desktop
 → scanning filesystem…
 → querying OSV.dev (6637 unique packages)…
 → fetching severity + fix info (487 CVEs, 320 cached)…

nazar 🧿 — scan results
scanned: /Users/you/Desktop

PROJECT                         ECOSYSTEM   PACKAGES  DIRECT  CRIT  HIGH  MED  LOW  ?   FIXABLE
────────────────────────────────────────────────────────────────────────────────────────────────
my-api                          npm         690       627     1     26    15   10   0   18
my-api/backend                  PyPI        12        12      0     1     0    0    0   1
side-project/frontend           npm         144       144     0     9     14   1    0   8
old-prototype                   npm         25        24      0     0     0    0    0   0

4 project(s), 871 total packages (807 direct), 77 vulnerabilities (1 crit / 27 high / 29 med / 11 low).
27 package(s) have a known fix — run `nazar fix` to upgrade.

Cross-project hotspots (vulnerable in 2+ projects):

  [CRITICAL]  form-data@4.0.2  →4.0.3    3 projects  GHSA-fjxv-7rqg-78g4
  [HIGH]      lodash@4.17.21             2 projects  GHSA-f23m-r3pf-42rh, GHSA-r5fr-rjxr-66jc

(use --detail to see vulnerable packages, --project <name> for a single project)
```

### Output formats

```bash
nazar scan .                            # colored terminal table (default)
nazar scan . --json                     # machine-readable JSON
nazar scan . --csv > vulns.csv          # CSV: one row per (package, vuln)
nazar scan . --sarif > nazar.sarif      # SARIF 2.1.0 for GitHub/GitLab
nazar scan . --markdown                 # GitHub-flavoured Markdown
nazar scan . --html -o report.html      # self-contained HTML report
```

All formats support `--output-file` / `-o` to write to a file instead of stdout:

```bash
nazar scan . --markdown -o summary.md
nazar scan . --html -o nazar-report.html
```

### Filtering & display

```bash
# Show only vulnerable projects (hide clean ones)
nazar scan . --vuln-only

# Sort table by worst severity / critical count / fixable count
nazar scan . --sort worst
nazar scan . --sort crit
nazar scan . --sort fixable

# Show only top 10 worst projects
nazar scan . --top 10

# Group rows by ecosystem
nazar scan . --group-by-ecosystem

# Filter to a single ecosystem
nazar scan . --ecosystem npm
nazar scan . --ecosystem rubygems

# Only show vulns published in the last 30 days
nazar scan . --since 30d

# Show only NEW vulns vs the previous scan
nazar scan . --new

# Summary only — no table or detail (useful in scripts)
nazar scan . --quiet
```

### Drill into a project

```bash
nazar scan ~/Desktop --detail                          # full vuln list for all projects
nazar scan ~/Desktop --project my-api                  # one project (substring match)
nazar scan ~/Desktop --severity critical               # critical only in detail
nazar scan ~/Desktop --detail --project api --severity high
```

### Multi-path scanning

```bash
nazar scan ~/Projects ~/Desktop ~/Work
```

All paths are merged into a single report. The display root is their common ancestor. Each path is walked independently so overlapping roots are deduplicated.

### Performance flags

```bash
--offline          # skip OSV entirely — just enumerate projects
--no-severity      # skip per-vuln detail fetch (faster, no fix hints)
--no-cache         # force fresh OSV lookups (results are still cached)
2>/dev/null        # silence progress lines when piping stdout
```

### CI — fail on severity

```bash
nazar scan . --fail-on high      # exit 2 on HIGH or CRITICAL
nazar scan . --fail-on critical  # only CRITICAL triggers exit 2
```

Exit codes: `0` = clean, `1` = scan/parse error, `2` = vulns found.

### Webhook notification

```bash
nazar scan . --webhook https://hooks.slack.com/services/...
```

Posts a Slack-compatible JSON payload after the scan completes. The body contains a `text` key (human summary) plus a `nazar` block with structured data (project count, severity breakdown, status). Failure is a warning; it never aborts the scan.

---

## nazar ci

CI-mode wrapper around `nazar scan` with production-safe defaults:

```bash
nazar ci .                   # scan CWD, exit 2 on HIGH+, quiet output
nazar ci . --fail-on critical
nazar ci . --sarif -o nazar.sarif
nazar ci . --json > results.json
```

**Defaults vs `nazar scan`:**
- `--fail-on high` (threshold is HIGH not off)
- `--quiet` (only the summary line unless a machine format is chosen)

### GitHub Actions example

```yaml
- name: nazar vulnerability scan
  run: |
    nazar ci . --sarif -o nazar.sarif
    nazar ci . --markdown >> $GITHUB_STEP_SUMMARY

- name: Upload SARIF to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nazar.sarif
  if: always()
```

---

## nazar fix

Interactively upgrade vulnerable packages with backup + rollback:

```bash
nazar fix ~/Projects            # interactive selection
nazar fix ~/Projects --all      # fix everything without prompting
nazar fix ~/Projects --auto     # CI mode: --all + --safe-only (no major bumps)
nazar fix ~/Projects --dry-run  # show what would be fixed, make no changes
```

Flags:

```
--auto           CI shortcut: --all + --safe-only (no major version bumps)
--all            fix all without prompting
--dry-run        show fixes, make no changes
--safe-only      skip any fix that requires a major version bump
--severity       only fix vulns at or above this level (critical|high|medium|low)
--project        only fix projects matching this substring
--ecosystem      only fix this ecosystem (npm|pypi|go|cargo|rubygems|packagist|nuget)
--run-tests      run this command after each fix; roll back if it fails
--rollback       undo the last fix session (restores backed-up lockfiles)
```

nazar backs up every modified lockfile to `~/.cache/nazar/fix-backups/` before touching it. If something goes wrong:

```bash
nazar fix ~/Projects --rollback
```

---

## nazar diff

Show what changed since the last `nazar scan`:

```bash
nazar diff ~/Projects
```

```
nazar 🧿 — diff
now vs 2 days ago  (2026-05-21 09:14)

NEW  (3)
  [HIGH]      express@4.18.2        CVE-2024-43796 →4.19.2    my-api
  [MEDIUM]    body-parser@1.20.2    CVE-2024-45590 →1.20.3    my-api
  [LOW]       path-to-regexp@0.1.7  GHSA-9wv6-86v2            my-api

RESOLVED  (1)
  [MEDIUM]    semver@7.3.8          GHSA-c2qf-rxjj-qqgw        old-project

3 new  /  1 resolved  /  12 unchanged
```

`nazar scan` automatically saves a snapshot after every run. `nazar diff` loads the last snapshot and compares.

---

## nazar watch

Continuously re-scan on a schedule and alert when new vulns appear:

```bash
nazar watch ~/Projects                          # default: every 6 hours
nazar watch ~/Projects --interval 30m          # every 30 minutes
nazar watch ~/Projects --severity critical      # only alert on CRITICAL
nazar watch ~/Projects --notify                 # also send OS desktop notification
```

Only changes vs the previous scan are shown. First run establishes the baseline. Press Ctrl-C to stop.

---

## nazar show

Look up a single CVE or GHSA:

```bash
nazar show GHSA-fjxv-7rqg-78g4
nazar show CVE-2024-43796
```

---

## Suppressing accepted vulns

### `.nazarignore` file

Place at the scan root (or specify with `--ignore-file`):

```
# Ignore a vuln everywhere
GHSA-xxxx-xxxx-xxxx
CVE-2024-1234

# Exact package@version pair
lodash@4.17.20:GHSA-xxxx

# Any version of a package
lodash@*:CVE-2024-1234

# Scoped npm names work too
@scope/utils@1.2.3:CVE-2024-...
```

### Inline rules

```bash
nazar scan . --ignore GHSA-xxxx --ignore "lodash@*:CVE-2024-1234"
```

### Manage rules interactively

```bash
nazar ignore list
nazar ignore add GHSA-xxxx
nazar ignore remove GHSA-xxxx
```

---

## Supported ecosystems

| Ecosystem | Lockfile(s) | OSV identifier |
|-----------|------------|----------------|
| **npm** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `npm` |
| **PyPI** | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt` | `PyPI` |
| **Go** | `go.mod` + `go.sum` | `Go` |
| **Rust** | `Cargo.toml` + `Cargo.lock` | `crates.io` |
| **Ruby** | `Gemfile` + `Gemfile.lock` | `RubyGems` |
| **PHP** | `composer.json` + `composer.lock` | `Packagist` |
| **.NET** | `packages.lock.json` | `NuGet` |

Notes:
- yarn.lock: classic (v1) and Berry (v2+) supported
- pnpm-lock.yaml: v6 and v9 supported
- A directory with multiple ecosystems produces one row per ecosystem
- Composer versions with a leading `v` (e.g. `v6.4.0`) are normalized automatically

### Skipped directories

```
node_modules  .git  vendor  target  dist  build  .next  __pycache__  .venv  venv  testdata  fixtures
```

Add more with `--exclude`:

```bash
nazar scan . --exclude testdata --exclude fixtures
```

---

## Caching

OSV results are cached at `~/.cache/nazar/` (Linux) or `~/Library/Caches/nazar/` (macOS):

| Layer | TTL | Key |
|-------|-----|-----|
| Coordinate batch | 24 h | `(ecosystem, package, version)` |
| Vuln detail (severity, fix) | 7 d | vuln ID |

```bash
nazar cache stats          # show entry counts, sizes, staleness
nazar cache path           # print cache directory
nazar cache prune          # remove only expired entries
nazar cache clear          # delete everything
nazar cache clear --what coords   # coords only
```

---

## Configuration

```bash
nazar config show            # print current config
nazar config set sort worst  # set default sort order
nazar config edit            # open in $EDITOR
nazar config path            # print config file location
```

Config is stored at `~/.config/nazar/config.json`. CLI flags always override config values.

---

## Philosophy

- **Read-only by default.** `nazar scan` and `nazar diff` never touch any file in your projects.
- **No silent auto-patching.** `nazar fix --auto` is opt-in and limited to safe upgrades (no major bumps).
- **Local-first.** No telemetry. No accounts. The only network call is to [OSV.dev](https://osv.dev)'s public API; use `--offline` to skip even that.

---

## Development

```bash
go test -race ./...
go vet ./...
golangci-lint run    # optional locally; required in CI
go build -o nazar ./cmd/nazar
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide, project layout, and how to add a new ecosystem.

### CI integration examples

Ready-to-copy workflows live under [`examples/`](examples/):

- [GitHub Actions](examples/github-actions/nazar-ci.yml)
- [GitLab CI](examples/gitlab-ci/.gitlab-ci.yml)
- [pre-commit](examples/pre-commit/.pre-commit-hooks.yaml)

## Contributing

We welcome bug reports, parsers for new ecosystems, docs, and tests. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening a PR.

Good starting points: issues labeled [`good first issue`](https://github.com/umutciftci/nazar/labels/good%20first%20issue) or [`help wanted`](https://github.com/umutciftci/nazar/labels/help%20wanted).

**Security:** do not open public issues for vulnerabilities in nazar — see [SECURITY.md](SECURITY.md).

## Verifying releases

Official release binaries are built by GitHub Actions. Checksums are in `checksums.txt` on each [release](https://github.com/umutciftci/nazar/releases). When cosign signatures are published:

```bash
# Download checksums.txt, checksums.txt.sig, and checksums.txt.pem from the release page, then:
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/umutciftci/nazar/.github/workflows/release.yml@refs/tags/v*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

SBOM files (`*.spdx.json`) are attached to each release archive for supply-chain auditing.

## License

MIT — see [LICENSE](LICENSE).
