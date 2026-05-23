# Dogfood triage (2026-05-23)

Local build: `go build -o nazar ./cmd/nazar` (Go 1.26 via Homebrew).

Desktop scan: 107 projects, ~20s, 268 vulns — performance acceptable.

## Fixed in this pass

| Priority | Issue | Fix |
|----------|-------|-----|
| P1 | `internal/parser/testdata` detected as PyPI project; `nazar ci .` reported fixture CVEs | Skip `testdata` and `fixtures` in [`internal/scanner/scanner.go`](../internal/scanner/scanner.go) |
| P1 | `--quiet` / `nazar ci` still printed banner + progress lines | Quiet path in [`internal/report/table.go`](../internal/report/table.go); suppress progress in [`cmd/nazar/scan.go`](../cmd/nazar/scan.go) |
| P2 | `nazar show NONSENSE-1234` showed empty record | Error when OSV returns empty stub in [`cmd/nazar/show.go`](../cmd/nazar/show.go) |
| P2 | `--fail-on` message: "1 vulnerability/vulnerabilities" | Proper plural in `errVulnsFound.Error()` |
| P2 | `history.Compare` loop (gosimple) | Single `append` spread |

## Backlog (not fixed)

| Priority | Issue | Notes |
|----------|-------|-------|
| P2 | Progress counter on non-quiet large scans (`1/107` on stderr) | Acceptable; could throttle updates |
| P2 | `nazar show` with empty summary but withdrawn IDs may still need richer copy | Edge case |
| P2 | Re-enable strict golangci (`gofmt`, `goimports`, `revive`) after local `gofmt -w` | `.golangci.yml` relaxed temporarily |
| P3 | Homebrew tap repo empty on first clone | Release must publish `Formula/nazar.rb` |
| P3 | SARIF `%SRCROOT%` URI base for Code Scanning | Verify in real GitHub workflow |

## Verification commands

```bash
go test -race ./...
./nazar ci .                    # one summary line, exit 0 on this repo
./nazar show NONSENSE-1234      # error exit 1
./nazar scan . --quiet          # 1 Go project (testdata skipped)
```
