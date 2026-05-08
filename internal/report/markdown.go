package report

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// RenderMarkdown writes a GitHub-flavoured Markdown report to w.
//
// The output is suitable for a GitHub PR description, issue comment, or
// GitHub Actions job summary (append to $GITHUB_STEP_SUMMARY).
func RenderMarkdown(w io.Writer, root string, offline bool, results []Result, opts RenderOptions) {
	fmt.Fprintln(w, "# nazar 🧿 — scan results")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Scanned:** `%s`\n", root)
	if offline {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "> ⚠️ **Offline mode** — OSV lookup skipped.")
	}
	fmt.Fprintln(w)

	if len(results) == 0 {
		fmt.Fprintln(w, "*No projects detected.*")
		return
	}

	// ── Build row data (mirrors RenderText) ───────────────────────────────────

	type mdRow struct {
		path      string
		ecosystem string
		total     int
		direct    int
		fixable   int
		sc        severityCounts
	}

	rows := make([]mdRow, 0, len(results))
	for _, r := range results {
		rel, err := filepath.Rel(root, r.Project.Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			rel = r.Project.Path
		}
		if rel == "." {
			rel = "(root)"
		}
		direct, fixable := 0, 0
		for _, p := range r.Packages {
			if p.Package.Direct {
				direct++
			}
			for _, v := range p.Vulns {
				if v.FixedIn != "" {
					fixable++
					break
				}
			}
		}
		rows = append(rows, mdRow{
			path:      rel,
			ecosystem: string(r.Project.Ecosystem),
			total:     len(r.Packages),
			direct:    direct,
			fixable:   fixable,
			sc:        tally(r.Packages),
		})
	}

	// Sort rows (same buckets as RenderText).
	mdSevRank := func(sc severityCounts) int {
		switch {
		case sc.Critical > 0:
			return 5
		case sc.High > 0:
			return 4
		case sc.Medium > 0:
			return 3
		case sc.Low > 0:
			return 2
		case sc.Unknown > 0:
			return 1
		default:
			return 0
		}
	}
	switch opts.SortBy {
	case "worst":
		sort.SliceStable(rows, func(i, j int) bool {
			ri, rj := mdSevRank(rows[i].sc), mdSevRank(rows[j].sc)
			if ri != rj {
				return ri > rj
			}
			return rows[i].path < rows[j].path
		})
	case "crit":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].sc.Critical != rows[j].sc.Critical {
				return rows[i].sc.Critical > rows[j].sc.Critical
			}
			return rows[i].path < rows[j].path
		})
	case "high":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].sc.High != rows[j].sc.High {
				return rows[i].sc.High > rows[j].sc.High
			}
			return rows[i].path < rows[j].path
		})
	case "total":
		sort.SliceStable(rows, func(i, j int) bool {
			ti, tj := rows[i].sc.Total(), rows[j].sc.Total()
			if ti != tj {
				return ti > tj
			}
			return rows[i].path < rows[j].path
		})
	case "fixable":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].fixable != rows[j].fixable {
				return rows[i].fixable > rows[j].fixable
			}
			return rows[i].path < rows[j].path
		})
	default: // "path" or empty
		sort.SliceStable(rows, func(i, j int) bool {
			return rows[i].path < rows[j].path
		})
	}

	// Totals across ALL rows (before any display-only filters).
	var totals severityCounts
	var totalPkgs, totalDirect, totalFixable int
	for _, rw := range rows {
		totalPkgs += rw.total
		totalDirect += rw.direct
		totalFixable += rw.fixable
		totals.Critical += rw.sc.Critical
		totals.High += rw.sc.High
		totals.Medium += rw.sc.Medium
		totals.Low += rw.sc.Low
		totals.Unknown += rw.sc.Unknown
	}
	allRows := rows

	if opts.VulnOnly && !offline {
		var filtered []mdRow
		for _, rw := range rows {
			if rw.sc.Total() > 0 {
				filtered = append(filtered, rw)
			}
		}
		rows = filtered
	}
	if opts.TopN > 0 && opts.TopN < len(rows) {
		rows = rows[:opts.TopN]
	}

	// ── Summary table ──────────────────────────────────────────────────────────

	fmt.Fprintln(w, "| PROJECT | ECOSYSTEM | PKG | DIRECT | CRIT | HIGH | MED | LOW | ? | FIXABLE |")
	fmt.Fprintln(w, "|:--------|:----------|----:|-------:|-----:|-----:|----:|----:|--:|--------:|")

	for _, rw := range rows {
		crit, high, med, low, unk, fix := "—", "—", "—", "—", "—", "—"
		if !offline {
			crit = fmt.Sprintf("%d", rw.sc.Critical)
			high = fmt.Sprintf("%d", rw.sc.High)
			med = fmt.Sprintf("%d", rw.sc.Medium)
			low = fmt.Sprintf("%d", rw.sc.Low)
			unk = fmt.Sprintf("%d", rw.sc.Unknown)
			fix = fmt.Sprintf("%d", rw.fixable)
		}
		fmt.Fprintf(w, "| `%s` | %s | %d | %d | %s | %s | %s | %s | %s | %s |\n",
			mdEscape(rw.path), rw.ecosystem, rw.total, rw.direct,
			crit, high, med, low, unk, fix,
		)
	}

	if opts.TopN > 0 && len(allRows) > opts.TopN {
		fmt.Fprintf(w, "\n*… and %d more project(s) (remove `--top` to see all).*\n", len(allRows)-opts.TopN)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "*%s*\n", summaryLine(len(allRows), totalPkgs, totalDirect, totalFixable, totals, offline))

	// Ignored-rule footnote.
	ignoredTotal := 0
	for _, r := range results {
		ignoredTotal += r.IgnoredCount
	}
	if ignoredTotal > 0 {
		fmt.Fprintf(w, "\n*(%d vulnerability match(es) suppressed by ignore rules)*\n", ignoredTotal)
	}

	// ── Vulnerable packages detail ─────────────────────────────────────────────

	if offline || totals.Total() == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "### Vulnerable packages")

	for _, r := range results {
		rel, err := filepath.Rel(root, r.Project.Path)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			rel = r.Project.Path
		}

		var hits []PackageVulns
		for _, p := range r.Packages {
			vulns := filterBySeverity(p.Vulns, opts.MinSeverity)
			if len(vulns) > 0 {
				hits = append(hits, PackageVulns{Package: p.Package, Vulns: vulns})
			}
		}
		if len(hits) == 0 {
			continue
		}

		sort.Slice(hits, func(i, j int) bool {
			wi := worstSeverity(hits[i].Vulns)
			wj := worstSeverity(hits[j].Vulns)
			if wi != wj {
				return wi.Rank() > wj.Rank()
			}
			return hits[i].Package.Name < hits[j].Package.Name
		})

		fmt.Fprintf(w, "\n#### `%s`\n\n", mdEscape(rel))
		fmt.Fprintln(w, "| Severity | Package | Version | Fix | CVEs |")
		fmt.Fprintln(w, "|:---------|:--------|:--------|:----|:-----|")

		for _, h := range hits {
			worst := worstSeverity(h.Vulns)
			fixIn := "—"
			ids := make([]string, 0, len(h.Vulns))
			for _, v := range h.Vulns {
				ids = append(ids, "`"+v.ID+"`")
				if fixIn == "—" && v.FixedIn != "" {
					fixIn = "`" + mdEscape(v.FixedIn) + "`"
				}
			}
			fmt.Fprintf(w, "| **%s** | `%s` | `%s` | %s | %s |\n",
				string(worst),
				mdEscape(h.Package.Name),
				mdEscape(h.Package.Version),
				fixIn,
				strings.Join(ids, " "),
			)
			// First vuln summary as a blockquote.
			if h.Vulns[0].Summary != "" {
				summary := h.Vulns[0].Summary
				if len(summary) > 120 {
					summary = summary[:117] + "…"
				}
				fmt.Fprintf(w, "\n> %s\n\n", summary)
			}
		}
	}
}

// mdEscape escapes pipe and backtick characters that would break a Markdown
// table cell.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "'")
	return s
}
