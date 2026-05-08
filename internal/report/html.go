package report

import (
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/umutciftci/nazar/internal/osv"
)

// htmlRow is the per-project data fed into the HTML template.
type htmlRow struct {
	Path      string
	Ecosystem string
	Packages  int
	Critical  int
	High      int
	Medium    int
	Low       int
	Fixable   int
	Worst     osv.Severity
	Detail    []htmlPkgDetail
}

// htmlPkgDetail is the per-package detail used in the expandable section.
type htmlPkgDetail struct {
	Name    string
	Version string
	Direct  bool
	Vulns   []htmlVuln
	Worst   osv.Severity
}

// htmlVuln is a single vulnerability entry in the detail section.
type htmlVuln struct {
	ID       string
	Severity osv.Severity
	Summary  string
	FixedIn  string
}

// htmlData is the root context passed to the HTML template.
type htmlData struct {
	Root         string
	Offline      bool
	ScannedAt    string
	SummaryLine  string
	TotalProj    int
	TotalPkgs    int
	TotalFixable int
	Totals       severityCounts
	Rows         []htmlRow
}

// RenderHTML writes a self-contained HTML scan report to w.
func RenderHTML(w io.Writer, root string, offline bool, results []Result, opts RenderOptions) error {
	rows := buildHTMLRows(root, results, opts)

	var totals severityCounts
	var totalPkgs, totalDirect, totalFixable int
	for _, r := range results {
		sc := tally(r.Packages)
		totals.Critical += sc.Critical
		totals.High += sc.High
		totals.Medium += sc.Medium
		totals.Low += sc.Low
		totals.Unknown += sc.Unknown
		for _, p := range r.Packages {
			totalPkgs++
			if p.Package.Direct {
				totalDirect++
			}
			for _, v := range p.Vulns {
				if v.FixedIn != "" {
					totalFixable++
					break
				}
			}
		}
	}

	data := htmlData{
		Root:         root,
		Offline:      offline,
		ScannedAt:    time.Now().Format("2006-01-02 15:04:05 MST"),
		SummaryLine:  summaryLine(len(results), totalPkgs, totalDirect, totalFixable, totals, offline),
		TotalProj:    len(results),
		TotalPkgs:    totalPkgs,
		TotalFixable: totalFixable,
		Totals:       totals,
		Rows:         rows,
	}

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"sevColor":  htmlSevColor,
		"sevBadge":  htmlSevBadge,
		"rowColor":  htmlRowColor,
		"dimZero":   htmlDimZero,
		"iconCheck": func() string { return "✓" },
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("report: parse template: %w", err)
	}
	return tmpl.Execute(w, data)
}

// buildHTMLRows converts results into sorted, filtered htmlRow slices.
func buildHTMLRows(root string, results []Result, opts RenderOptions) []htmlRow {
	rows := make([]htmlRow, 0, len(results))

	for _, r := range results {
		rel, err := filepath.Rel(root, r.Project.Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			rel = r.Project.Path
		}
		if rel == "." {
			rel = "(root)"
		}

		sc := tally(r.Packages)

		fixable := 0
		for _, p := range r.Packages {
			for _, v := range p.Vulns {
				if v.FixedIn != "" {
					fixable++
					break
				}
			}
		}

		// Build per-package detail (filtered by MinSeverity).
		var details []htmlPkgDetail
		for _, pv := range r.Packages {
			vulns := filterBySeverity(pv.Vulns, opts.MinSeverity)
			if len(vulns) == 0 {
				continue
			}
			// Sort vulns by severity desc, then ID.
			sorted := make([]osv.Vuln, len(vulns))
			copy(sorted, vulns)
			sort.Slice(sorted, func(i, j int) bool {
				if sorted[i].Severity.Rank() != sorted[j].Severity.Rank() {
					return sorted[i].Severity.Rank() > sorted[j].Severity.Rank()
				}
				return sorted[i].ID < sorted[j].ID
			})

			hvulns := make([]htmlVuln, 0, len(sorted))
			for _, v := range sorted {
				sum := v.Summary
				if len(sum) > 120 {
					sum = sum[:117] + "..."
				}
				hvulns = append(hvulns, htmlVuln{
					ID:       v.ID,
					Severity: v.Severity,
					Summary:  sum,
					FixedIn:  v.FixedIn,
				})
			}

			details = append(details, htmlPkgDetail{
				Name:    pv.Package.Name,
				Version: pv.Package.Version,
				Direct:  pv.Package.Direct,
				Vulns:   hvulns,
				Worst:   worstSeverity(vulns),
			})
		}

		// Sort details by worst severity desc, then name.
		sort.Slice(details, func(i, j int) bool {
			if details[i].Worst.Rank() != details[j].Worst.Rank() {
				return details[i].Worst.Rank() > details[j].Worst.Rank()
			}
			return details[i].Name < details[j].Name
		})

		rows = append(rows, htmlRow{
			Path:      rel,
			Ecosystem: string(r.Project.Ecosystem),
			Packages:  len(r.Packages),
			Critical:  sc.Critical,
			High:      sc.High,
			Medium:    sc.Medium,
			Low:       sc.Low,
			Fixable:   fixable,
			Worst:     sc.Worst(),
			Detail:    details,
		})
	}

	// Sort.
	switch opts.SortBy {
	case "worst":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Worst.Rank() != rows[j].Worst.Rank() {
				return rows[i].Worst.Rank() > rows[j].Worst.Rank()
			}
			return rows[i].Path < rows[j].Path
		})
	case "crit":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Critical != rows[j].Critical {
				return rows[i].Critical > rows[j].Critical
			}
			return rows[i].Path < rows[j].Path
		})
	case "high":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].High != rows[j].High {
				return rows[i].High > rows[j].High
			}
			return rows[i].Path < rows[j].Path
		})
	case "total":
		sort.SliceStable(rows, func(i, j int) bool {
			ti := rows[i].Critical + rows[i].High + rows[i].Medium + rows[i].Low
			tj := rows[j].Critical + rows[j].High + rows[j].Medium + rows[j].Low
			if ti != tj {
				return ti > tj
			}
			return rows[i].Path < rows[j].Path
		})
	case "fixable":
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Fixable != rows[j].Fixable {
				return rows[i].Fixable > rows[j].Fixable
			}
			return rows[i].Path < rows[j].Path
		})
	default:
		sort.SliceStable(rows, func(i, j int) bool {
			return rows[i].Path < rows[j].Path
		})
	}

	// --vuln-only: hide clean projects.
	if opts.VulnOnly {
		filtered := rows[:0]
		for _, r := range rows {
			if r.Critical+r.High+r.Medium+r.Low > 0 {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}

	// --top N.
	if opts.TopN > 0 && opts.TopN < len(rows) {
		rows = rows[:opts.TopN]
	}

	return rows
}

func htmlSevColor(s osv.Severity) string {
	switch s {
	case osv.SeverityCritical:
		return "#ef4444"
	case osv.SeverityHigh:
		return "#f97316"
	case osv.SeverityMedium:
		return "#f59e0b"
	case osv.SeverityLow:
		return "#9ca3af"
	default:
		return "#6b7280"
	}
}

func htmlSevBadge(s osv.Severity) string {
	color := htmlSevColor(s)
	label := string(s)
	if s == osv.SeverityUnknown {
		label = "?"
	}
	return fmt.Sprintf(`<span class="badge" style="background:%s">%s</span>`, color, label)
}

func htmlRowColor(s osv.Severity) string {
	switch s {
	case osv.SeverityCritical:
		return "rgba(239,68,68,0.08)"
	case osv.SeverityHigh:
		return "rgba(249,115,22,0.07)"
	case osv.SeverityMedium:
		return "rgba(245,158,11,0.06)"
	default:
		return "transparent"
	}
}

func htmlDimZero(n int) string {
	if n == 0 {
		return `<span class="dim">0</span>`
	}
	return fmt.Sprintf("%d", n)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>nazar scan report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #1e1e2e;
    --surface:   #27273a;
    --surface2:  #313145;
    --border:    #383851;
    --text:      #cdd6f4;
    --muted:     #7f849c;
    --accent:    #7b68ee;

    --crit:    #ef4444;
    --high:    #f97316;
    --med:     #f59e0b;
    --low:     #9ca3af;
    --clean:   #22c55e;
    --unknown: #6b7280;
  }

  body {
    font-family: ui-monospace, "Cascadia Code", "Fira Code", monospace;
    background: var(--bg);
    color: var(--text);
    font-size: 13px;
    line-height: 1.5;
    padding: 24px;
  }

  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: baseline;
    gap: 12px;
    margin-bottom: 8px;
  }
  .header h1 {
    font-size: 22px;
    color: var(--accent);
    letter-spacing: 1px;
  }
  .header .subtitle {
    color: var(--muted);
    font-size: 12px;
  }
  .scan-path {
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 20px;
    word-break: break-all;
  }
  .offline-banner {
    background: rgba(245,158,11,0.12);
    border: 1px solid var(--med);
    color: var(--med);
    border-radius: 6px;
    padding: 8px 14px;
    margin-bottom: 20px;
    font-size: 12px;
  }

  /* ── Stats bar ── */
  .stats {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 28px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 20px;
    min-width: 110px;
    text-align: center;
  }
  .stat-card .stat-label {
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
  }
  .stat-card .stat-value {
    font-size: 26px;
    font-weight: bold;
    line-height: 1;
  }
  .stat-card.crit  .stat-value { color: var(--crit); }
  .stat-card.high  .stat-value { color: var(--high); }
  .stat-card.med   .stat-value { color: var(--med); }
  .stat-card.low   .stat-value { color: var(--low); }
  .stat-card.clean .stat-value { color: var(--clean); }
  .stat-card.neutral .stat-value { color: var(--text); }

  /* ── Table ── */
  .section-title {
    font-size: 13px;
    font-weight: bold;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 10px;
  }

  .table-wrap {
    overflow-x: auto;
    border-radius: 8px;
    border: 1px solid var(--border);
    margin-bottom: 32px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  thead {
    background: var(--surface2);
    position: sticky;
    top: 0;
    z-index: 1;
  }
  th {
    padding: 10px 14px;
    text-align: left;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    cursor: pointer;
    white-space: nowrap;
    user-select: none;
  }
  th:hover { color: var(--text); }
  th.sorted { color: var(--accent); }
  th .sort-icon { display: inline-block; margin-left: 4px; opacity: 0.5; }
  th.sorted .sort-icon { opacity: 1; }

  tbody tr {
    border-top: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.1s;
  }
  tbody tr:hover { background: var(--surface) !important; }
  td {
    padding: 9px 14px;
    white-space: nowrap;
  }
  td.path-cell {
    white-space: normal;
    word-break: break-all;
    max-width: 320px;
    font-weight: 500;
  }
  td.num { text-align: right; }
  .dim { color: var(--muted); }
  .eco-badge {
    display: inline-block;
    background: rgba(123,104,238,0.15);
    color: var(--accent);
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 11px;
    letter-spacing: 0.3px;
  }
  .fix-count {
    color: var(--clean);
    font-weight: 600;
  }
  .chevron {
    display: inline-block;
    transition: transform 0.2s;
    color: var(--muted);
    font-size: 10px;
    margin-right: 6px;
  }
  tr.expanded .chevron { transform: rotate(90deg); color: var(--accent); }

  /* ── Detail rows ── */
  tr.detail-row {
    display: none;
    cursor: default;
  }
  tr.detail-row.open { display: table-row; }
  tr.detail-row:hover { background: inherit !important; }
  .detail-cell {
    padding: 0 14px 14px 14px;
    white-space: normal;
  }
  .detail-inner {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
  }
  .pkg-row {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
  }
  .pkg-row:last-child { border-bottom: none; }
  .pkg-name {
    font-weight: 600;
    color: var(--text);
    min-width: 160px;
  }
  .pkg-version {
    color: var(--muted);
    font-size: 12px;
  }
  .direct-tag {
    font-size: 10px;
    background: rgba(34,197,94,0.15);
    color: var(--clean);
    border-radius: 3px;
    padding: 1px 5px;
    align-self: center;
  }
  .vuln-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 4px;
    flex: 1 1 100%;
  }
  .vuln-chip {
    display: flex;
    flex-direction: column;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 4px 8px;
    font-size: 11px;
    gap: 2px;
  }
  .vuln-chip-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .vuln-id {
    color: var(--accent);
    font-weight: 600;
  }
  .fix-tag {
    color: var(--clean);
    font-size: 10px;
  }
  .vuln-summary {
    color: var(--muted);
    font-size: 10px;
    line-height: 1.4;
  }

  /* ── Badges ── */
  .badge {
    display: inline-block;
    border-radius: 4px;
    padding: 1px 7px;
    font-size: 10px;
    font-weight: 700;
    color: #fff;
    letter-spacing: 0.4px;
  }

  /* ── Footer ── */
  footer {
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: space-between;
  }
  .footer-summary { color: var(--text); font-size: 12px; }

  /* ── No results ── */
  .empty { color: var(--muted); padding: 24px; text-align: center; }
</style>
</head>
<body>

<div class="header">
  <h1>nazar 🧿</h1>
  <span class="subtitle">vulnerability scan report</span>
</div>
<div class="scan-path">scanned: {{.Root}}</div>

{{if .Offline}}
<div class="offline-banner">⚠ offline mode — OSV vulnerability lookup was skipped</div>
{{end}}

<!-- Stats bar -->
<div class="stats">
  <div class="stat-card neutral">
    <div class="stat-label">Projects</div>
    <div class="stat-value">{{.TotalProj}}</div>
  </div>
  <div class="stat-card neutral">
    <div class="stat-label">Packages</div>
    <div class="stat-value">{{.TotalPkgs}}</div>
  </div>
  {{if not .Offline}}
  <div class="stat-card crit">
    <div class="stat-label">Critical</div>
    <div class="stat-value">{{.Totals.Critical}}</div>
  </div>
  <div class="stat-card high">
    <div class="stat-label">High</div>
    <div class="stat-value">{{.Totals.High}}</div>
  </div>
  <div class="stat-card med">
    <div class="stat-label">Medium</div>
    <div class="stat-value">{{.Totals.Medium}}</div>
  </div>
  <div class="stat-card low">
    <div class="stat-label">Low</div>
    <div class="stat-value">{{.Totals.Low}}</div>
  </div>
  <div class="stat-card clean">
    <div class="stat-label">Fixable</div>
    <div class="stat-value">{{.TotalFixable}}</div>
  </div>
  {{end}}
</div>

<!-- Projects table -->
<div class="section-title">Projects</div>
<div class="table-wrap">
  <table id="proj-table">
    <thead>
      <tr>
        <th data-col="path" class="sorted">Project<span class="sort-icon">↑</span></th>
        <th data-col="eco">Ecosystem<span class="sort-icon"></span></th>
        <th data-col="pkgs" class="num">Packages<span class="sort-icon"></span></th>
        <th data-col="crit" class="num">CRIT<span class="sort-icon"></span></th>
        <th data-col="high" class="num">HIGH<span class="sort-icon"></span></th>
        <th data-col="med"  class="num">MED<span class="sort-icon"></span></th>
        <th data-col="low"  class="num">LOW<span class="sort-icon"></span></th>
        <th data-col="fix"  class="num">FIXABLE<span class="sort-icon"></span></th>
      </tr>
    </thead>
    <tbody>
{{range $i, $row := .Rows}}
      <tr id="row-{{$i}}" data-idx="{{$i}}"
          style="background:{{rowColor $row.Worst}}"
          data-path="{{$row.Path}}"
          data-eco="{{$row.Ecosystem}}"
          data-pkgs="{{$row.Packages}}"
          data-crit="{{$row.Critical}}"
          data-high="{{$row.High}}"
          data-med="{{$row.Medium}}"
          data-low="{{$row.Low}}"
          data-fix="{{$row.Fixable}}">
        <td class="path-cell">
          <span class="chevron">▶</span>{{$row.Path}}
        </td>
        <td><span class="eco-badge">{{$row.Ecosystem}}</span></td>
        <td class="num">{{$row.Packages}}</td>
        <td class="num" style="color:#ef4444;font-weight:bold">{{dimZero $row.Critical}}</td>
        <td class="num" style="color:#f97316;font-weight:bold">{{dimZero $row.High}}</td>
        <td class="num" style="color:#f59e0b">{{dimZero $row.Medium}}</td>
        <td class="num" style="color:#9ca3af">{{dimZero $row.Low}}</td>
        <td class="num">{{if gt $row.Fixable 0}}<span class="fix-count">{{$row.Fixable}}</span>{{else}}<span class="dim">0</span>{{end}}</td>
      </tr>
      <tr id="detail-{{$i}}" class="detail-row">
        <td class="detail-cell" colspan="8">
          <div class="detail-inner">
{{if $row.Detail}}
{{range $row.Detail}}
            <div class="pkg-row">
              <div>
                <span class="pkg-name">{{.Name}}</span>
                <span class="pkg-version">@{{.Version}}</span>
                {{if .Direct}}<span class="direct-tag">direct</span>{{end}}
              </div>
              <div class="vuln-list">
{{range .Vulns}}
                <div class="vuln-chip">
                  <div class="vuln-chip-top">
                    {{sevBadge .Severity}}
                    <span class="vuln-id">{{.ID}}</span>
                    {{if .FixedIn}}<span class="fix-tag">→ {{.FixedIn}}</span>{{end}}
                  </div>
                  {{if .Summary}}<div class="vuln-summary">{{.Summary}}</div>{{end}}
                </div>
{{end}}
              </div>
            </div>
{{end}}
{{else}}
            <span class="dim">No vulnerable packages above the current severity filter.</span>
{{end}}
          </div>
        </td>
      </tr>
{{end}}
    </tbody>
  </table>
  {{if not .Rows}}<div class="empty">No projects to display.</div>{{end}}
</div>

<footer>
  <span class="footer-summary">{{.SummaryLine}}</span>
  <span>nazar · generated {{.ScannedAt}}</span>
</footer>

<script>
(function () {
  // ── Row expand/collapse ───────────────────────────────────────────────────
  document.querySelectorAll('#proj-table tbody tr:not(.detail-row)').forEach(function (tr) {
    tr.addEventListener('click', function () {
      var idx = tr.dataset.idx;
      var detail = document.getElementById('detail-' + idx);
      if (!detail) return;
      var open = detail.classList.contains('open');
      detail.classList.toggle('open', !open);
      tr.classList.toggle('expanded', !open);
    });
  });

  // ── Column sort ───────────────────────────────────────────────────────────
  var sortState = { col: 'path', asc: true };

  function rowVal(tr, col) {
    switch (col) {
      case 'path': return tr.dataset.path.toLowerCase();
      case 'eco':  return tr.dataset.eco.toLowerCase();
      case 'pkgs': return +tr.dataset.pkgs;
      case 'crit': return +tr.dataset.crit;
      case 'high': return +tr.dataset.high;
      case 'med':  return +tr.dataset.med;
      case 'low':  return +tr.dataset.low;
      case 'fix':  return +tr.dataset.fix;
      default:     return tr.dataset.path.toLowerCase();
    }
  }

  document.querySelectorAll('#proj-table th').forEach(function (th) {
    th.addEventListener('click', function () {
      var col = th.dataset.col;
      if (sortState.col === col) {
        sortState.asc = !sortState.asc;
      } else {
        sortState.col = col;
        sortState.asc = col === 'path' || col === 'eco';
      }

      // Update header styles.
      document.querySelectorAll('#proj-table th').forEach(function (h) {
        h.classList.remove('sorted');
        h.querySelector('.sort-icon').textContent = '';
      });
      th.classList.add('sorted');
      th.querySelector('.sort-icon').textContent = sortState.asc ? '↑' : '↓';

      // Collect data rows and their paired detail rows.
      var tbody = document.querySelector('#proj-table tbody');
      var pairs = [];
      tbody.querySelectorAll('tr:not(.detail-row)').forEach(function (tr) {
        var idx = tr.dataset.idx;
        var detail = document.getElementById('detail-' + idx);
        pairs.push({ tr: tr, detail: detail, val: rowVal(tr, col) });
      });

      pairs.sort(function (a, b) {
        var av = a.val, bv = b.val;
        if (typeof av === 'string') {
          var cmp = av < bv ? -1 : av > bv ? 1 : 0;
          return sortState.asc ? cmp : -cmp;
        }
        return sortState.asc ? av - bv : bv - av;
      });

      pairs.forEach(function (p) {
        tbody.appendChild(p.tr);
        if (p.detail) tbody.appendChild(p.detail);
      });
    });
  });
})();
</script>
</body>
</html>
`
