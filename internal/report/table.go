// Package report renders scan results in either a colorised terminal table
// (default) or machine-readable JSON (`--json`).
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/parser"
	"github.com/umutciftci/nazar/internal/scanner"
)

// PackageVulns pairs a parsed package with the OSV vulnerabilities found
// for it. Vulns is empty when nothing matched (the package was queried
// and OSV returned nothing).
type PackageVulns struct {
	Package parser.Package `json:"package"`
	Vulns   []osv.Vuln     `json:"vulns,omitempty"`
}

// Result pairs a detected project with its packages-with-vulns. When the
// scan was run with --offline, every entry's Vulns will be empty; the JSON
// caller can distinguish "skipped" from "checked, none found" using the
// top-level Offline flag in scanReport.
type Result struct {
	Project      scanner.Project `json:"project"`
	Packages     []PackageVulns  `json:"packages"`
	IgnoredCount int             `json:"ignored_count,omitempty"`
}

// RenderOptions controls optional display behaviour for both renderers.
type RenderOptions struct {
	// MinSeverity filters the vuln detail section to show only vulns at or
	// above this severity. The summary table always shows full counts.
	// Empty string (zero value) means "show everything".
	MinSeverity osv.Severity

	// ShowDetail enables the per-project vulnerable package list.
	// When false (default) only the summary table and hotspots are shown.
	ShowDetail bool

	// ProjectFilter, when non-empty, restricts the detail section to projects
	// whose relative path contains this substring (case-insensitive).
	// It implicitly enables ShowDetail for the matching projects.
	ProjectFilter string

	// SortBy controls table sort order. Valid values:
	//   "path"    — alphabetical by project path (default)
	//   "worst"   — worst severity bucket descending
	//   "crit"    — critical count descending
	//   "high"    — high count descending
	//   "total"   — total vuln count descending
	//   "fixable" — fixable package count descending
	SortBy string

	// GroupByEcosystem, when true, inserts a bold ecosystem section header
	// before each group of rows sharing the same ecosystem (npm / Go / PyPI / …).
	// Rows are always sorted by ecosystem first when this flag is set.
	GroupByEcosystem bool

	// TopN, when > 0, limits the table to the first N rows (after sorting).
	// Summary totals always reflect all projects.
	TopN int

	// VulnOnly, when true, hides projects with zero vulnerabilities from the
	// summary table (they are still counted in the footer totals).
	VulnOnly bool

	// Quiet, when true, suppresses the summary table, hotspots, and detail
	// sections. Only the single-line summary is printed to w.
	Quiet bool
}

// scanReport is the top-level shape we emit when --json is set.
type scanReport struct {
	Root         string   `json:"root"`
	Offline      bool     `json:"offline"`
	IgnoredTotal int      `json:"ignored_total,omitempty"`
	Projects     []Result `json:"projects"`
}

// Style palette — kept minimal on purpose. lipgloss auto-degrades on
// terminals that don't support colour, so this works in CI logs too.
var (
	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7B68EE")). // nazar blue
			Bold(true)

	pathStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	ecosystemStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7B68EE")).
			Bold(true)

	cleanStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("46")) // green

	dimCountStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	mutedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Italic(true)

	// Severity colour palette — red for crit/high, amber for med, dim for low.
	criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	highStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	lowStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	unknownStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)

	idStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("203"))

	pkgRefStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Bold(true)
)

// styleFor returns the colour style for a given severity bucket.
func styleFor(s osv.Severity) lipgloss.Style {
	switch s {
	case osv.SeverityCritical:
		return criticalStyle
	case osv.SeverityHigh:
		return highStyle
	case osv.SeverityMedium:
		return mediumStyle
	case osv.SeverityLow:
		return lowStyle
	default:
		return unknownStyle
	}
}

// severityCounts tallies vulnerabilities by severity.
type severityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Total returns the sum across all buckets.
func (sc severityCounts) Total() int {
	return sc.Critical + sc.High + sc.Medium + sc.Low + sc.Unknown
}

// Worst returns the highest non-zero bucket.
func (sc severityCounts) Worst() osv.Severity {
	switch {
	case sc.Critical > 0:
		return osv.SeverityCritical
	case sc.High > 0:
		return osv.SeverityHigh
	case sc.Medium > 0:
		return osv.SeverityMedium
	case sc.Low > 0:
		return osv.SeverityLow
	default:
		return osv.SeverityUnknown
	}
}

func tally(pvs []PackageVulns) severityCounts {
	var sc severityCounts
	for _, p := range pvs {
		for _, v := range p.Vulns {
			switch v.Severity {
			case osv.SeverityCritical:
				sc.Critical++
			case osv.SeverityHigh:
				sc.High++
			case osv.SeverityMedium:
				sc.Medium++
			case osv.SeverityLow:
				sc.Low++
			default:
				sc.Unknown++
			}
		}
	}
	return sc
}

// RenderText writes a human-friendly summary of the scan to w.
func RenderText(w io.Writer, root string, offline bool, results []Result, opts RenderOptions) {
	fmt.Fprintln(w, headerStyle.Render("nazar 🧿 — scan results"))
	fmt.Fprintln(w, mutedStyle.Render("scanned: "+root))
	if offline {
		fmt.Fprintln(w, mutedStyle.Render("offline mode — OSV lookup skipped"))
	}
	fmt.Fprintln(w)

	if len(results) == 0 {
		fmt.Fprintln(w, mutedStyle.Render("No projects detected."))
		return
	}

	const (
		minPathCol      = 30
		ecosystemColLen = 10
		countColLen     = 10
		sevColLen       = 6
	)

	type row struct {
		path      string
		ecosystem string
		total     int
		direct    int
		fixable   int
		sc        severityCounts
	}
	rows := make([]row, 0, len(results))
	pathCol := minPathCol
	for _, r := range results {
		rel, err := filepath.Rel(root, r.Project.Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			rel = r.Project.Path
		}
		if rel == "." {
			rel = "(root)"
		}
		direct := 0
		fixable := 0
		for _, p := range r.Packages {
			if p.Package.Direct {
				direct++
			}
			for _, v := range p.Vulns {
				if v.FixedIn != "" {
					fixable++
					break // count package once, not per-vuln
				}
			}
		}
		rows = append(rows, row{
			path:      rel,
			ecosystem: string(r.Project.Ecosystem),
			total:     len(r.Packages),
			direct:    direct,
			fixable:   fixable,
			sc:        tally(r.Packages),
		})
		if l := lipgloss.Width(rel); l > pathCol {
			pathCol = l
		}
	}

	// ── Sort rows ─────────────────────────────────────────────────────────────
	// Severity rank: critical > high > medium > low > unknown (0).
	sevRank := func(sc severityCounts) int {
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
			ri, rj := sevRank(rows[i].sc), sevRank(rows[j].sc)
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
			ti := rows[i].sc.Total()
			tj := rows[j].sc.Total()
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

	// Compute full-set totals (all rows, before any display filtering).
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

	// allRows holds the full sorted set for the summary line (project count,
	// totals) before any display-only filters are applied.
	allRows := rows

	// --quiet: print only the one-line summary and return immediately.
	if opts.Quiet {
		fmt.Fprintln(w, summaryLine(len(allRows), totalPkgs, totalDirect, totalFixable, totals, offline))
		return
	}

	// --vuln-only: hide clean projects from the display table only.
	if opts.VulnOnly && !offline {
		filtered := make([]row, 0, len(rows))
		for _, rw := range rows {
			if rw.sc.Total() > 0 {
				filtered = append(filtered, rw)
			}
		}
		rows = filtered
	}

	// Truncate display rows if --top is set. allRows is unchanged.
	if opts.TopN > 0 && opts.TopN < len(rows) {
		rows = rows[:opts.TopN]
	}

	const gap = "  "

	header := strings.Join([]string{
		headerStyle.Render(padRight("PROJECT", pathCol)),
		headerStyle.Render(padRight("ECOSYSTEM", ecosystemColLen)),
		headerStyle.Render(padRight("PACKAGES", countColLen)),
		headerStyle.Render(padRight("DIRECT", countColLen)),
		headerStyle.Render(padRight("CRIT", sevColLen)),
		headerStyle.Render(padRight("HIGH", sevColLen)),
		headerStyle.Render(padRight("MED", sevColLen)),
		headerStyle.Render(padRight("LOW", sevColLen)),
		headerStyle.Render(padRight("?", sevColLen)),
		headerStyle.Render("FIXABLE"),
	}, gap)
	fmt.Fprintln(w, header)
	rule := pathCol + ecosystemColLen + countColLen*2 + sevColLen*5 + 7 + 9*len(gap)
	fmt.Fprintln(w, mutedStyle.Render(strings.Repeat("─", rule)))

	// When --group-by-ecosystem, sort rows by ecosystem first (then by the
	// user's chosen secondary sort), and print a section header on change.
	if opts.GroupByEcosystem {
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].ecosystem != rows[j].ecosystem {
				return rows[i].ecosystem < rows[j].ecosystem
			}
			return rows[i].path < rows[j].path
		})
	}

	prevEco := ""
	for _, rw := range rows {
		if opts.GroupByEcosystem && rw.ecosystem != prevEco {
			if prevEco != "" {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, ecosystemStyle.Render("── "+rw.ecosystem+" ──"))
			prevEco = rw.ecosystem
		}

		fixableCell := dimCountStyle.Render(padRight("—", 7))
		if !offline && rw.fixable > 0 {
			fixableCell = cleanStyle.Render(fmt.Sprintf("%d", rw.fixable))
		} else if !offline {
			fixableCell = dimCountStyle.Render("0")
		}

		line := strings.Join([]string{
			pathStyle.Render(padRight(rw.path, pathCol)),
			ecosystemStyle.Render(padRight(rw.ecosystem, ecosystemColLen)),
			cleanStyle.Render(padRight(fmt.Sprintf("%d", rw.total), countColLen)),
			dimCountStyle.Render(padRight(fmt.Sprintf("%d", rw.direct), countColLen)),
			cellInt(rw.sc.Critical, criticalStyle, sevColLen, offline),
			cellInt(rw.sc.High, highStyle, sevColLen, offline),
			cellInt(rw.sc.Medium, mediumStyle, sevColLen, offline),
			cellInt(rw.sc.Low, lowStyle, sevColLen, offline),
			cellInt(rw.sc.Unknown, unknownStyle, sevColLen, offline),
			fixableCell,
		}, gap)
		fmt.Fprintln(w, line)
	}

	// If --top truncated the table, show a hint about hidden projects.
	if opts.TopN > 0 && len(allRows) > opts.TopN {
		hidden := len(allRows) - opts.TopN
		fmt.Fprintln(w, mutedStyle.Render(fmt.Sprintf("… and %d more project(s) not shown (remove --top to see all)", hidden)))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, mutedStyle.Render(summaryLine(len(allRows), totalPkgs, totalDirect, totalFixable, totals, offline)))

	ignoredTotal := 0
	for _, r := range results {
		ignoredTotal += r.IgnoredCount
	}
	if ignoredTotal > 0 {
		fmt.Fprintln(w, mutedStyle.Render(fmt.Sprintf("(%d vulnerability match(es) suppressed by ignore rules)", ignoredTotal)))
	}

	if !offline && totals.Total() > 0 {
		renderHotspots(w, results)

		wantDetail := opts.ShowDetail || opts.ProjectFilter != ""
		if wantDetail {
			if opts.MinSeverity != "" && opts.MinSeverity != osv.SeverityUnknown {
				fmt.Fprintln(w, mutedStyle.Render(fmt.Sprintf("(detail filtered to %s+ only)", string(opts.MinSeverity))))
			}
			detailResults := results
			if opts.ProjectFilter != "" {
				detailResults = filterResultsByProject(results, root, opts.ProjectFilter)
				if len(detailResults) == 0 {
					fmt.Fprintln(w, mutedStyle.Render(fmt.Sprintf("no projects matching %q", opts.ProjectFilter)))
				}
			}
			if len(detailResults) > 0 {
				renderVulnDetail(w, detailResults, root, opts.MinSeverity)
			}
		} else {
			fmt.Fprintln(w, mutedStyle.Render("(use --detail to see vulnerable packages, --project <name> for a single project)"))
		}
	}
}

// cellInt renders a single integer cell, dimming "0" and using "—" in
// offline mode (since we didn't actually check).
func cellInt(n int, style lipgloss.Style, width int, offline bool) string {
	if offline {
		return dimCountStyle.Render(padRight("—", width))
	}
	if n == 0 {
		return dimCountStyle.Render(padRight("0", width))
	}
	return style.Render(padRight(fmt.Sprintf("%d", n), width))
}

func summaryLine(numProjects, totalPkgs, totalDirect, totalFixable int, totals severityCounts, offline bool) string {
	if offline {
		return fmt.Sprintf("%d project(s), %d total packages (%d direct), vulnerability check skipped.",
			numProjects, totalPkgs, totalDirect)
	}
	base := fmt.Sprintf(
		"%d project(s), %d total packages (%d direct), %d vulnerabilities (%d crit / %d high / %d med / %d low / %d unknown).",
		numProjects, totalPkgs, totalDirect,
		totals.Total(), totals.Critical, totals.High, totals.Medium, totals.Low, totals.Unknown,
	)
	if totalFixable > 0 {
		base += fmt.Sprintf(" %d package(s) have a known fix — run `nazar fix` to upgrade.", totalFixable)
	}
	return base
}

// renderVulnDetail prints a per-project breakdown of the vulnerable packages
// found, sorted by severity (worst first) within each project.
// minSeverity filters out vulns below the threshold; empty means show all.
func renderVulnDetail(w io.Writer, results []Result, root string, minSeverity osv.Severity) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, warnStyle.Render("Vulnerable packages:"))

	for _, r := range results {
		var hits []PackageVulns
		for _, p := range r.Packages {
			vulns := filterBySeverity(p.Vulns, minSeverity)
			if len(vulns) > 0 {
				hits = append(hits, PackageVulns{Package: p.Package, Vulns: vulns})
			}
		}
		if len(hits) == 0 {
			continue
		}

		// Sort hits by worst-severity-of-package descending, then by name.
		sort.Slice(hits, func(i, j int) bool {
			wi := worstSeverity(hits[i].Vulns)
			wj := worstSeverity(hits[j].Vulns)
			if wi != wj {
				return wi.Rank() > wj.Rank()
			}
			return hits[i].Package.Name < hits[j].Package.Name
		})

		rel, err := filepath.Rel(root, r.Project.Path)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			rel = r.Project.Path
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  "+pathStyle.Render(rel))

		for _, h := range hits {
			worst := worstSeverity(h.Vulns)
			tag := styleFor(worst).Render(fmt.Sprintf("[%s]", string(worst)))

			// Sort vulns within a package by severity desc, then by ID.
			vsorted := make([]osv.Vuln, len(h.Vulns))
			copy(vsorted, h.Vulns)
			sort.Slice(vsorted, func(i, j int) bool {
				if vsorted[i].Severity != vsorted[j].Severity {
					return vsorted[i].Severity.Rank() > vsorted[j].Severity.Rank()
				}
				return vsorted[i].ID < vsorted[j].ID
			})

			ids := make([]string, 0, len(vsorted))
			for _, v := range vsorted {
				entry := idStyle.Render(v.ID)
				if v.FixedIn != "" {
					entry += mutedStyle.Render(" →"+v.FixedIn)
				}
				ids = append(ids, entry)
			}
			fmt.Fprintf(w, "    %s  %s  %s\n",
				tag,
				pkgRefStyle.Render(fmt.Sprintf("%s@%s", h.Package.Name, h.Package.Version)),
				strings.Join(ids, ", "),
			)
			// Show the worst vuln's summary as a short contextual hint.
			if vsorted[0].Summary != "" {
				summary := vsorted[0].Summary
				if len(summary) > 100 {
					summary = summary[:97] + "…"
				}
				fmt.Fprintf(w, "        %s\n", mutedStyle.Render(summary))
			}
		}
	}
}

// hotspotEntry tracks a vulnerable package that appears across multiple projects.
type hotspotEntry struct {
	name     string
	version  string
	fixedIn  string
	severity osv.Severity
	vulnIDs  []string
	projects []string
}

// renderHotspots prints the cross-project hotspot table — packages that are
// vulnerable in 2 or more projects. This helps developers see which upgrades
// would fix the most projects at once.
func renderHotspots(w io.Writer, results []Result) {
	type pkgKey struct{ name, version string }
	type pkgData struct {
		severity osv.Severity
		fixedIn  string
		vulnIDs  map[string]struct{}
		projects map[string]struct{}
	}

	byPkg := map[pkgKey]*pkgData{}

	for _, r := range results {
		for _, pv := range r.Packages {
			if len(pv.Vulns) == 0 {
				continue
			}
			k := pkgKey{pv.Package.Name, pv.Package.Version}
			d, ok := byPkg[k]
			if !ok {
				d = &pkgData{
					vulnIDs:  map[string]struct{}{},
					projects: map[string]struct{}{},
				}
				byPkg[k] = d
			}
			d.projects[r.Project.Path] = struct{}{}
			for _, v := range pv.Vulns {
				d.vulnIDs[v.ID] = struct{}{}
				if v.Severity.Rank() > d.severity.Rank() {
					d.severity = v.Severity
				}
				if d.fixedIn == "" && v.FixedIn != "" {
					d.fixedIn = v.FixedIn
				}
			}
		}
	}

	// Collect entries that appear in 2+ projects.
	var hotspots []hotspotEntry
	for k, d := range byPkg {
		if len(d.projects) < 2 {
			continue
		}
		entry := hotspotEntry{
			name:    k.name,
			version: k.version,
			fixedIn: d.fixedIn,
		}
		entry.severity = d.severity
		for id := range d.vulnIDs {
			entry.vulnIDs = append(entry.vulnIDs, id)
		}
		for p := range d.projects {
			entry.projects = append(entry.projects, p)
		}
		sort.Strings(entry.vulnIDs)
		sort.Strings(entry.projects)
		hotspots = append(hotspots, entry)
	}

	if len(hotspots) == 0 {
		return
	}

	// Sort by project count desc, then severity desc, then name.
	sort.Slice(hotspots, func(i, j int) bool {
		if len(hotspots[i].projects) != len(hotspots[j].projects) {
			return len(hotspots[i].projects) > len(hotspots[j].projects)
		}
		if hotspots[i].severity.Rank() != hotspots[j].severity.Rank() {
			return hotspots[i].severity.Rank() > hotspots[j].severity.Rank()
		}
		return hotspots[i].name < hotspots[j].name
	})

	fmt.Fprintln(w)
	fmt.Fprintln(w, warnStyle.Render("Cross-project hotspots (vulnerable in 2+ projects):"))

	for _, h := range hotspots {
		fixHint := ""
		if h.fixedIn != "" {
			fixHint = mutedStyle.Render("  →"+h.fixedIn)
		}
		ids := make([]string, 0, len(h.vulnIDs))
		for _, id := range h.vulnIDs {
			ids = append(ids, idStyle.Render(id))
		}
		fmt.Fprintf(w, "\n  %s  %s%s  %s  %s\n",
			styleFor(h.severity).Render(fmt.Sprintf("[%s]", string(h.severity))),
			pkgRefStyle.Render(fmt.Sprintf("%s@%s", h.name, h.version)),
			fixHint,
			dimCountStyle.Render(fmt.Sprintf("%d projects", len(h.projects))),
			strings.Join(ids, ", "),
		)
	}
}

// filterBySeverity returns only the vulns at or above minSeverity.
// If minSeverity is empty or SeverityUnknown, all vulns are returned.
func filterBySeverity(vulns []osv.Vuln, min osv.Severity) []osv.Vuln {
	if min == "" || min == osv.SeverityUnknown {
		return vulns
	}
	out := vulns[:0:0]
	for _, v := range vulns {
		if v.Severity.Rank() >= min.Rank() {
			out = append(out, v)
		}
	}
	return out
}

func worstSeverity(vulns []osv.Vuln) osv.Severity {
	worst := osv.SeverityUnknown
	for _, v := range vulns {
		if v.Severity.Rank() > worst.Rank() {
			worst = v.Severity
		}
	}
	return worst
}

// filterResultsByProject returns results whose relative path contains filter
// (case-insensitive substring match).
func filterResultsByProject(results []Result, root, filter string) []Result {
	lower := strings.ToLower(filter)
	var out []Result
	for _, r := range results {
		rel, err := filepath.Rel(root, r.Project.Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			rel = r.Project.Path
		}
		if rel == "." {
			rel = "(root)"
		}
		// Match against relative path OR the base directory name so that
		// "--project my-api" works whether scanning from parent or directly.
		baseName := strings.ToLower(filepath.Base(r.Project.Path))
		if strings.Contains(strings.ToLower(rel), lower) || strings.Contains(baseName, lower) {
			out = append(out, r)
		}
	}
	return out
}

// RenderCSV writes one row per (project, package, vuln) to w in CSV format.
// Headers: project,ecosystem,lockfile,package,version,severity,vuln_id,fix_version,summary
func RenderCSV(w io.Writer, root string, results []Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"project", "ecosystem", "lockfile",
		"package", "version",
		"severity", "vuln_id", "fix_version", "summary",
	}); err != nil {
		return err
	}

	for _, r := range results {
		rel, err := filepath.Rel(root, r.Project.Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			rel = r.Project.Path
		}
		if rel == "." {
			rel = "(root)"
		}
		lockfileBase := filepath.Base(r.Project.LockfilePath)
		ecosystem := string(r.Project.Ecosystem)

		for _, pv := range r.Packages {
			if len(pv.Vulns) == 0 {
				continue
			}
			for _, v := range pv.Vulns {
				if err := cw.Write([]string{
					rel,
					ecosystem,
					lockfileBase,
					pv.Package.Name,
					pv.Package.Version,
					string(v.Severity),
					v.ID,
					v.FixedIn,
					v.Summary,
				}); err != nil {
					return err
				}
			}
		}
	}

	cw.Flush()
	return cw.Error()
}

// RenderJSON writes a deterministic JSON document describing the scan.
func RenderJSON(w io.Writer, root string, offline bool, results []Result, opts RenderOptions) error {
	ignoredTotal := 0
	for _, r := range results {
		ignoredTotal += r.IgnoredCount
	}
	doc := scanReport{Root: root, Offline: offline, IgnoredTotal: ignoredTotal, Projects: results}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// padRight returns s padded with spaces (or truncated with an ellipsis) so
// that lipgloss.Width(result) == width.
func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w == width {
		return s
	}
	if w < width {
		return s + strings.Repeat(" ", width-w)
	}
	if width <= 1 {
		return s[:width]
	}
	return s[:width-1] + "…"
}
