package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/fixer"
	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/report"
	"github.com/umutciftci/nazar/internal/scanner"
)

// fixGroup is a (package@version → fixedIn) tuple that appears in one or more
// projects. The interactive UI shows one row per group.
type fixGroup struct {
	PackageName string
	OldVersion  string
	FixedIn     string
	Severity    osv.Severity
	VulnIDs     []string
	Projects    []scanner.Project
}

// fixFlags holds parsed flag values for the fix command.
type fixFlags struct {
	dryRun          bool
	all             bool
	auto            bool
	safeOnly        bool
	minSeverity     string
	projectFilter   string
	ecosystem       string
	runTests        string
	rollback        bool
	cacheDir        string
	osvBaseURL      string
	osvTimeout      time.Duration
	severityWorkers int
	noCache         bool
}

func newFixCmd() *cobra.Command {
	flags := &fixFlags{}

	cmd := &cobra.Command{
		Use:   "fix <path>",
		Short: "Interactively upgrade vulnerable packages",
		Long: "Fix scans the given directory, finds every package with a known fix version,\n" +
			"and lets you choose which ones to upgrade. Lockfiles are backed up before any\n" +
			"changes so you can always run `nazar fix --rollback` to undo.\n\n" +
			"This command runs the appropriate package manager (npm, yarn, pnpm, poetry,\n" +
			"uv, pipenv, go, cargo) — make sure the relevant tool is on your PATH.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFix(cmd, args[0], flags)
		},
	}

	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "show what would be fixed without making any changes")
	cmd.Flags().BoolVar(&flags.all, "all", false, "fix all fixable vulnerabilities without prompting")
	cmd.Flags().BoolVar(&flags.auto, "auto", false, "CI mode: apply all safe-only fixes without prompting (shortcut for --all --safe-only)")
	cmd.Flags().BoolVar(&flags.safeOnly, "safe-only", false, "skip fixes that require a major version bump")
	cmd.Flags().StringVar(&flags.minSeverity, "severity", "", "only fix vulns at or above this level (critical|high|medium|low)")
	cmd.Flags().StringVar(&flags.projectFilter, "project", "", "only fix projects whose path contains this substring (case-insensitive)")
	cmd.Flags().StringVar(&flags.ecosystem, "ecosystem", "", "only fix projects in this ecosystem: npm|pypi|go|cargo")
	cmd.Flags().StringVar(&flags.runTests, "run-tests", "", "command to run after each project fix (e.g. 'npm test'); rollback if it fails")
	cmd.Flags().BoolVar(&flags.rollback, "rollback", false, "undo the last fix session (restore backed-up lockfiles)")
	cmd.Flags().StringVar(&flags.cacheDir, "cache-dir", "", "override the OSV cache directory (default: ~/.cache/nazar)")
	cmd.Flags().StringVar(&flags.osvBaseURL, "osv-url", osv.DefaultBaseURL, "OSV API base URL")
	cmd.Flags().DurationVar(&flags.osvTimeout, "osv-timeout", 90*time.Second, "overall timeout for the OSV lookup phase")
	cmd.Flags().IntVar(&flags.severityWorkers, "severity-workers", 8, "parallel HTTP workers for the severity fetch phase")
	cmd.Flags().BoolVar(&flags.noCache, "no-cache", false, "bypass OSV cache")

	return cmd
}

func runFix(cmd *cobra.Command, target string, flags *fixFlags) error {
	// --auto is a CI-friendly shortcut for --all --safe-only.
	if flags.auto {
		flags.all = true
		flags.safeOnly = true
	}

	abs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// --rollback: restore last session and exit.
	if flags.rollback {
		return doRollback(cmd, abs, flags)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", abs)
	}

	// ── Scan ─────────────────────────────────────────────────────────────────

	fmt.Fprintln(cmd.ErrOrStderr(), " → scanning filesystem…")
	projects, err := scanner.ScanWithOptions(abs, scanner.Options{})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	parsedProjects, _ := parseProjectsConcurrent(projects)

	// ── OSV lookup ────────────────────────────────────────────────────────────

	scanFlags := &scanFlags{
		cacheDir:        flags.cacheDir,
		osvBaseURL:      flags.osvBaseURL,
		osvTimeout:      flags.osvTimeout,
		severityWorkers: flags.severityWorkers,
		noCache:         flags.noCache,
	}

	coords := dedupCoords(parsedProjects)
	if len(coords) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No packages found.")
		return nil
	}

	fmt.Fprintf(cmd.ErrOrStderr(), " → querying OSV.dev (%d unique packages)…\n", len(coords))
	vulnsByCoord, err := lookupOSV(cmd.Context(), coords, scanFlags)
	if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: OSV lookup failed:", err)
	}

	ids := uniqueVulnIDs(vulnsByCoord)
	detailsByID := map[string]*osv.VulnDetail{}
	if len(ids) > 0 {
		cached := countCachedDetails(ids, scanFlags)
		uncached := len(ids) - cached
		if uncached > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), " → fetching severity + fix info (%d CVEs, %d cached)…\n", len(ids), cached)
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), " → severity + fix info (%d CVEs, all cached)…\n", len(ids))
		}
		details, err := fetchSeverity(cmd.Context(), ids, scanFlags, nil)
		if err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: severity fetch had issues:", err)
		}
		for id, d := range details {
			detailsByID[id] = d
		}
	}

	// ── Build results + collect fixable groups ────────────────────────────────

	minSev, err := parseSeverityFlag("--severity", flags.minSeverity)
	if err != nil {
		return err
	}

	results := buildResults(parsedProjects, vulnsByCoord, detailsByID, scanFlags)

	// --project filter: keep only matching projects.
	if flags.projectFilter != "" {
		lower := strings.ToLower(flags.projectFilter)
		filtered := results[:0]
		for _, r := range results {
			rel, _ := filepath.Rel(abs, r.Project.Path)
			baseName := strings.ToLower(filepath.Base(r.Project.Path))
			if strings.Contains(strings.ToLower(rel), lower) || strings.Contains(baseName, lower) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
		if len(results) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", noFixStyle.Render(
				fmt.Sprintf("No projects matching %q found.", flags.projectFilter)))
			return nil
		}
		fmt.Fprintf(cmd.ErrOrStderr(), " → filtered to %d project(s) matching %q\n",
			len(results), flags.projectFilter)
	}

	// --ecosystem filter: keep only projects in the specified ecosystem.
	if flags.ecosystem != "" {
		lower := strings.ToLower(flags.ecosystem)
		filtered := results[:0]
		for _, r := range results {
			if strings.EqualFold(string(r.Project.Ecosystem), lower) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
		if len(results) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", noFixStyle.Render(
				fmt.Sprintf("No %s projects found.", flags.ecosystem)))
			return nil
		}
		fmt.Fprintf(cmd.ErrOrStderr(), " → filtered to %d %s project(s)\n",
			len(results), flags.ecosystem)
	}

	groups := collectFixGroups(results, minSev, flags.safeOnly)

	if len(groups) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), noFixStyle.Render("✓ No fixable vulnerabilities found."))
		return nil
	}

	// ── Render the fixable list ───────────────────────────────────────────────

	printFixableList(cmd, groups)

	if flags.dryRun {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), mutedFixStyle.Render("Dry run — no changes made."))
		return nil
	}

	// ── Select which groups to fix ────────────────────────────────────────────

	selected, err := selectGroups(cmd, groups, flags.all)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), mutedFixStyle.Render("Nothing selected — exiting."))
		return nil
	}

	// ── Apply ─────────────────────────────────────────────────────────────────

	return applyFixes(cmd, abs, selected, flags)
}

// ── Styles ───────────────────────────────────────────────────────────────────

var (
	fixHeaderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7B68EE")).Bold(true)
	fixNumStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	noFixStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	mutedFixStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Italic(true)
	successStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	errStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
)

// ── collectFixGroups ──────────────────────────────────────────────────────────

func collectFixGroups(results []report.Result, minSev osv.Severity, safeOnly bool) []fixGroup {
	type key struct{ name, oldVer string }
	type data struct {
		severity osv.Severity
		vulnIDs  map[string]struct{}
		projects map[string]scanner.Project
		fixedIns []string
	}

	byKey := map[key]*data{}

	for _, r := range results {
		for _, pv := range r.Packages {
			for _, v := range pv.Vulns {
				if v.FixedIn == "" {
					continue
				}
				// Skip downgrades — only suggest actual upgrades.
				if semverCmp(v.FixedIn, pv.Package.Version) <= 0 {
					continue
				}
				// --severity filter: skip vulns below the threshold.
				if minSev != "" && v.Severity.Rank() < minSev.Rank() {
					continue
				}
				k := key{pv.Package.Name, pv.Package.Version}
				d, ok := byKey[k]
				if !ok {
					d = &data{
						vulnIDs:  map[string]struct{}{},
						projects: map[string]scanner.Project{},
					}
					byKey[k] = d
				}
				d.vulnIDs[v.ID] = struct{}{}
				d.projects[r.Project.Path] = r.Project
				if v.Severity.Rank() > d.severity.Rank() {
					d.severity = v.Severity
				}
				d.fixedIns = append(d.fixedIns, v.FixedIn)
			}
		}
	}

	groups := make([]fixGroup, 0, len(byKey))
	for k, d := range byKey {
		best := highestSemver(d.fixedIns)
		if best == "" {
			continue
		}
		// --safe-only: skip major version bumps.
		if safeOnly && semverParts(best)[0] > semverParts(k.oldVer)[0] {
			continue
		}
		g := fixGroup{
			PackageName: k.name,
			OldVersion:  k.oldVer,
			FixedIn:     best,
			Severity:    d.severity,
		}
		for id := range d.vulnIDs {
			g.VulnIDs = append(g.VulnIDs, id)
		}
		for _, p := range d.projects {
			g.Projects = append(g.Projects, p)
		}
		sort.Strings(g.VulnIDs)
		sort.Slice(g.Projects, func(i, j int) bool {
			return g.Projects[i].Path < g.Projects[j].Path
		})
		groups = append(groups, g)
	}

	// Sort: severity desc, project count desc, name asc.
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Severity.Rank() != groups[j].Severity.Rank() {
			return groups[i].Severity.Rank() > groups[j].Severity.Rank()
		}
		if len(groups[i].Projects) != len(groups[j].Projects) {
			return len(groups[i].Projects) > len(groups[j].Projects)
		}
		return groups[i].PackageName < groups[j].PackageName
	})
	return groups
}

// ── semver helpers ────────────────────────────────────────────────────────────

// semverCmp compares two version strings. Returns -1, 0, or 1.
// Handles "v" prefix and pre-release suffixes ("1.4.4-lts.1").
func semverCmp(a, b string) int {
	ap, bp := semverParts(a), semverParts(b)
	for i := 0; i < 3; i++ {
		if ap[i] < bp[i] {
			return -1
		}
		if ap[i] > bp[i] {
			return 1
		}
	}
	return 0
}

func semverParts(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	parts := strings.SplitN(v, ".", 3)
	var r [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		r[i], _ = strconv.Atoi(p)
	}
	return r
}

func highestSemver(versions []string) string {
	best := ""
	for _, v := range versions {
		if best == "" || semverCmp(v, best) > 0 {
			best = v
		}
	}
	return best
}

// ── printFixableList ──────────────────────────────────────────────────────────

func printFixableList(cmd *cobra.Command, groups []fixGroup) {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s  %s\n",
		fixHeaderStyle.Render("nazar 🧿 — fixable vulnerabilities"),
		mutedFixStyle.Render(fmt.Sprintf("(%d packages)", len(groups))),
	)
	fmt.Fprintln(w)

	for i, g := range groups {
		sevTag := styleForSev(g.Severity).Render(fmt.Sprintf("[%s]", string(g.Severity)))
		num := fixNumStyle.Render(fmt.Sprintf("#%-3d", i+1))
		pkg := lipgloss.NewStyle().Bold(true).Render(
			fmt.Sprintf("%s@%s", g.PackageName, g.OldVersion),
		)
		fix := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("→" + g.FixedIn)

		projectNames := make([]string, 0, len(g.Projects))
		for _, p := range g.Projects {
			projectNames = append(projectNames, filepath.Base(p.Path))
		}
		cveCount := mutedFixStyle.Render(fmt.Sprintf("fixes %d CVE(s)", len(g.VulnIDs)))
		proj := mutedFixStyle.Render(
			fmt.Sprintf("%d project(s): %s", len(g.Projects), strings.Join(projectNames, ", ")),
		)

		majorBump := ""
		if semverParts(g.FixedIn)[0] > semverParts(g.OldVersion)[0] {
			majorBump = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render(" ⚠ major")
		}

		fmt.Fprintf(w, "  %s %s  %s  %s%s  %s  %s\n", num, sevTag, pkg, fix, majorBump, cveCount, proj)
	}
	fmt.Fprintln(w)
}

// ── selectGroups ─────────────────────────────────────────────────────────────

func selectGroups(cmd *cobra.Command, groups []fixGroup, all bool) ([]fixGroup, error) {
	if all {
		return groups, nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Fix: %s / %s / %s\n",
		lipgloss.NewStyle().Bold(true).Render("a = all"),
		lipgloss.NewStyle().Bold(true).Render("1,2,5-8 = select"),
		lipgloss.NewStyle().Bold(true).Render("q = quit"),
	)
	fmt.Fprint(cmd.OutOrStdout(), "> ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	line = strings.TrimSpace(line)

	switch strings.ToLower(line) {
	case "q", "quit", "":
		return nil, nil
	case "a", "all":
		return groups, nil
	}

	// Parse "1,2,5-8" → indices (1-based).
	indices, err := parseSelection(line, len(groups))
	if err != nil {
		return nil, err
	}
	selected := make([]fixGroup, 0, len(indices))
	for _, idx := range indices {
		selected = append(selected, groups[idx-1])
	}
	return selected, nil
}

func parseSelection(s string, max int) ([]int, error) {
	seen := map[int]struct{}{}
	var out []int

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > max || lo > hi {
				return nil, fmt.Errorf("invalid range %q (valid: 1-%d)", part, max)
			}
			for i := lo; i <= hi; i++ {
				if _, ok := seen[i]; !ok {
					seen[i] = struct{}{}
					out = append(out, i)
				}
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || n > max {
				return nil, fmt.Errorf("invalid selection %q (valid: 1-%d)", part, max)
			}
			if _, ok := seen[n]; !ok {
				seen[n] = struct{}{}
				out = append(out, n)
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

// ── applyFixes ────────────────────────────────────────────────────────────────

func applyFixes(cmd *cobra.Command, root string, groups []fixGroup, flags *fixFlags) error {
	backupRoot := backupRootDir(flags.cacheDir)
	sessionDir := fixer.SessionDir(backupRoot)

	manifest := &fixer.Manifest{Timestamp: time.Now().UTC()}
	var mu sync.Mutex
	w := cmd.OutOrStdout()

	fmt.Fprintln(w)

	for _, g := range groups {
		fmt.Fprintf(w, "%s  %s@%s → %s\n",
			lipgloss.NewStyle().Bold(true).Render(g.PackageName),
			mutedFixStyle.Render(g.OldVersion),
			lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render(g.FixedIn),
			mutedFixStyle.Render(fmt.Sprintf("(%d project(s))", len(g.Projects))),
		)

		for _, proj := range g.Projects {
			rel, _ := filepath.Rel(root, proj.Path)
			action := fixer.Action{
				LockfilePath: proj.LockfilePath,
				ProjectDir:   proj.Path,
				PackageName:  g.PackageName,
				OldVersion:   g.OldVersion,
				FixedIn:      g.FixedIn,
			}

			result := fixer.Apply(action, sessionDir)

			mu.Lock()
			if result.Backup.BackupPath != "" {
				manifest.Entries = append(manifest.Entries, result.Backup)
			}
			mu.Unlock()

			if result.Err != nil {
				fmt.Fprintf(w, "  %s %s: %s\n",
					errStyle.Render("✗"),
					mutedFixStyle.Render(rel),
					errStyle.Render(result.Err.Error()),
				)
				continue
			}

			// --run-tests: execute test command, rollback on failure.
			if flags.runTests != "" {
				fmt.Fprintf(w, "  %s %s  ", successStyle.Render("✓"), mutedFixStyle.Render(rel))
				fmt.Fprintf(w, "%s\n", mutedFixStyle.Render("→ running tests…"))
				parts := strings.Fields(flags.runTests)
				tc := exec.Command(parts[0], parts[1:]...)
				tc.Dir = proj.Path
				if out, terr := tc.CombinedOutput(); terr != nil {
					fmt.Fprintf(w, "  %s tests failed — rolling back %s\n", errStyle.Render("✗"), mutedFixStyle.Render(rel))
					if len(strings.TrimSpace(string(out))) > 0 {
						fmt.Fprintf(w, "      %s\n", mutedFixStyle.Render(strings.TrimSpace(string(out))))
					}
					_ = fixer.Rollback(&fixer.Manifest{Entries: []fixer.Entry{result.Backup}})
					// Remove from manifest so --rollback doesn't try again.
					result.Backup = fixer.Entry{}
				} else {
					fmt.Fprintf(w, "  %s %s  %s\n",
						successStyle.Render("✓"),
						mutedFixStyle.Render(rel),
						successStyle.Render("tests passed"),
					)
				}
			} else {
				fmt.Fprintf(w, "  %s %s\n",
					successStyle.Render("✓"),
					mutedFixStyle.Render(rel),
				)
			}
		}
	}

	// Save manifest even if some fixes failed — partial rollback is still useful.
	if len(manifest.Entries) > 0 {
		if err := fixer.SaveManifest(sessionDir, manifest); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: could not save rollback manifest:", err)
		} else {
			fmt.Fprintln(w)
			fmt.Fprintln(w, mutedFixStyle.Render(
				fmt.Sprintf("Backup saved. Run `nazar fix --rollback %s` to undo.", root),
			))
		}
	}
	return nil
}

// ── doRollback ────────────────────────────────────────────────────────────────

func doRollback(cmd *cobra.Command, root string, flags *fixFlags) error {
	backupRoot := backupRootDir(flags.cacheDir)
	m, sessionDir, err := fixer.LoadLatestManifest(backupRoot)
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Rolling back session from %s (%d file(s))…\n",
		m.Timestamp.Local().Format("2006-01-02 15:04:05"),
		len(m.Entries),
	)

	if err := fixer.Rollback(m); err != nil {
		return fmt.Errorf("rollback: %w", err)
	}

	// Remove the session directory so --rollback isn't accidentally repeated.
	_ = os.RemoveAll(sessionDir)

	fmt.Fprintln(w, successStyle.Render("✓ Rollback complete."))
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// buildResults is the shared scan→enrich pipeline used by both scan and fix.
func buildResults(
	parsedProjects []parsedProject,
	vulnsByCoord map[osv.Coordinate][]osv.Vuln,
	detailsByID map[string]*osv.VulnDetail,
	flags *scanFlags,
) []report.Result {
	results := make([]report.Result, 0, len(parsedProjects))
	for _, pp := range parsedProjects {
		pvs := make([]report.PackageVulns, 0, len(pp.packages))
		for _, pkg := range pp.packages {
			pv := report.PackageVulns{Package: pkg}
			raw := vulnsByCoord[osv.Coordinate{
				Ecosystem: string(pp.project.Ecosystem),
				Name:      pkg.Name,
				Version:   pkg.Version,
			}]
			for _, v := range raw {
				if d, ok := detailsByID[v.ID]; ok {
					v.Severity = osv.DeriveSeverity(d)
					if d != nil {
						v.Summary = d.Summary
						v.FixedIn = osv.DeriveFixedVersion(d, string(pp.project.Ecosystem), pkg.Name)
					}
				}
				pv.Vulns = append(pv.Vulns, v)
			}
			pvs = append(pvs, pv)
		}
		results = append(results, report.Result{Project: pp.project, Packages: pvs})
	}
	return results
}

func backupRootDir(cacheDir string) string {
	if cacheDir != "" {
		return filepath.Join(cacheDir, "fix-backups")
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "nazar", "fix-backups")
	}
	return filepath.Join(base, "nazar", "fix-backups")
}

func styleForSev(s osv.Severity) lipgloss.Style {
	switch s {
	case osv.SeverityCritical:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	case osv.SeverityHigh:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	case osv.SeverityMedium:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	}
}
