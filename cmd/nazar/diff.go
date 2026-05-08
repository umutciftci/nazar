package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/history"
	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/scanner"
)

func newDiffCmd() *cobra.Command {
	var (
		cacheDir        string
		osvBaseURL      string
		osvTimeout      time.Duration
		severityWorkers int
		excludeDirs     []string
	)

	cmd := &cobra.Command{
		Use:   "diff <path>",
		Short: "Show what changed since the last scan",
		Long: "Diff compares the current scan against the last saved snapshot and shows\n" +
			"new and resolved vulnerabilities.\n\n" +
			"nazar scan saves a snapshot automatically after every run.\n" +
			"Run `nazar scan <path>` first if no history exists yet.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := &scanFlags{
				cacheDir:        cacheDir,
				osvBaseURL:      osvBaseURL,
				osvTimeout:      osvTimeout,
				severityWorkers: severityWorkers,
				excludeDirs:     excludeDirs,
			}
			return runDiff(cmd, args[0], flags)
		},
	}
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "override the cache directory")
	cmd.Flags().StringVar(&osvBaseURL, "osv-url", osv.DefaultBaseURL, "OSV API base URL")
	cmd.Flags().DurationVar(&osvTimeout, "osv-timeout", 90*time.Second, "overall timeout for OSV lookup")
	cmd.Flags().IntVar(&severityWorkers, "severity-workers", 8, "parallel workers for severity fetch")
	cmd.Flags().StringSliceVar(&excludeDirs, "exclude", nil, "extra directory names to skip during scan (repeatable)")
	return cmd
}

func runDiff(cmd *cobra.Command, target string, flags *scanFlags) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	histDir := history.HistoryDir(flags.cacheDir)
	prev, err := history.Load(abs, histDir)
	if err != nil {
		return fmt.Errorf("load history: %w", err)
	}

	w := cmd.OutOrStdout()

	if prev == nil {
		fmt.Fprintln(w, mutedStyle.Render("No previous scan found for this path."))
		fmt.Fprintln(w, mutedStyle.Render("Run `nazar scan "+target+"` to create a baseline."))
		return nil
	}

	// ── Fresh scan ────────────────────────────────────────────────────────────

	fmt.Fprintln(cmd.ErrOrStderr(), " → scanning filesystem…")
	projects, err := scanner.ScanWithOptions(abs, scanner.Options{ExcludeDirs: flags.excludeDirs})
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	parsedProjects, parseErrs := parseProjectsConcurrent(projects)
	for _, e := range parseErrs {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning:", e)
	}

	coords := dedupCoords(parsedProjects)
	vulnsByCoord, osvErr := lookupOSV(cmd.Context(), coords, flags)
	if osvErr != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: OSV lookup failed:", osvErr)
	}

	ids := uniqueVulnIDs(vulnsByCoord)
	detailsByID := map[string]*osv.VulnDetail{}
	if len(ids) > 0 {
		cached := countCachedDetails(ids, flags)
		if len(ids)-cached > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), " → fetching severity + fix info (%d CVEs, %d cached)…\n", len(ids), cached)
		}
		details, sevErr := fetchSeverity(cmd.Context(), ids, flags, nil)
		if sevErr != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: severity fetch had issues:", sevErr)
		}
		for id, d := range details {
			detailsByID[id] = d
		}
	}

	results := buildResults(parsedProjects, vulnsByCoord, detailsByID, flags)
	curr := history.FromResults(abs, results)
	diff := history.Compare(prev, curr)

	// ── Header ────────────────────────────────────────────────────────────────

	age := time.Since(prev.Timestamp)
	fmt.Fprintln(w, headerStyle.Render("nazar 🧿 — diff"))
	fmt.Fprintln(w, mutedStyle.Render(fmt.Sprintf("now vs %s ago  (%s)",
		formatAge(age), prev.Timestamp.Local().Format("2006-01-02 15:04"))))
	fmt.Fprintln(w)

	if len(diff.New) == 0 && len(diff.Resolved) == 0 {
		fmt.Fprintln(w, lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true).Render(
			fmt.Sprintf("✓ No changes — %d vulnerabilities unchanged.", len(curr.Items)),
		))
		_ = history.Save(curr, histDir)
		return nil
	}

	// ── New ───────────────────────────────────────────────────────────────────

	if len(diff.New) > 0 {
		sort.Slice(diff.New, func(i, j int) bool {
			if diff.New[i].Severity.Rank() != diff.New[j].Severity.Rank() {
				return diff.New[i].Severity.Rank() > diff.New[j].Severity.Rank()
			}
			return diff.New[i].Package < diff.New[j].Package
		})
		fmt.Fprintf(w, "%s  %s\n",
			lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true).Render("NEW"),
			mutedStyle.Render(fmt.Sprintf("(%d)", len(diff.New))),
		)
		for _, it := range diff.New {
			rel, _ := filepath.Rel(abs, it.Project)
			if rel == "." {
				rel = "(root)"
			}
			fix := ""
			if it.FixedIn != "" {
				fix = "  " + mutedStyle.Render("→"+it.FixedIn)
			}
			fmt.Fprintf(w, "  %s  %-30s  %s%s  %s\n",
				styleForSev(it.Severity).Render(fmt.Sprintf("[%-8s]", string(it.Severity))),
				lipgloss.NewStyle().Bold(true).Render(it.Package+"@"+it.Version),
				lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Render(it.VulnID),
				fix,
				mutedStyle.Render(rel),
			)
		}
		fmt.Fprintln(w)
	}

	// ── Resolved ──────────────────────────────────────────────────────────────

	if len(diff.Resolved) > 0 {
		sort.Slice(diff.Resolved, func(i, j int) bool {
			return diff.Resolved[i].Package < diff.Resolved[j].Package
		})
		fmt.Fprintf(w, "%s  %s\n",
			lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true).Render("RESOLVED"),
			mutedStyle.Render(fmt.Sprintf("(%d)", len(diff.Resolved))),
		)
		for _, it := range diff.Resolved {
			rel, _ := filepath.Rel(abs, it.Project)
			if rel == "." {
				rel = "(root)"
			}
			fmt.Fprintf(w, "  %s  %-30s  %s  %s\n",
				styleForSev(it.Severity).Render(fmt.Sprintf("[%-8s]", string(it.Severity))),
				lipgloss.NewStyle().Bold(true).Render(it.Package+"@"+it.Version),
				lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Render(it.VulnID),
				mutedStyle.Render(rel),
			)
		}
		fmt.Fprintln(w)
	}

	unchanged := len(curr.Items) - len(diff.New)
	if unchanged < 0 {
		unchanged = 0
	}
	fmt.Fprintln(w, mutedStyle.Render(fmt.Sprintf(
		"%d new  /  %d resolved  /  %d unchanged",
		len(diff.New), len(diff.Resolved), unchanged,
	)))

	_ = history.Save(curr, histDir)
	return nil
}

func formatAge(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}
