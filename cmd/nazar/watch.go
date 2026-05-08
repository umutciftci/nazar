package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/history"
	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/report"
	"github.com/umutciftci/nazar/internal/scanner"
)

func newWatchCmd() *cobra.Command {
	var (
		interval        time.Duration
		cacheDir        string
		osvBaseURL      string
		osvTimeout      time.Duration
		severityWorkers int
		minSeverity     string
		notify          bool
		excludeDirs     []string
	)

	cmd := &cobra.Command{
		Use:   "watch <path>",
		Short: "Continuously scan and alert on new vulnerabilities",
		Long: "Watch rescans the directory on the given interval and prints an alert\n" +
			"whenever new vulnerabilities appear. Ctrl-C to stop.\n\n" +
			"Results are compared against the previous scan, so only changes are shown.\n" +
			"The first run establishes the baseline.\n\n" +
			"Use --notify to also send an OS desktop notification when new vulns are found\n" +
			"(macOS: uses osascript; Linux: uses notify-send if available).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := &scanFlags{
				cacheDir:        cacheDir,
				osvBaseURL:      osvBaseURL,
				osvTimeout:      osvTimeout,
				severityWorkers: severityWorkers,
				noCache:         true, // always fresh in watch mode
				excludeDirs:     excludeDirs,
			}
			sev, err := parseSeverityFlag("--severity", minSeverity)
			if err != nil {
				return err
			}
			return runWatch(cmd, args[0], interval, sev, notify, flags)
		},
	}

	cmd.Flags().DurationVar(&interval, "interval", 6*time.Hour, "how often to re-scan (e.g. 30m, 1h, 6h)")
	cmd.Flags().StringVar(&minSeverity, "severity", "high", "only alert on vulns at or above this level (critical|high|medium|low)")
	cmd.Flags().BoolVar(&notify, "notify", false, "send an OS desktop notification when new vulnerabilities are found")
	cmd.Flags().StringSliceVar(&excludeDirs, "exclude", nil, "extra directory names to skip during scan (repeatable)")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "override the cache directory")
	cmd.Flags().StringVar(&osvBaseURL, "osv-url", osv.DefaultBaseURL, "OSV API base URL")
	cmd.Flags().DurationVar(&osvTimeout, "osv-timeout", 90*time.Second, "overall timeout for OSV lookup")
	cmd.Flags().IntVar(&severityWorkers, "severity-workers", 8, "parallel workers for severity fetch")
	return cmd
}

func runWatch(cmd *cobra.Command, target string, interval time.Duration, minSev osv.Severity, notify bool, flags *scanFlags) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w := cmd.OutOrStdout()
	histDir := history.HistoryDir(flags.cacheDir)

	alertStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	cleanStyle2 := lipgloss.NewStyle().Foreground(lipgloss.Color("46"))

	fmt.Fprintf(w, "%s  %s\n",
		headerStyle.Render("nazar 🧿 — watch"),
		mutedStyle.Render(fmt.Sprintf("scanning %s every %s  (Ctrl-C to stop)", abs, interval)),
	)
	fmt.Fprintln(w)

	tick := time.NewTicker(interval)
	defer tick.Stop()

	// Run immediately on start.
	runWatchCycle(ctx, cmd, abs, histDir, minSev, notify, flags, alertStyle, cleanStyle2)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(w, mutedStyle.Render("\nWatch stopped."))
			return nil
		case t := <-tick.C:
			fmt.Fprintf(w, "\n%s\n", mutedStyle.Render("── "+t.Format("2006-01-02 15:04:05")+" ──────────────"))
			runWatchCycle(ctx, cmd, abs, histDir, minSev, notify, flags, alertStyle, cleanStyle2)
		}
	}
}

func runWatchCycle(
	ctx context.Context,
	cmd *cobra.Command,
	abs, histDir string,
	minSev osv.Severity,
	notify bool,
	flags *scanFlags,
	alertStyle, cleanStyle lipgloss.Style,
) {
	w := cmd.OutOrStdout()
	ts := time.Now().Format("15:04:05")

	// Load previous snapshot before scanning.
	prev, _ := history.Load(abs, histDir)

	// Scan.
	projects, err := scanner.ScanWithOptions(abs, scanner.Options{ExcludeDirs: flags.excludeDirs})
	if err != nil {
		fmt.Fprintf(w, "%s  scan error: %v\n", mutedStyle.Render(ts), err)
		return
	}
	parsedProjects, parseErrs := parseProjectsConcurrent(projects)
	for _, e := range parseErrs {
		fmt.Fprintf(w, "%s  parse warning: %v\n", mutedStyle.Render(ts), e)
	}
	coords := dedupCoords(parsedProjects)

	vulnsByCoord, osvErr := lookupOSV(ctx, coords, flags)
	if osvErr != nil {
		fmt.Fprintf(w, "%s  OSV warning: %v\n", mutedStyle.Render(ts), osvErr)
	}
	ids := uniqueVulnIDs(vulnsByCoord)
	detailsByID := map[string]*osv.VulnDetail{}
	if len(ids) > 0 {
		details, sevErr := fetchSeverity(ctx, ids, flags, nil)
		if sevErr != nil {
			fmt.Fprintf(w, "%s  severity warning: %v\n", mutedStyle.Render(ts), sevErr)
		}
		for id, d := range details {
			detailsByID[id] = d
		}
	}

	results := buildResults(parsedProjects, vulnsByCoord, detailsByID, flags)
	curr := history.FromResults(abs, results)
	diff := history.Compare(prev, curr)

	// Filter new items by severity threshold.
	var filtered []history.Item
	for _, it := range diff.New {
		if minSev == "" || it.Severity.Rank() >= minSev.Rank() {
			filtered = append(filtered, it)
		}
	}

	if len(filtered) == 0 {
		totals := countTotals(results)
		fmt.Fprintf(w, "%s  %s  %s\n",
			mutedStyle.Render(ts),
			cleanStyle.Render("✓ no new vulns"),
			mutedStyle.Render(fmt.Sprintf("(%d total)", totals)),
		)
	} else {
		fmt.Fprintf(w, "%s  %s\n",
			mutedStyle.Render(ts),
			alertStyle.Render(fmt.Sprintf("⚠  %d NEW vulnerability/vulnerabilities!", len(filtered))),
		)
		for _, it := range filtered {
			rel, _ := filepath.Rel(abs, it.Project)
			if rel == "." {
				rel = "(root)"
			}
			fix := ""
			if it.FixedIn != "" {
				fix = "  " + mutedStyle.Render("→"+it.FixedIn)
			}
			fmt.Fprintf(w, "       %s  %s  %s%s  %s\n",
				styleForSev(it.Severity).Render(fmt.Sprintf("[%s]", string(it.Severity))),
				lipgloss.NewStyle().Bold(true).Render(it.Package+"@"+it.Version),
				lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Render(it.VulnID),
				fix,
				mutedStyle.Render(rel),
			)
		}
		if notify {
			sendDesktopNotification("nazar — new vulnerabilities",
				fmt.Sprintf("%d new vuln(s) found in %s", len(filtered), filepath.Base(abs)))
		}
	}

	_ = history.Save(curr, histDir)
}

// sendDesktopNotification fires a best-effort OS desktop notification.
// It uses osascript on macOS and notify-send on Linux.
// Errors are silently ignored — notifications are informational, not critical.
func sendDesktopNotification(title, body string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(
			`display notification %q with title %q sound name "Basso"`,
			body, title,
		)
		cmd = exec.Command("osascript", "-e", script)
	case "linux":
		cmd = exec.Command("notify-send", "-u", "critical", title, body)
	default:
		return
	}
	_ = cmd.Run()
}

func countTotals(results []report.Result) int {
	n := 0
	for _, r := range results {
		for _, pv := range r.Packages {
			n += len(pv.Vulns)
		}
	}
	return n
}
