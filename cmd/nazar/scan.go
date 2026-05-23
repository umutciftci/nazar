package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/history"
	"github.com/umutciftci/nazar/internal/ignore"
	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/parser"
	"github.com/umutciftci/nazar/internal/report"
	"github.com/umutciftci/nazar/internal/scanner"
)

// scanFlags holds parsed flag values for the scan command.
type scanFlags struct {
	jsonOutput       bool
	sarifOutput      bool
	csvOutput        bool
	markdownOutput   bool
	htmlOutput       bool
	outputFile       string
	quiet            bool
	detail           bool
	projectFilter    string
	sortBy           string
	topN             int
	vulnOnly         bool
	groupByEcosystem bool
	ecosystem        string
	excludeDirs      []string
	since            string
	showNew          bool
	offline          bool
	noCache          bool
	noSeverity       bool
	cacheDir         string
	osvBaseURL       string
	osvTimeout       time.Duration
	severityWorkers  int
	ignoreFile       string
	ignoreInline     []string
	minSeverity      string
	failOn           string
	webhook          string
}

// errVulnsFound is returned by runScan when --fail-on is set and matching
// vulnerabilities are found. main() maps this to exit code 2.
type errVulnsFound struct {
	threshold osv.Severity
	count     int
}

func (e *errVulnsFound) Error() string {
	noun := "vulnerabilities"
	if e.count == 1 {
		noun = "vulnerability"
	}
	return fmt.Sprintf("%d %s at or above %s found (--fail-on triggered)", e.count, noun, e.threshold)
}

// newScanCmd builds the `nazar scan <path>` subcommand.
func newScanCmd() *cobra.Command {
	flags := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "scan <path> [path...]",
		Short: "Scan one or more directories for vulnerable dependencies",
		Long: "Scan walks the given directory trees, finds every project in a supported " +
			"ecosystem (npm, PyPI, Go, Rust/crates.io), parses its lockfiles and queries " +
			"OSV.dev for known vulnerabilities.\n\n" +
			"Multiple paths are merged into a single report:\n" +
			"  nazar scan ~/Projects ~/Desktop ~/Work\n\n" +
			"This command is read-only: it never modifies the projects it scans.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args, flags)
		},
	}

	cmd.Flags().BoolVar(&flags.jsonOutput, "json", false, "emit machine-readable JSON instead of a table")
	cmd.Flags().BoolVar(&flags.sarifOutput, "sarif", false, "emit SARIF 2.1.0 JSON (for GitHub/GitLab security tabs)")
	cmd.Flags().BoolVar(&flags.csvOutput, "csv", false, "emit CSV (one row per vulnerability, for spreadsheets)")
	cmd.Flags().BoolVar(&flags.detail, "detail", false, "show vulnerable package list per project (default: summary table only)")
	cmd.Flags().StringVar(&flags.projectFilter, "project", "", "show detail only for projects whose path contains this substring")
	cmd.Flags().StringVar(&flags.sortBy, "sort", "worst", "sort table by: worst|crit|high|total|fixable|path")
	cmd.Flags().IntVar(&flags.topN, "top", 0, "show only the top N most-vulnerable projects (0 = show all)")
	cmd.Flags().BoolVar(&flags.vulnOnly, "vuln-only", false, "hide projects with zero vulnerabilities from the table")
	cmd.Flags().BoolVar(&flags.groupByEcosystem, "group-by-ecosystem", false, "group table rows by ecosystem with section headers")
	cmd.Flags().StringVar(&flags.ecosystem, "ecosystem", "", "filter to one ecosystem: npm|pypi|go|cargo")
	cmd.Flags().StringSliceVar(&flags.excludeDirs, "exclude", nil, "extra directory names to skip during scan (repeatable). E.g. --exclude testdata")
	cmd.Flags().StringVar(&flags.since, "since", "", "only show vulns published within this window (e.g. 7d, 30d, 1y)")
	cmd.Flags().BoolVar(&flags.offline, "offline", false, "skip OSV.dev lookup; only enumerate projects and packages")
	cmd.Flags().BoolVar(&flags.noCache, "no-cache", false, "ignore the OSV cache and force fresh lookups (results are still cached)")
	cmd.Flags().BoolVar(&flags.noSeverity, "no-severity", false, "skip the per-vulnerability severity fetch (faster, less detail)")
	cmd.Flags().StringVar(&flags.cacheDir, "cache-dir", "", "override the OSV cache directory (default: ~/.cache/nazar)")
	cmd.Flags().StringVar(&flags.osvBaseURL, "osv-url", osv.DefaultBaseURL, "OSV API base URL (only useful for testing/proxying)")
	cmd.Flags().DurationVar(&flags.osvTimeout, "osv-timeout", 90*time.Second, "overall timeout for the OSV lookup phase")
	cmd.Flags().IntVar(&flags.severityWorkers, "severity-workers", 8, "parallel HTTP workers for the severity fetch phase")
	cmd.Flags().StringVar(&flags.ignoreFile, "ignore-file", "", "path to a .nazarignore file (default: <scan-root>/.nazarignore if present)")
	cmd.Flags().StringSliceVar(&flags.ignoreInline, "ignore", nil, "vulnerability suppression rule (repeatable). Examples: GHSA-xxxx, lodash@4.17.20:GHSA-xxxx, lodash@*:CVE-2024-1234")
	cmd.Flags().StringVar(&flags.minSeverity, "severity", "", "filter vuln detail to this level and above (critical|high|medium|low)")
	cmd.Flags().StringVar(&flags.failOn, "fail-on", "", "exit 2 if any vuln at or above this severity is found (critical|high|medium|low)")
	cmd.Flags().StringVarP(&flags.outputFile, "output-file", "o", "", "write output to this file instead of stdout")
	cmd.Flags().BoolVarP(&flags.quiet, "quiet", "q", false, "print only the summary line (suppress table, hotspots, and detail)")
	cmd.Flags().BoolVar(&flags.markdownOutput, "markdown", false, "emit a GitHub-flavoured Markdown report")
	cmd.Flags().BoolVar(&flags.htmlOutput, "html", false, "emit a self-contained HTML report (open in any browser)")
	cmd.Flags().BoolVar(&flags.showNew, "new", false, "show only vulnerabilities not seen in the previous scan snapshot")
	cmd.Flags().StringVar(&flags.webhook, "webhook", "", "POST scan summary JSON to this URL after scan completes (Slack-compatible)")

	return cmd
}

// runScan validates the target paths and executes the full pipeline:
// scan → parse → OSV batch → severity+fix enrichment → ignore filter → render.
func runScan(cmd *cobra.Command, targets []string, flags *scanFlags) error {
	// Resolve and validate all paths up-front.
	absPaths := make([]string, 0, len(targets))
	for _, t := range targets {
		abs, err := filepath.Abs(t)
		if err != nil {
			return fmt.Errorf("resolve path %q: %w", t, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("path does not exist: %s", abs)
			}
			return fmt.Errorf("stat %s: %w", abs, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("path is not a directory: %s", abs)
		}
		absPaths = append(absPaths, abs)
	}

	// Display root: common ancestor of all paths (used for relative display).
	displayRoot := commonAncestor(absPaths)

	minSev, err := parseSeverityFlag("--severity", flags.minSeverity)
	if err != nil {
		return err
	}
	failOnSev, err := parseSeverityFlag("--fail-on", flags.failOn)
	if err != nil {
		return err
	}

	// Merge ignore rules from all roots.
	var ignoreSet *ignore.Set
	for _, abs := range absPaths {
		set, err := loadIgnoreSet(abs, flags)
		if err != nil {
			return fmt.Errorf("load ignore rules: %w", err)
		}
		ignoreSet = ignore.Merge(ignoreSet, set)
	}

	// Scan all paths, merge projects.
	logProgress(cmd, flags, "scanning filesystem…")
	var allProjects []scanner.Project
	var parseErrs []error
	for _, abs := range absPaths {
		ps, err := scanner.ScanWithOptions(abs, scanner.Options{ExcludeDirs: flags.excludeDirs})
		if err != nil {
			return fmt.Errorf("scan %s: %w", abs, err)
		}
		allProjects = append(allProjects, ps...)
	}
	// Deduplicate projects that appear in multiple roots (shouldn't happen, but safe).
	allProjects = deduplicateProjects(allProjects)

	parsed, errs := parseProjectsConcurrent(allProjects)
	parseErrs = append(parseErrs, errs...)

	// OSV phase.
	vulnsByCoord := map[osv.Coordinate][]osv.Vuln{}
	detailsByID := map[string]*osv.VulnDetail{}

	if !flags.offline {
		coords := dedupCoords(parsed)
		if len(coords) > 0 {
			logProgress(cmd, flags, fmt.Sprintf("querying OSV.dev (%d unique packages)…", len(coords)))
			batchOut, err := lookupOSV(cmd.Context(), coords, flags)
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: OSV lookup failed:", err)
			} else {
				vulnsByCoord = batchOut
			}
		}
		if !flags.noSeverity && len(vulnsByCoord) > 0 {
			ids := uniqueVulnIDs(vulnsByCoord)
			cached := countCachedDetails(ids, flags)
			uncached := len(ids) - cached
			if uncached > 0 {
				logProgress(cmd, flags, fmt.Sprintf("fetching severity + fix info (%d CVEs, %d cached)…", len(ids), cached))
			} else {
				logProgress(cmd, flags, fmt.Sprintf("severity + fix info (%d CVEs, all cached)…", len(ids)))
			}
			var onProgress osv.ProgressFunc
			if !flags.quiet && !flags.jsonOutput && !flags.sarifOutput && uncached > 0 {
				onProgress = makeProgressPrinter(cmd)
			}
			details, err := fetchSeverity(cmd.Context(), ids, flags, onProgress)
			// Ensure the inline progress counter doesn't bleed into the next line.
			if !flags.quiet && !flags.jsonOutput && !flags.sarifOutput && uncached > 0 {
				fmt.Fprintln(cmd.ErrOrStderr())
			}
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: severity fetch had issues:", err)
			}
			for id, d := range details {
				detailsByID[id] = d
			}
		}
	}

	// Stitch: per-project package list with vulns, enriched with severity,
	// summary, fix version, and ignore rules applied.
	results := buildResultsWithIgnore(parsed, vulnsByCoord, detailsByID, flags, ignoreSet)

	// --ecosystem filter: keep only matching projects.
	if flags.ecosystem != "" {
		lower := strings.ToLower(flags.ecosystem)
		filtered := results[:0]
		for _, r := range results {
			if strings.EqualFold(string(r.Project.Ecosystem), lower) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	// --since: filter to vulns published within the given window.
	if flags.since != "" {
		cutoff, err := parseSince(flags.since)
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		results = filterByPublished(results, detailsByID, cutoff)
		if !flags.jsonOutput && !flags.sarifOutput && !flags.csvOutput {
			fmt.Fprintf(cmd.ErrOrStderr(), " → --since %s: showing vulns published on or after %s\n",
				flags.since, cutoff.Format("2006-01-02"))
		}
	}

	// Load previous snapshot BEFORE saving the new one (required for --new).
	var prevSnapshot *history.Snapshot
	if flags.showNew {
		prevSnapshot, _ = history.Load(displayRoot, history.HistoryDir(flags.cacheDir))
	}

	// Persist snapshot (full current state) for nazar diff / watch / --new.
	// Must happen before the --new filter so the baseline is always the complete
	// current state, not the filtered view.
	if !flags.offline && !flags.jsonOutput && !flags.sarifOutput && !flags.csvOutput {
		snap := history.FromResults(displayRoot, results)
		_ = history.Save(snap, history.HistoryDir(flags.cacheDir))
	}

	// --new: keep only vulnerabilities absent from the previous snapshot.
	if flags.showNew {
		curr := history.FromResults(displayRoot, results)
		diff := history.Compare(prevSnapshot, curr)
		newSet := make(map[string]struct{}, len(diff.New))
		for _, it := range diff.New {
			// Key matches history.itemKey: project|package@version|vulnID
			newSet[it.Project+"|"+it.Package+"@"+it.Version+"|"+it.VulnID] = struct{}{}
		}
		results = filterToNewVulns(results, newSet)
		if !flags.jsonOutput && !flags.sarifOutput && !flags.csvOutput {
			newCount := 0
			for _, r := range results {
				for _, pv := range r.Packages {
					newCount += len(pv.Vulns)
				}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), " → --new: %d new vulnerability/vulnerabilities vs previous snapshot\n", newCount)
		}
	}

	opts := report.RenderOptions{
		MinSeverity:      minSev,
		ShowDetail:       flags.detail,
		ProjectFilter:    flags.projectFilter,
		SortBy:           flags.sortBy,
		TopN:             flags.topN,
		VulnOnly:         flags.vulnOnly,
		GroupByEcosystem: flags.groupByEcosystem,
		Quiet:            flags.quiet,
	}

	// Output writer: honour --output-file by writing to a file instead of stdout.
	outWriter := cmd.OutOrStdout()
	if flags.outputFile != "" {
		f, err := os.Create(flags.outputFile)
		if err != nil {
			return fmt.Errorf("open output file %q: %w", flags.outputFile, err)
		}
		defer f.Close() //nolint:errcheck
		outWriter = f
	}

	switch {
	case flags.sarifOutput:
		if err := report.RenderSARIF(outWriter, displayRoot, results, version); err != nil {
			return fmt.Errorf("render sarif: %w", err)
		}
	case flags.csvOutput:
		if err := report.RenderCSV(outWriter, displayRoot, results); err != nil {
			return fmt.Errorf("render csv: %w", err)
		}
	case flags.jsonOutput:
		if err := report.RenderJSON(outWriter, displayRoot, flags.offline, results, opts); err != nil {
			return fmt.Errorf("render json: %w", err)
		}
	case flags.markdownOutput:
		report.RenderMarkdown(outWriter, displayRoot, flags.offline, results, opts)
	case flags.htmlOutput:
		if err := report.RenderHTML(outWriter, displayRoot, flags.offline, results, opts); err != nil {
			return fmt.Errorf("render html: %w", err)
		}
	default:
		report.RenderText(outWriter, displayRoot, flags.offline, results, opts)
	}

	if len(parseErrs) > 0 {
		fmt.Fprintln(cmd.ErrOrStderr())
		fmt.Fprintln(cmd.ErrOrStderr(), "Warnings:")
		for _, e := range parseErrs {
			fmt.Fprintln(cmd.ErrOrStderr(), "  -", e)
		}
	}

	// --webhook: POST scan summary (best-effort; errors are warnings only).
	if flags.webhook != "" {
		if err := sendWebhook(flags.webhook, displayRoot, results); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: webhook delivery failed:", err)
		}
	}

	// --fail-on: exit 2 if any vuln at or above the threshold is found.
	if failOnSev != "" {
		count := 0
		for _, r := range results {
			for _, pv := range r.Packages {
				for _, v := range pv.Vulns {
					if v.Severity.Rank() >= failOnSev.Rank() && v.Severity != osv.SeverityUnknown {
						count++
					}
				}
			}
		}
		if count > 0 {
			return &errVulnsFound{threshold: failOnSev, count: count}
		}
	}

	return nil
}

// logProgress writes a status line to stderr (suppressed for machine-readable output).
func logProgress(cmd *cobra.Command, flags *scanFlags, msg string) {
	if flags.quiet || flags.jsonOutput || flags.sarifOutput || flags.csvOutput {
		return
	}
	fmt.Fprintln(cmd.ErrOrStderr(), " →", msg)
}

// makeProgressPrinter returns a ProgressFunc that prints an inline counter to
// stderr during the severity fetch phase. The total comes from the callback
// itself (len(misses) inside FetchDetails) so it accurately reflects only
// the IDs that actually need a network round-trip.
func makeProgressPrinter(cmd *cobra.Command) osv.ProgressFunc {
	return func(done, total int) {
		fmt.Fprintf(cmd.ErrOrStderr(), "\r    %d/%d", done, total)
	}
}

// countCachedDetails returns how many of ids are already in the detail cache.
func countCachedDetails(ids []string, flags *scanFlags) int {
	cache, err := osv.NewDetailCache(detailCacheDir(flags.cacheDir), osv.DefaultDetailTTL)
	if err != nil {
		return 0
	}
	n := 0
	for _, id := range ids {
		if _, hit := cache.Get(id); hit {
			n++
		}
	}
	return n
}

// parseProjectsConcurrent parses all projects' lockfiles in parallel.
// Results are sorted by project path for deterministic output.
func parseProjectsConcurrent(projects []scanner.Project) ([]parsedProject, []error) {
	type result struct {
		pp  parsedProject
		err error
	}

	ch := make(chan result, len(projects))
	var wg sync.WaitGroup
	wg.Add(len(projects))
	for _, p := range projects {
		p := p
		go func() {
			defer wg.Done()
			pkgs, err := parseProject(p)
			if err != nil {
				ch <- result{err: fmt.Errorf("%s: %w", p.Path, err)}
				return
			}
			ch <- result{pp: parsedProject{project: p, packages: pkgs}}
		}()
	}
	wg.Wait()
	close(ch)

	var parsed []parsedProject
	var errs []error
	for r := range ch {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		parsed = append(parsed, r.pp)
	}
	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].project.Path < parsed[j].project.Path
	})
	return parsed, errs
}

// parseProject dispatches lockfile parsing to the right parser by ecosystem
// and lockfile filename.
func parseProject(p scanner.Project) ([]parser.Package, error) {
	switch p.Ecosystem {
	case scanner.EcosystemNPM:
		return parseNPMLockfile(p.LockfilePath)
	case scanner.EcosystemPyPI:
		return parser.ParsePythonLockfile(p.LockfilePath)
	case scanner.EcosystemGo:
		return parser.ParseGoSum(p.LockfilePath)
	case scanner.EcosystemCratesIO:
		return parser.ParseCargoLock(p.LockfilePath)
	case scanner.EcosystemRubyGems:
		return parser.ParseGemfileLock(p.LockfilePath)
	case scanner.EcosystemPackagist:
		return parser.ParseComposerLock(p.LockfilePath)
	case scanner.EcosystemNuGet:
		return parser.ParseDotnetPackagesLock(p.LockfilePath)
	default:
		return nil, fmt.Errorf("unsupported ecosystem %q", p.Ecosystem)
	}
}

// parseNPMLockfile dispatches npm-family lockfiles by filename.
func parseNPMLockfile(path string) ([]parser.Package, error) {
	switch filepath.Base(path) {
	case "package-lock.json":
		return parser.ParseNPMLockfile(path)
	case "yarn.lock":
		return parser.ParseYarnLock(path)
	case "pnpm-lock.yaml":
		return parser.ParsePnpmLock(path)
	default:
		return nil, fmt.Errorf("unrecognised npm lockfile: %s", filepath.Base(path))
	}
}

// parseSeverityFlag validates a --severity / --fail-on string into a Severity.
func parseSeverityFlag(flag, val string) (osv.Severity, error) {
	if val == "" {
		return "", nil
	}
	s := osv.Severity(strings.ToUpper(val))
	switch s {
	case osv.SeverityCritical, osv.SeverityHigh, osv.SeverityMedium, osv.SeverityLow:
		return s, nil
	default:
		return "", fmt.Errorf("%s: invalid severity %q — must be one of critical, high, medium, low", flag, val)
	}
}

// loadIgnoreSet merges the file-based ignore set with any inline --ignore rules.
func loadIgnoreSet(root string, flags *scanFlags) (*ignore.Set, error) {
	path := flags.ignoreFile
	if path == "" {
		path = filepath.Join(root, ".nazarignore")
	}
	fileSet, err := ignore.LoadFile(path)
	if err != nil {
		return nil, err
	}
	inlineSet, err := ignore.ParseRules(flags.ignoreInline)
	if err != nil {
		return nil, fmt.Errorf("--ignore: %w", err)
	}
	return ignore.Merge(fileSet, inlineSet), nil
}

// buildResultsWithIgnore stitches parsed projects with OSV data, applies
// severity/summary/fixedIn enrichment, and filters out ignored vulns.
func buildResultsWithIgnore(
	parsedProjects []parsedProject,
	vulnsByCoord map[osv.Coordinate][]osv.Vuln,
	detailsByID map[string]*osv.VulnDetail,
	flags *scanFlags,
	ignoreSet interface {
		Match(name, version, id string) bool
	},
) []report.Result {
	results := make([]report.Result, 0, len(parsedProjects))
	for _, pp := range parsedProjects {
		pvs := make([]report.PackageVulns, 0, len(pp.packages))
		ignored := 0
		for _, pkg := range pp.packages {
			pv := report.PackageVulns{Package: pkg}
			if !flags.offline {
				raw := vulnsByCoord[osv.Coordinate{
					Ecosystem: string(pp.project.Ecosystem),
					Name:      pkg.Name,
					Version:   pkg.Version,
				}]
				for _, v := range raw {
					if ignoreSet.Match(pkg.Name, pkg.Version, v.ID) {
						ignored++
						continue
					}
					if d, ok := detailsByID[v.ID]; ok {
						v.Severity = osv.DeriveSeverity(d)
						if d != nil {
							v.Summary = d.Summary
							v.FixedIn = osv.DeriveFixedVersion(d, string(pp.project.Ecosystem), pkg.Name)
						}
					}
					pv.Vulns = append(pv.Vulns, v)
				}
			}
			pvs = append(pvs, pv)
		}
		results = append(results, report.Result{
			Project:      pp.project,
			Packages:     pvs,
			IgnoredCount: ignored,
		})
	}
	return results
}

// parsedProject pairs a detected project with its parsed package list.
type parsedProject struct {
	project  scanner.Project
	packages []parser.Package
}

// dedupCoords flattens parsed projects into a unique slice of coordinates.
func dedupCoords(parsed []parsedProject) []osv.Coordinate {
	seen := make(map[osv.Coordinate]struct{})
	var out []osv.Coordinate
	for _, pp := range parsed {
		eco := string(pp.project.Ecosystem)
		for _, pkg := range pp.packages {
			c := osv.Coordinate{Ecosystem: eco, Name: pkg.Name, Version: pkg.Version}
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	return out
}

// uniqueVulnIDs collects every distinct vuln ID across all batch results.
func uniqueVulnIDs(byCoord map[osv.Coordinate][]osv.Vuln) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, vs := range byCoord {
		for _, v := range vs {
			if _, ok := seen[v.ID]; ok {
				continue
			}
			seen[v.ID] = struct{}{}
			out = append(out, v.ID)
		}
	}
	return out
}

// lookupOSV runs the coordinate batch lookup against OSV.
func lookupOSV(parent context.Context, coords []osv.Coordinate, flags *scanFlags) (map[osv.Coordinate][]osv.Vuln, error) {
	ctx, cancel := setupContext(parent, flags.osvTimeout)
	defer cancel()

	cache, err := osv.NewCache(coordCacheDir(flags.cacheDir), osv.DefaultTTL)
	if err != nil {
		return nil, fmt.Errorf("init coord cache: %w", err)
	}
	client := osv.NewClient(
		osv.WithBaseURL(flags.osvBaseURL),
		osv.WithUserAgent("nazar/"+version),
	)
	return osv.Lookup(ctx, client, cache, coords, flags.noCache)
}

// fetchSeverity runs the per-ID detail fetch with optional progress reporting.
func fetchSeverity(parent context.Context, ids []string, flags *scanFlags, progress osv.ProgressFunc) (map[string]*osv.VulnDetail, error) {
	ctx, cancel := setupContext(parent, flags.osvTimeout)
	defer cancel()

	cache, err := osv.NewDetailCache(detailCacheDir(flags.cacheDir), osv.DefaultDetailTTL)
	if err != nil {
		return nil, fmt.Errorf("init detail cache: %w", err)
	}
	client := osv.NewClient(
		osv.WithBaseURL(flags.osvBaseURL),
		osv.WithUserAgent("nazar/"+version),
	)
	return osv.FetchDetails(ctx, client, cache, ids, flags.noCache, flags.severityWorkers, progress)
}

// setupContext applies the user's timeout and a SIGINT/SIGTERM trap.
func setupContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, timeoutCancel := context.WithTimeout(parent, timeout)
	ctx, signalStop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	return ctx, func() {
		signalStop()
		timeoutCancel()
	}
}

func coordCacheDir(override string) string {
	if override == "" {
		return ""
	}
	return filepath.Join(override, "osv")
}

func detailCacheDir(override string) string {
	if override == "" {
		return ""
	}
	return filepath.Join(override, "vulns")
}

// commonAncestor returns the longest common directory ancestor of all paths.
// With a single path it returns that path unchanged.
func commonAncestor(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	if len(paths) == 1 {
		return paths[0]
	}
	sep := string(filepath.Separator)
	parts := strings.Split(filepath.Clean(paths[0]), sep)
	for _, p := range paths[1:] {
		pp := strings.Split(filepath.Clean(p), sep)
		maxLen := len(parts)
		if len(pp) < maxLen {
			maxLen = len(pp)
		}
		match := 0
		for i := 0; i < maxLen; i++ {
			if parts[i] == pp[i] {
				match = i + 1
			} else {
				break
			}
		}
		parts = parts[:match]
	}
	if len(parts) == 0 {
		return sep
	}
	result := strings.Join(parts, sep)
	if result == "" {
		return sep
	}
	return result
}

// parseSince parses a human-friendly window like "7d", "30d", "1y", "2w"
// into a cutoff time.Time (now minus the window).
func parseSince(s string) (time.Time, error) {
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("expected a value like 7d, 30d, 1y, 2w")
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	n := 0
	if _, err := fmt.Sscanf(numStr, "%d", &n); err != nil || n <= 0 {
		return time.Time{}, fmt.Errorf("expected a positive integer before the unit (got %q)", numStr)
	}
	now := time.Now()
	switch unit {
	case 'd':
		return now.AddDate(0, 0, -n), nil
	case 'w':
		return now.AddDate(0, 0, -n*7), nil
	case 'm':
		return now.AddDate(0, -n, 0), nil
	case 'y':
		return now.AddDate(-n, 0, 0), nil
	default:
		return time.Time{}, fmt.Errorf("unknown unit %q; use d (days), w (weeks), m (months), y (years)", string(unit))
	}
}

// filterByPublished removes vulns from results where the published date is
// before cutoff. Projects with no matching vulns are kept with empty Packages
// so the table still shows them (vuln count 0).
func filterByPublished(results []report.Result, details map[string]*osv.VulnDetail, cutoff time.Time) []report.Result {
	out := make([]report.Result, 0, len(results))
	for _, r := range results {
		newPkgs := make([]report.PackageVulns, 0, len(r.Packages))
		for _, pv := range r.Packages {
			newVulns := pv.Vulns[:0]
			for _, v := range pv.Vulns {
				d, ok := details[v.ID]
				if !ok {
					// No detail available — keep it (don't silently drop).
					newVulns = append(newVulns, v)
					continue
				}
				pub := d.PublishedTime()
				if pub.IsZero() || !pub.Before(cutoff) {
					newVulns = append(newVulns, v)
				}
			}
			newPkgs = append(newPkgs, report.PackageVulns{
				Package: pv.Package,
				Vulns:   newVulns,
			})
		}
		out = append(out, report.Result{
			Project:      r.Project,
			Packages:     newPkgs,
			IgnoredCount: r.IgnoredCount,
		})
	}
	return out
}

// filterToNewVulns keeps only the vulnerabilities whose
// "project|package@version|vulnID" key exists in newSet.
// Projects with no matching vulns are kept in the result with empty Packages
// so the table still shows them with a zero count.
func filterToNewVulns(results []report.Result, newSet map[string]struct{}) []report.Result {
	out := make([]report.Result, 0, len(results))
	for _, r := range results {
		newPkgs := make([]report.PackageVulns, 0, len(r.Packages))
		for _, pv := range r.Packages {
			var keep []osv.Vuln
			for _, v := range pv.Vulns {
				k := r.Project.Path + "|" + pv.Package.Name + "@" + pv.Package.Version + "|" + v.ID
				if _, ok := newSet[k]; ok {
					keep = append(keep, v)
				}
			}
			newPkgs = append(newPkgs, report.PackageVulns{
				Package: pv.Package,
				Vulns:   keep,
			})
		}
		out = append(out, report.Result{
			Project:      r.Project,
			Packages:     newPkgs,
			IgnoredCount: r.IgnoredCount,
		})
	}
	return out
}

// deduplicateProjects removes projects with the same path (can occur when
// multiple scan roots overlap).
func deduplicateProjects(ps []scanner.Project) []scanner.Project {
	seen := make(map[string]struct{}, len(ps))
	out := ps[:0]
	for _, p := range ps {
		if _, ok := seen[p.Path]; ok {
			continue
		}
		seen[p.Path] = struct{}{}
		out = append(out, p)
	}
	return out
}
