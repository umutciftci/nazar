package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/osv"
)

// newCICmd builds the `nazar ci [path]` subcommand.
//
// It is a thin wrapper around runScan with CI-friendly defaults:
//   - scans the current directory when no path is given
//   - exits 2 when any HIGH or above vulnerability is found (--fail-on high)
//   - brief output (--quiet) — one summary line to stdout, progress to stderr
//   - progress and warnings still go to stderr so CI log parsers can distinguish
//
// All scan flags are available via long form if the defaults need overriding.
func newCICmd() *cobra.Command {
	flags := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "ci [path]",
		Short: "Scan in CI mode with safe defaults (exit 2 on HIGH+ vulns)",
		Long: "CI scans the given directory (default: current working directory) and exits\n" +
			"with code 2 when vulnerabilities at or above the --fail-on threshold are found.\n\n" +
			"Default behaviour:\n" +
			"  --fail-on high   exit 2 when any HIGH or CRITICAL vuln is found\n" +
			"  --quiet          print only the one-line summary (no table or detail)\n\n" +
			"Override as needed:\n" +
			"  nazar ci . --fail-on critical --severity medium\n" +
			"  nazar ci . --json > results.json\n" +
			"  nazar ci . --markdown --output-file nazar.md\n" +
			"  nazar ci . --sarif --output-file nazar.sarif\n\n" +
			"For GitHub Actions, pipe SARIF to the Security tab:\n" +
			"  nazar ci . --sarif --output-file nazar.sarif\n" +
			"  # then: upload-artifact / code-scanning-action\n\n" +
			"Exit codes: 0 = clean, 1 = error, 2 = vulnerabilities found.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			} else {
				// No path arg: try to use the working directory.
				cwd, err := os.Getwd()
				if err == nil {
					target = cwd
				}
			}

			// Apply CI defaults for flags that weren't explicitly set.
			if flags.failOn == "" {
				flags.failOn = string(osv.SeverityHigh)
			}
			// In CI, quiet is the right default unless the caller asked for a
			// specific output format (json/sarif/csv/markdown all have their own
			// terseness).
			if !flags.jsonOutput && !flags.sarifOutput && !flags.csvOutput && !flags.markdownOutput {
				flags.quiet = true
			}

			return runScan(cmd, []string{target}, flags)
		},
	}

	// Expose the same flags as scan so CI users can customise without switching commands.
	cmd.Flags().StringVar(&flags.failOn, "fail-on", "", "exit 2 if any vuln at or above this severity is found (default: high)")
	cmd.Flags().StringVar(&flags.minSeverity, "severity", "", "filter vuln detail (critical|high|medium|low)")
	cmd.Flags().BoolVar(&flags.jsonOutput, "json", false, "emit JSON instead of a summary line")
	cmd.Flags().BoolVar(&flags.sarifOutput, "sarif", false, "emit SARIF 2.1.0 JSON (for GitHub/GitLab security tabs)")
	cmd.Flags().BoolVar(&flags.csvOutput, "csv", false, "emit CSV (one row per vulnerability)")
	cmd.Flags().BoolVar(&flags.markdownOutput, "markdown", false, "emit GitHub-flavoured Markdown")
	cmd.Flags().StringVarP(&flags.outputFile, "output-file", "o", "", "write output to this file instead of stdout")
	cmd.Flags().BoolVar(&flags.noCache, "no-cache", false, "ignore the OSV cache and force fresh lookups")
	cmd.Flags().BoolVar(&flags.noSeverity, "no-severity", false, "skip per-vuln severity fetch (faster)")
	cmd.Flags().StringVar(&flags.ecosystem, "ecosystem", "", "filter to one ecosystem: npm|pypi|go|cargo|rubygems|packagist|nuget")
	cmd.Flags().StringSliceVar(&flags.excludeDirs, "exclude", nil, "extra directory names to skip during scan (repeatable)")
	cmd.Flags().StringVar(&flags.cacheDir, "cache-dir", "", "override the OSV cache directory")
	cmd.Flags().StringVar(&flags.osvBaseURL, "osv-url", osv.DefaultBaseURL, "OSV API base URL")
	cmd.Flags().DurationVar(&flags.osvTimeout, "osv-timeout", 90*time.Second, "overall timeout for the OSV lookup phase")
	cmd.Flags().IntVar(&flags.severityWorkers, "severity-workers", 8, "parallel workers for severity fetch")
	cmd.Flags().StringVar(&flags.ignoreFile, "ignore-file", "", "path to a .nazarignore file")
	cmd.Flags().StringSliceVar(&flags.ignoreInline, "ignore", nil, "inline suppression rule (repeatable)")
	cmd.Flags().BoolVar(&flags.detail, "detail", false, "show vulnerable package list (implied by --json)")
	cmd.Flags().StringVar(&flags.webhook, "webhook", "", "POST scan summary to this URL (Slack-compatible)")

	return cmd
}

// ciSummaryLine builds the single-line CI summary printed by `nazar ci`.
func ciSummaryLine(root string, projects, vulns int, failOnSev osv.Severity, clean bool) string {
	if clean {
		return fmt.Sprintf("✓ nazar: 0 vulnerabilities found in %d project(s) under %s", projects, root)
	}
	return fmt.Sprintf("✗ nazar: %d vulnerabilities found in %d project(s) under %s [fail-on: %s]",
		vulns, projects, root, failOnSev)
}
