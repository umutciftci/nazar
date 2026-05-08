package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/osv"
)

func newShowCmd() *cobra.Command {
	var (
		cacheDir   string
		osvBaseURL string
		noCache    bool
	)

	cmd := &cobra.Command{
		Use:   "show <CVE-ID|GHSA-ID>",
		Short: "Show detailed information about a vulnerability",
		Long:  "Show fetches and displays the full OSV record for a given CVE or GHSA ID.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShow(cmd, args[0], cacheDir, osvBaseURL, noCache)
		},
	}
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "override the cache directory")
	cmd.Flags().StringVar(&osvBaseURL, "osv-url", osv.DefaultBaseURL, "OSV API base URL")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "bypass cache and fetch fresh data")
	return cmd
}

func runShow(cmd *cobra.Command, id, cacheDir, osvBaseURL string, noCache bool) error {
	flags := &scanFlags{
		cacheDir:   cacheDir,
		osvBaseURL: osvBaseURL,
		noCache:    noCache,
		osvTimeout: 30 * time.Second,
	}

	details, err := fetchSeverity(cmd.Context(), []string{id}, flags, nil)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", id, err)
	}

	d, ok := details[id]
	if !ok || d == nil {
		return fmt.Errorf("vulnerability %s not found", id)
	}

	w := cmd.OutOrStdout()
	sev := osv.DeriveSeverity(d)
	fixedIn := osv.DeriveFixedVersion(d, "", "")

	fmt.Fprintln(w, headerStyle.Render("nazar 🧿 — "+id))
	fmt.Fprintln(w)

	// Summary line.
	sevLabel := styleForSev(sev).Render(fmt.Sprintf("[%s]", string(sev)))
	fmt.Fprintf(w, "%s  %s\n\n", sevLabel,
		lipgloss.NewStyle().Bold(true).Render(d.Summary),
	)

	// Fix version.
	if fixedIn != "" {
		fmt.Fprintf(w, "  %s  %s\n",
			mutedStyle.Render("Fix:"),
			lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("→ upgrade to "+fixedIn),
		)
	}

	// CVSS scores.
	if len(d.Severity) > 0 {
		fmt.Fprintf(w, "  %s\n", mutedStyle.Render("CVSS:"))
		for _, s := range d.Severity {
			fmt.Fprintf(w, "    %s  %s\n",
				mutedStyle.Render(s.Type),
				lipgloss.NewStyle().Bold(true).Render(s.Score),
			)
		}
	}

	// Affected ecosystems + packages.
	if len(d.Affected) > 0 {
		fmt.Fprintf(w, "\n  %s\n", mutedStyle.Render("Affected:"))
		for _, a := range d.Affected {
			rangeStrs := []string{}
			for _, r := range a.Ranges {
				if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
					continue
				}
				intro, fixed := "", ""
				for _, e := range r.Events {
					if e.Introduced != "" {
						intro = e.Introduced
					}
					if e.Fixed != "" {
						fixed = e.Fixed
					}
				}
				if intro != "" || fixed != "" {
					rangeStrs = append(rangeStrs, fmt.Sprintf(">=%s, <%s", intro, fixed))
				}
			}
			ranges := ""
			if len(rangeStrs) > 0 {
				ranges = "  " + mutedStyle.Render(strings.Join(rangeStrs, " / "))
			}
			fmt.Fprintf(w, "    %s  %s%s\n",
				ecosystemStyle.Render(a.Package.Ecosystem),
				lipgloss.NewStyle().Bold(true).Render(a.Package.Name),
				ranges,
			)
		}
	}

	// OSV link.
	fmt.Fprintf(w, "\n  %s  %s\n",
		mutedStyle.Render("Details:"),
		mutedStyle.Render("https://osv.dev/vulnerability/"+id),
	)

	return nil
}
