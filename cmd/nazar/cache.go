package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/history"
	"github.com/umutciftci/nazar/internal/osv"
)

func newCacheCmd() *cobra.Command {
	var cacheDir string

	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the local OSV cache",
		Long: "Cache lets you inspect and clear the local disk cache that nazar uses\n" +
			"to avoid re-fetching OSV data on every scan.\n\n" +
			"Two caches are maintained:\n" +
			"  coords  — batch query results (TTL: 24 h)\n" +
			"  vulns   — per-CVE detail + severity (TTL: 7 d)",
	}
	cmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", "", "override the cache directory")

	cmd.AddCommand(newCachePathCmd(&cacheDir))
	cmd.AddCommand(newCacheStatsCmd(&cacheDir))
	cmd.AddCommand(newCacheClearCmd(&cacheDir))
	cmd.AddCommand(newCachePruneCmd(&cacheDir))
	return cmd
}

func newCachePathCmd(cacheDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the cache directory path",
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := cacheBaseDir(*cacheDir)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), base)
			return nil
		},
	}
}

func newCacheStatsCmd(cacheDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show cache usage (entry counts, disk size, staleness)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := cacheBaseDir(*cacheDir)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			fmt.Fprintln(w, headerStyle.Render("nazar 🧿 — cache stats"))
			fmt.Fprintln(w, mutedStyle.Render(base))
			fmt.Fprintln(w)

			printCacheSection(w, "coords  (batch query results)", filepath.Join(base, "osv"), osv.DefaultTTL)
			fmt.Fprintln(w)
			printCacheSection(w, "vulns   (per-CVE detail + severity)", filepath.Join(base, "vulns"), osv.DefaultDetailTTL)
			fmt.Fprintln(w)
			printCacheSection(w, "history (diff/watch snapshots)", history.HistoryDir(*cacheDir), 0)

			return nil
		},
	}
}

func newCacheClearCmd(cacheDir *string) *cobra.Command {
	var what string

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete cached data",
		Long: "Clear deletes cached data so the next scan fetches fresh results.\n\n" +
			"Use --what to target a specific sub-cache:\n" +
			"  all      — everything (default)\n" +
			"  coords   — batch query results only\n" +
			"  vulns    — per-CVE detail only\n" +
			"  history  — diff/watch snapshots only",
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := cacheBaseDir(*cacheDir)
			if err != nil {
				return err
			}

			targets := map[string]string{
				"coords":  filepath.Join(base, "osv"),
				"vulns":   filepath.Join(base, "vulns"),
				"history": history.HistoryDir(*cacheDir),
			}

			var toDelete []string
			switch what {
			case "all", "":
				toDelete = []string{targets["coords"], targets["vulns"], targets["history"]}
			case "coords", "vulns", "history":
				toDelete = []string{targets[what]}
			default:
				return fmt.Errorf("unknown target %q; expected all|coords|vulns|history", what)
			}

			w := cmd.OutOrStdout()
			deleted := 0
			for _, p := range toDelete {
				if _, err := os.Stat(p); os.IsNotExist(err) {
					continue
				}
				if err := os.RemoveAll(p); err != nil {
					fmt.Fprintf(w, "%s  could not remove %s: %v\n",
						lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✗"), p, err)
					continue
				}
				fmt.Fprintf(w, "%s  cleared %s\n",
					headerStyle.Render("✓"),
					mutedStyle.Render(p),
				)
				deleted++
			}
			if deleted == 0 {
				fmt.Fprintln(w, mutedStyle.Render("Nothing to clear — cache is already empty."))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&what, "what", "all", "what to clear: all|coords|vulns|history")
	return cmd
}

func newCachePruneCmd(cacheDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "prune",
		Short: "Remove only expired cache entries (keep fresh ones)",
		Long: "Prune walks the coords and vulns caches and deletes only the files whose\n" +
			"TTL has elapsed. Fresh entries are kept so the next scan stays fast.\n\n" +
			"  coords TTL: 24 h\n" +
			"  vulns  TTL: 7 d",
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := cacheBaseDir(*cacheDir)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			total := 0

			type target struct {
				label string
				dir   string
				ttl   time.Duration
			}
			targets := []target{
				{"coords", filepath.Join(base, "osv"), osv.DefaultTTL},
				{"vulns", filepath.Join(base, "vulns"), osv.DefaultDetailTTL},
			}

			for _, t := range targets {
				removed := 0
				now := time.Now()
				// Cache files may be in subdirectories (first 2 chars of hash).
				_ = filepath.WalkDir(t.dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return nil
					}
					info, err := d.Info()
					if err != nil {
						return nil
					}
					if now.Sub(info.ModTime()) > t.ttl {
						if os.Remove(path) == nil {
							removed++
						}
					}
					return nil
				})
				if removed > 0 {
					fmt.Fprintf(w, "%s  pruned %d stale %s entries\n",
						headerStyle.Render("✓"), removed, t.label)
				} else {
					fmt.Fprintf(w, "     %s — nothing to prune\n", mutedStyle.Render(t.label))
				}
				total += removed
			}

			if total > 0 {
				fmt.Fprintln(w, mutedStyle.Render(fmt.Sprintf("%d total entries removed", total)))
			}
			return nil
		},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// cacheBaseDir returns the effective nazar cache base directory.
func cacheBaseDir(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate cache dir: %w", err)
	}
	return filepath.Join(base, "nazar"), nil
}

type dirStats struct {
	entries int
	stale   int
	bytes   int64
	oldest  time.Time
	newest  time.Time
}

func statDir(dir string, ttl time.Duration) dirStats {
	var s dirStats
	now := time.Now()
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		s.entries++
		s.bytes += info.Size()
		mod := info.ModTime()
		if s.oldest.IsZero() || mod.Before(s.oldest) {
			s.oldest = mod
		}
		if mod.After(s.newest) {
			s.newest = mod
		}
		if ttl > 0 && now.Sub(mod) > ttl {
			s.stale++
		}
		return nil
	})
	return s
}

func printCacheSection(w io.Writer, label, dir string, ttl time.Duration) {
	fmt.Fprintf(w, "  %s\n", headerStyle.Render(label))
	fmt.Fprintf(w, "    %s  %s\n", mutedStyle.Render("path:"), dir)

	s := statDir(dir, ttl)
	if s.entries == 0 {
		fmt.Fprintf(w, "    %s\n", mutedStyle.Render("empty"))
		return
	}

	fmt.Fprintf(w, "    %s  %d\n", mutedStyle.Render("entries:"), s.entries)
	fmt.Fprintf(w, "    %s  %s\n", mutedStyle.Render("size:   "), formatBytes(s.bytes))

	if ttl > 0 {
		freshStr := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("✓ fresh")
		if s.stale > 0 {
			freshStr = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).
				Render(fmt.Sprintf("%d stale", s.stale))
		}
		fmt.Fprintf(w, "    %s  %s  %s\n", mutedStyle.Render("ttl:    "), ttl.String(), freshStr)
	}

	if !s.oldest.IsZero() {
		now := time.Now()
		fmt.Fprintf(w, "    %s  %s (newest) … %s (oldest)\n",
			mutedStyle.Render("age:    "),
			formatAge(now.Sub(s.newest)),
			formatAge(now.Sub(s.oldest)),
		)
	}
}

func formatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
}
