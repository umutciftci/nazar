package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/umutciftci/nazar/internal/ignore"
)

const nazarignoreFile = ".nazarignore"

func newIgnoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ignore",
		Short: "Manage vulnerability suppression rules",
		Long: "Ignore lets you view and manage the .nazarignore file that lives in your\n" +
			"scan root. Rules suppress specific vulnerabilities from scan output.\n\n" +
			"Rule formats:\n" +
			"  GHSA-xxxx-xxxx-xxxx              ignore this ID everywhere\n" +
			"  CVE-2024-1234                    same, CVE form\n" +
			"  lodash@4.17.20:GHSA-xxxx         only this package@version\n" +
			"  lodash@*:GHSA-xxxx               any version of lodash",
	}
	cmd.AddCommand(newIgnoreListCmd())
	cmd.AddCommand(newIgnoreAddCmd())
	cmd.AddCommand(newIgnoreRemoveCmd())
	return cmd
}

// ignoreFilePath resolves the .nazarignore path for a given root directory.
func ignoreFilePath(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	return filepath.Join(abs, nazarignoreFile), nil
}

// ── list ──────────────────────────────────────────────────────────────────────

func newIgnoreListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [path]",
		Short: "List current suppression rules",
		Long:  "List prints every rule in the .nazarignore file at <path> (default: current directory).",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) > 0 {
				root = args[0]
			}
			ignorePath, err := ignoreFilePath(root)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			lines, err := readIgnoreLines(ignorePath)
			if err != nil {
				return err
			}

			if len(lines) == 0 {
				fmt.Fprintln(w, mutedStyle.Render("No suppression rules found at "+ignorePath))
				fmt.Fprintln(w, mutedStyle.Render("Run `nazar ignore add <rule> [path]` to add one."))
				return nil
			}

			fmt.Fprintln(w, headerStyle.Render("nazar 🧿 — ignore rules"))
			fmt.Fprintln(w, mutedStyle.Render(ignorePath))
			fmt.Fprintln(w)
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					fmt.Fprintln(w)
					continue
				}
				if strings.HasPrefix(trimmed, "#") {
					fmt.Fprintln(w, mutedStyle.Render(line))
					continue
				}
				fmt.Fprintf(w, "  %s  %s\n",
					mutedStyle.Render(fmt.Sprintf("%3d.", i+1)),
					line,
				)
			}
			return nil
		},
	}
}

// ── add ───────────────────────────────────────────────────────────────────────

func newIgnoreAddCmd() *cobra.Command {
	var comment string

	cmd := &cobra.Command{
		Use:   "add <rule> [path]",
		Short: "Add a suppression rule to .nazarignore",
		Long: "Add appends a new rule to the .nazarignore file at <path>.\n" +
			"The file is created if it does not exist.\n\n" +
			"Examples:\n" +
			"  nazar ignore add GHSA-fjxv-7rqg-78g4\n" +
			"  nazar ignore add lodash@*:CVE-2024-1234 ~/projects/myapp\n" +
			"  nazar ignore add GHSA-xxxx --comment \"accepted risk, no upgrade available\"",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			rule := args[0]
			root := "."
			if len(args) > 1 {
				root = args[1]
			}
			ignorePath, err := ignoreFilePath(root)
			if err != nil {
				return err
			}

			// Validate the rule before writing.
			if _, err := ignore.ParseRules([]string{rule}); err != nil {
				return fmt.Errorf("invalid rule: %w", err)
			}

			// Check for duplicates.
			existing, err := readIgnoreLines(ignorePath)
			if err != nil {
				return err
			}
			for _, line := range existing {
				if strings.TrimSpace(line) == rule {
					fmt.Fprintf(cmd.OutOrStdout(), "%s  rule already exists: %s\n",
						mutedStyle.Render("→"), rule)
					return nil
				}
			}

			// Build the line to append.
			entry := rule
			if comment != "" {
				entry = fmt.Sprintf("%-42s # %s", rule, comment)
			}

			if err := appendIgnoreLine(ignorePath, entry); err != nil {
				return fmt.Errorf("write .nazarignore: %w", err)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s  added rule: %s\n",
				headerStyle.Render("✓"),
				entry,
			)
			fmt.Fprintln(w, mutedStyle.Render("saved to "+ignorePath))
			return nil
		},
	}
	cmd.Flags().StringVar(&comment, "comment", "", "optional human-readable note (appended after #)")
	return cmd
}

// ── remove ────────────────────────────────────────────────────────────────────

func newIgnoreRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <rule> [path]",
		Short: "Remove a suppression rule from .nazarignore",
		Long: "Remove deletes the first line in .nazarignore that matches <rule> exactly\n" +
			"(after stripping comments and whitespace). The file is rewritten in place.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			rule := strings.TrimSpace(args[0])
			root := "."
			if len(args) > 1 {
				root = args[1]
			}
			ignorePath, err := ignoreFilePath(root)
			if err != nil {
				return err
			}

			lines, err := readIgnoreLines(ignorePath)
			if err != nil {
				return err
			}

			newLines := make([]string, 0, len(lines))
			removed := false
			for _, line := range lines {
				// Strip inline comment before matching.
				stripped := strings.TrimSpace(line)
				if idx := strings.Index(stripped, "#"); idx > 0 {
					stripped = strings.TrimSpace(stripped[:idx])
				}
				if !removed && stripped == rule {
					removed = true
					continue // drop this line
				}
				newLines = append(newLines, line)
			}

			if !removed {
				return fmt.Errorf("rule not found: %q", rule)
			}

			if err := writeIgnoreLines(ignorePath, newLines); err != nil {
				return fmt.Errorf("write .nazarignore: %w", err)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s  removed rule: %s\n",
				headerStyle.Render("✓"),
				rule,
			)
			fmt.Fprintln(w, mutedStyle.Render("saved to "+ignorePath))
			return nil
		},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// readIgnoreLines reads all lines from path. Returns an empty slice (no error)
// if the file does not exist.
func readIgnoreLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// appendIgnoreLine appends a single line to path, creating the file and
// parent directories if necessary.
func appendIgnoreLine(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

// writeIgnoreLines rewrites path with the given lines (no trailing newline
// manipulation — each line is written as-is followed by \n).
func writeIgnoreLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return w.Flush()
}
