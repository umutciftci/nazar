package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	appconfig "github.com/umutciftci/nazar/internal/config"
)

// applyConfig loads the config file and sets defaults for any flag that has
// not already been explicitly supplied on the command line.  Called from
// PersistentPreRunE on the root command.
func applyConfig(cmd *cobra.Command) error {
	cfg, err := appconfig.Load("")
	if err != nil {
		// Malformed config — warn but continue.
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: config file error: %v\n", err)
		return nil
	}

	set := func(name string) bool {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			// check persistent flags
			f = cmd.Root().PersistentFlags().Lookup(name)
		}
		return f != nil && f.Changed
	}
	setStr := func(name, val string) {
		if val == "" || set(name) {
			return
		}
		if f := cmd.Flags().Lookup(name); f != nil {
			_ = f.Value.Set(val)
		}
	}
	setBool := func(name string, val bool) {
		if !val || set(name) {
			return
		}
		if f := cmd.Flags().Lookup(name); f != nil {
			_ = f.Value.Set("true")
		}
	}
	setInt := func(name string, val int) {
		if val == 0 || set(name) {
			return
		}
		if f := cmd.Flags().Lookup(name); f != nil {
			_ = f.Value.Set(fmt.Sprintf("%d", val))
		}
	}
	setDur := func(name, val string) {
		if val == "" || set(name) {
			return
		}
		if _, err := time.ParseDuration(val); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: config: invalid duration for %q: %v\n", name, err)
			return
		}
		if f := cmd.Flags().Lookup(name); f != nil {
			_ = f.Value.Set(val)
		}
	}

	if cfg.Sort != nil {
		setStr("sort", *cfg.Sort)
	}
	if cfg.Top != nil {
		setInt("top", *cfg.Top)
	}
	if cfg.Severity != nil {
		setStr("severity", *cfg.Severity)
	}
	if cfg.SeverityWorkers != nil {
		setInt("severity-workers", *cfg.SeverityWorkers)
	}
	if cfg.OsvTimeout != nil {
		setDur("osv-timeout", *cfg.OsvTimeout)
	}
	if cfg.NoCache != nil {
		setBool("no-cache", *cfg.NoCache)
	}
	if cfg.CacheDir != nil {
		setStr("cache-dir", *cfg.CacheDir)
	}
	if cfg.SafeOnly != nil {
		setBool("safe-only", *cfg.SafeOnly)
	}
	if cfg.RunTests != nil {
		setStr("run-tests", *cfg.RunTests)
	}
	if cfg.Interval != nil {
		setDur("interval", *cfg.Interval)
	}

	return nil
}

// newConfigCmd builds the `nazar config` subcommand tree.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage nazar configuration",
		Long: "Config lets you view and edit the nazar configuration file.\n\n" +
			"The config file persists default flag values so you don't have to\n" +
			"retype them on every invocation. Command-line flags always win.\n\n" +
			"Config file location: " + appconfig.DefaultPath(),
	}
	cmd.AddCommand(newConfigShowCmd())
	cmd.AddCommand(newConfigEditCmd())
	cmd.AddCommand(newConfigSetCmd())
	cmd.AddCommand(newConfigPathCmd())
	return cmd
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the current configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := appconfig.DefaultPath()
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintln(cmd.OutOrStdout(), mutedStyle.Render("No config file found at "+path))
					fmt.Fprintln(cmd.OutOrStdout(), mutedStyle.Render("Run `nazar config set <key> <value>` to create one."))
					return nil
				}
				return err
			}
			// Pretty-print the JSON.
			var v any
			if err := json.Unmarshal(data, &v); err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\n", data)
				return nil
			}
			pretty, _ := json.MarshalIndent(v, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), headerStyle.Render("nazar config — "+path))
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), string(pretty))
			return nil
		},
	}
}

func newConfigPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path",
		Short: "Print the config file path",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), appconfig.DefaultPath())
		},
	}
}

func newConfigEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Open the config file in $EDITOR",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := appconfig.DefaultPath()
			// Ensure file exists.
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if err := appconfig.Save(&appconfig.Config{}, path); err != nil {
					return fmt.Errorf("create config: %w", err)
				}
			}
			editor := os.Getenv("EDITOR")
			if editor == "" {
				switch runtime.GOOS {
				case "darwin":
					editor = "open"
				case "windows":
					editor = "notepad"
				default:
					editor = "vi"
				}
			}
			parts := strings.Fields(editor)
			parts = append(parts, path)
			ec := exec.Command(parts[0], parts[1:]...)
			ec.Stdin = os.Stdin
			ec.Stdout = os.Stdout
			ec.Stderr = os.Stderr
			return ec.Run()
		},
	}
}

// newConfigSetCmd creates `nazar config set <key> <value>`.
func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a config value",
		Long: `Set a single configuration key.

Supported keys and example values:

  sort             worst|crit|high|total|fixable|path
  top              10
  severity         high|critical|medium|low
  severity-workers 16
  osv-timeout      2m
  no-cache         true|false
  cache-dir        /path/to/dir
  safe-only        true|false
  run-tests        npm test
  interval         6h`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, val := args[0], args[1]
			cfg, err := appconfig.Load("")
			if err != nil {
				cfg = &appconfig.Config{}
			}
			if err := applyConfigKey(cfg, key, val); err != nil {
				return err
			}
			if err := appconfig.Save(cfg, ""); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s  %s = %s\n",
				headerStyle.Render("✓"),
				mutedStyle.Render(key),
				val,
			)
			fmt.Fprintln(cmd.OutOrStdout(), mutedStyle.Render("saved to "+appconfig.DefaultPath()))
			return nil
		},
	}
}

func applyConfigKey(cfg *appconfig.Config, key, val string) error {
	switch key {
	case "sort":
		cfg.Sort = &val
	case "top":
		n := 0
		if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
			return fmt.Errorf("top: expected integer, got %q", val)
		}
		cfg.Top = &n
	case "severity":
		cfg.Severity = &val
	case "severity-workers":
		n := 0
		if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
			return fmt.Errorf("severity-workers: expected integer, got %q", val)
		}
		cfg.SeverityWorkers = &n
	case "osv-timeout":
		if _, err := time.ParseDuration(val); err != nil {
			return fmt.Errorf("osv-timeout: invalid duration %q: %w", val, err)
		}
		cfg.OsvTimeout = &val
	case "no-cache":
		b := val == "true" || val == "1" || val == "yes"
		cfg.NoCache = &b
	case "cache-dir":
		cfg.CacheDir = &val
	case "safe-only":
		b := val == "true" || val == "1" || val == "yes"
		cfg.SafeOnly = &b
	case "run-tests":
		cfg.RunTests = &val
	case "interval":
		if _, err := time.ParseDuration(val); err != nil {
			return fmt.Errorf("interval: invalid duration %q: %w", val, err)
		}
		cfg.Interval = &val
	default:
		return fmt.Errorf("unknown config key %q\n\nRun `nazar config set --help` for supported keys", key)
	}
	return nil
}
