package main

import (
	"github.com/spf13/cobra"
)

// newRootCmd builds the top-level cobra command tree for nazar.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "nazar",
		Short:         "The evil eye that watches over your dependencies",
		Long:          "nazar is a multi-project, local-first vulnerability scanner.\n\nRun `nazar scan <path>` to walk a directory and report on every project found.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// PersistentPreRunE applies config-file defaults before every subcommand.
		// Flags explicitly set on the command line always override config values.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return applyConfig(cmd)
		},
	}

	root.AddCommand(newScanCmd())
	root.AddCommand(newCICmd())
	root.AddCommand(newFixCmd())
	root.AddCommand(newDiffCmd())
	root.AddCommand(newWatchCmd())
	root.AddCommand(newShowCmd())
	root.AddCommand(newIgnoreCmd())
	root.AddCommand(newCacheCmd())
	root.AddCommand(newConfigCmd())
	return root
}
