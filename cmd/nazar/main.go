// Command nazar is a multi-project local vulnerability scanner.
//
// It walks a directory tree, detects projects in supported ecosystems
// (npm, PyPI), parses their lockfiles and reports the results.
package main

import (
	"errors"
	"fmt"
	"os"
)

// version is set by the linker at build time via -ldflags="-X main.version=...".
// It defaults to "dev" so that `go run` and local builds stay readable.
var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		var vulnsFound *errVulnsFound
		if errors.As(err, &vulnsFound) {
			// --fail-on threshold hit: print the message and exit 2 so CI
			// pipelines can distinguish "scan failed" (1) from "vulns found" (2).
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
