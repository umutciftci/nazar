package parser

import (
	"fmt"
	"os"
	"strings"
)

// ParseGemfileLock parses a Bundler Gemfile.lock and returns the list of
// installed gems. Only the GEM section's specs entries are read; PATH and GIT
// sections are included too (they have the same indentation format).
//
// Installed gems appear at exactly 4-space indent: "    name (version)".
// Their own dependency constraints appear at 6-space indent and are skipped.
func ParseGemfileLock(path string) ([]Package, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}

	var pkgs []Package
	inSpecs := false

	for _, line := range strings.Split(string(raw), "\n") {
		// Strip Windows-style carriage returns.
		line = strings.TrimRight(line, "\r")

		// Unindented lines are section headers (GEM, PLATFORMS, DEPENDENCIES, …)
		// or empty. Leave the specs block when we exit the current section.
		if len(line) == 0 || line[0] != ' ' {
			inSpecs = false
			continue
		}

		// "  specs:" (2-space indent) marks the beginning of installed gems.
		if strings.TrimRight(line, " ") == "  specs:" {
			inSpecs = true
			continue
		}

		if !inSpecs {
			continue
		}

		// Exactly 4-space indent = installed gem entry.
		// 6+ spaces = the gem's own dependency constraints (skip).
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}

		// Format: "    name (version)"
		trimmed := strings.TrimSpace(line)
		lp := strings.Index(trimmed, " (")
		if lp < 0 {
			continue
		}
		name := trimmed[:lp]
		ver := strings.TrimSuffix(trimmed[lp+2:], ")")
		ver = strings.TrimSpace(ver)

		// Version must start with a digit (not a constraint like "~> 2.0").
		if name == "" || ver == "" || !(ver[0] >= '0' && ver[0] <= '9') {
			continue
		}

		pkgs = append(pkgs, Package{Name: name, Version: ver})
	}

	return pkgs, nil
}
