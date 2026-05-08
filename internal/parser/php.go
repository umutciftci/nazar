package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// composerLock mirrors the fields we need from composer.lock.
type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseComposerLock parses a PHP Composer composer.lock file.
//
// Packages from the "packages" array are treated as direct (production)
// dependencies; those in "packages-dev" are marked as non-direct (dev-only).
// Version strings with a leading "v" (e.g. "v6.4.0") are normalised by
// stripping the prefix so they match OSV's expected format.
func ParseComposerLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read composer.lock: %w", err)
	}
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	var pkgs []Package
	for _, p := range lock.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:    p.Name,
			Version: strings.TrimPrefix(p.Version, "v"),
			Direct:  true,
		})
	}
	for _, p := range lock.PackagesDev {
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:    p.Name,
			Version: strings.TrimPrefix(p.Version, "v"),
			Direct:  false,
		})
	}
	return pkgs, nil
}
