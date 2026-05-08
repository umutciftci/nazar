package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// dotnetLock mirrors the structure of a .NET packages.lock.json file.
// The outer map key is the target framework moniker (e.g. "net8.0").
type dotnetLock struct {
	Version      int                                          `json:"version"`
	Dependencies map[string]map[string]dotnetLockedPackage   `json:"dependencies"`
}

// dotnetLockedPackage is a single resolved dependency entry.
type dotnetLockedPackage struct {
	// Type is "Direct" for top-level references or "Transitive" for indirect deps.
	Type        string `json:"type"`
	Resolved    string `json:"resolved"`
	ContentHash string `json:"contentHash"`
}

// ParseDotnetPackagesLock parses a .NET packages.lock.json file and returns
// the resolved NuGet packages. When the same package appears under multiple
// target frameworks at the same resolved version it is deduplicated. Packages
// appearing under multiple frameworks at different versions produce one entry
// per distinct (name, version) pair.
//
// The Direct field is true when the package's type is "Direct" in any
// framework section.
func ParseDotnetPackagesLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read packages.lock.json: %w", err)
	}
	var lock dotnetLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse packages.lock.json: %w", err)
	}

	type entry struct {
		version string
		direct  bool
	}
	// Key: lowercase(name)+"@"+version — deduplicates across frameworks.
	seen := make(map[string]entry)

	for _, frameworkDeps := range lock.Dependencies {
		for name, dep := range frameworkDeps {
			if dep.Resolved == "" {
				continue
			}
			key := strings.ToLower(name) + "@" + dep.Resolved
			e, exists := seen[key]
			if !exists {
				e = entry{version: dep.Resolved}
			}
			// Once marked Direct, stays Direct even if other frameworks see it
			// as Transitive.
			if strings.EqualFold(dep.Type, "Direct") {
				e.direct = true
			}
			seen[key] = e
		}
	}

	pkgs := make([]Package, 0, len(seen))
	for key, e := range seen {
		// Recover the original-case name from the key prefix.
		atIdx := strings.LastIndex(key, "@"+e.version)
		name := key[:atIdx]
		// Re-derive from the original map to get the actual case.
		// The seen map was keyed with lowercase names; we need to find the
		// original casing. We scan the framework dependencies again.
		// (This is O(n) but n is typically small for .NET projects.)
		originalName := name // fallback
	outer:
		for _, frameworkDeps := range lock.Dependencies {
			for n, dep := range frameworkDeps {
				if strings.EqualFold(n, name) && dep.Resolved == e.version {
					originalName = n
					break outer
				}
			}
		}
		pkgs = append(pkgs, Package{
			Name:    originalName,
			Version: e.version,
			Direct:  e.direct,
		})
	}

	sort.Slice(pkgs, func(i, j int) bool {
		return strings.ToLower(pkgs[i].Name) < strings.ToLower(pkgs[j].Name)
	})
	return pkgs, nil
}
