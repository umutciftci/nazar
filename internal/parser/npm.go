// Package parser turns ecosystem lockfiles into a normalized list of installed
// packages. The current implementation handles npm's package-lock.json across
// the three lockfileVersion variants seen in the wild (v1, v2, v3).
package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Package is a single dependency that was actually installed at scan time.
// It maps directly to the (ecosystem, name, version) triple that OSV.dev
// expects for vulnerability lookups.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Direct is true when this package appears in the root package.json's
	// `dependencies` or `devDependencies`, false when it's only pulled in
	// transitively. The scanner uses this to flag "your direct deps" vs
	// "your full closure" in the final report.
	Direct bool `json:"direct"`
}

// npmLockfile mirrors the union of fields we need across lockfileVersion 1/2/3.
//
// Lockfile v1 (npm 5/6) only populates Dependencies; v2 and v3 populate
// Packages (a flat map keyed by `node_modules/<name>` paths). v2 keeps both
// for back-compat; v3 drops Dependencies entirely.
type npmLockfile struct {
	Name            string                  `json:"name"`
	Version         string                  `json:"version"`
	LockfileVersion int                     `json:"lockfileVersion"`
	Packages        map[string]npmPackage   `json:"packages"`
	Dependencies    map[string]npmV1Package `json:"dependencies"`
}

// npmPackage is an entry in the `packages` map of a v2/v3 lockfile.
type npmPackage struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Resolved         string            `json:"resolved"`
	Link             bool              `json:"link"`
	Dev              bool              `json:"dev"`
	Optional         bool              `json:"optional"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

// npmV1Package is an entry in the `dependencies` map of a v1 lockfile.
// Nested `dependencies` represent the legacy nested resolution layout.
type npmV1Package struct {
	Version      string                  `json:"version"`
	Dev          bool                    `json:"dev"`
	Optional     bool                    `json:"optional"`
	Dependencies map[string]npmV1Package `json:"dependencies"`
}

// ParseNPMLockfile reads the lockfile at path and returns the deduplicated
// list of installed packages. Entries with no version, with `link: true`
// (workspace links), or representing the project itself are skipped.
//
// The returned slice is sorted by (Name, Version) for stable output and
// reproducible tests.
func ParseNPMLockfile(path string) ([]Package, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}

	var lf npmLockfile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	// dedupe key: name@version (npm allows multiple installs of the same
	// package at different versions, but each (name, version) only matters
	// once for vulnerability lookup).
	seen := make(map[string]Package)

	switch {
	case len(lf.Packages) > 0:
		// lockfileVersion 2 or 3: prefer the flat Packages map.
		collectFromV2(lf.Packages, seen)
	case len(lf.Dependencies) > 0:
		// lockfileVersion 1: fall back to the nested Dependencies tree.
		// Top-level entries are direct dependencies of the project.
		for name, dep := range lf.Dependencies {
			collectFromV1(name, dep, true, seen)
		}
	default:
		// Empty lockfile (no deps yet) is not an error.
	}

	out := make([]Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// collectFromV2 walks the flat `packages` map produced by lockfileVersion 2/3.
//
// The map key is the install path relative to the project root, e.g.
//   ""                                   → the root project itself
//   "node_modules/lodash"                → top-level (direct) install of lodash
//   "node_modules/foo/node_modules/bar"  → nested install of bar under foo
//
// Only the segment AFTER the final "node_modules/" is the package name.
// Entries whose key has no "node_modules/" segment refer to the root project
// (or workspaces) and are skipped — they are not third-party dependencies.
func collectFromV2(pkgs map[string]npmPackage, seen map[string]Package) {
	for key, p := range pkgs {
		if p.Link {
			continue // workspace symlink, no real install
		}
		if p.Version == "" {
			continue
		}

		name := nameFromV2Key(key, p.Name)
		if name == "" {
			continue // root project or unrecognised entry
		}

		direct := isDirectV2Key(key)

		k := name + "@" + p.Version
		if existing, ok := seen[k]; ok {
			// Promote to "direct" if any install of this (name, version)
			// is at the top level — direct beats transitive.
			if direct && !existing.Direct {
				existing.Direct = true
				seen[k] = existing
			}
			continue
		}
		seen[k] = Package{Name: name, Version: p.Version, Direct: direct}
	}
}

// nameFromV2Key derives the package name from a v2/v3 lockfile key.
// fallbackName comes from the entry's own `name` field and is used for
// scoped packages where the key doesn't unambiguously include the scope.
func nameFromV2Key(key, fallbackName string) string {
	if key == "" {
		return ""
	}
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		// A key without "node_modules/" is the root project or a workspace
		// alias. Either way, not a third-party dep.
		return ""
	}
	name := key[idx+len("node_modules/"):]
	if name == "" {
		return fallbackName
	}
	return name
}

// isDirectV2Key reports whether a v2/v3 key represents a top-level
// (direct) install — i.e. exactly one "node_modules/" segment.
func isDirectV2Key(key string) bool {
	if !strings.HasPrefix(key, "node_modules/") {
		return false
	}
	rest := key[len("node_modules/"):]
	return !strings.Contains(rest, "/node_modules/")
}

// collectFromV1 walks the nested v1 `dependencies` tree.
// The first invocation sets direct=true; recursive descent sets it to false.
func collectFromV1(name string, dep npmV1Package, direct bool, seen map[string]Package) {
	if dep.Version != "" {
		k := name + "@" + dep.Version
		if existing, ok := seen[k]; ok {
			if direct && !existing.Direct {
				existing.Direct = true
				seen[k] = existing
			}
		} else {
			seen[k] = Package{Name: name, Version: dep.Version, Direct: direct}
		}
	}
	for childName, child := range dep.Dependencies {
		collectFromV1(childName, child, false, seen)
	}
}
