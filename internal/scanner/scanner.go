// Package scanner walks a directory tree and detects projects in supported
// ecosystems. It deliberately skips heavy directories (node_modules, vendor,
// .git, etc.) so that scans complete in seconds even on large home directories.
package scanner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Ecosystem identifies a package manager / dependency format.
type Ecosystem string

const (
	EcosystemNPM       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "PyPI"
	EcosystemGo        Ecosystem = "Go"
	EcosystemCratesIO  Ecosystem = "crates.io"
	EcosystemRubyGems  Ecosystem = "RubyGems"
	EcosystemPackagist Ecosystem = "Packagist"
	EcosystemNuGet     Ecosystem = "NuGet"
)

// Project is a single detected project rooted at Path.
type Project struct {
	// Path is the absolute directory containing the project.
	Path string `json:"path"`
	// Ecosystem is the package manager that produced LockfilePath.
	Ecosystem Ecosystem `json:"ecosystem"`
	// LockfilePath is the absolute path to the lockfile that will be parsed.
	LockfilePath string `json:"lockfile_path"`
}

// skipDirs are directory names that the scanner refuses to descend into.
// They contain transitive dependencies, build artifacts, version-control
// metadata or virtualenvs — none of which we want to walk.
var skipDirs = map[string]struct{}{
	"node_modules": {},
	".git":         {},
	"vendor":       {},
	"target":       {},
	"dist":         {},
	"build":        {},
	".next":        {},
	"__pycache__":  {},
	".venv":        {},
	"venv":         {},
}

// Options controls optional scanner behaviour.
type Options struct {
	// ExcludeDirs is a list of extra directory names to skip (in addition to
	// the built-in skipDirs list). Only the base name is matched, not a path.
	// Example: []string{"testdata", "fixtures"}
	ExcludeDirs []string
}

// Scan walks root and returns every project it detects, sorted by path.
//
// Per-directory I/O errors (e.g. permission denied on a single subtree) are
// joined into the returned error but do not abort the walk: callers receive
// every project the scanner could enumerate together with the aggregate error.
func Scan(root string) ([]Project, error) {
	return ScanWithOptions(root, Options{})
}

// ScanWithOptions is like Scan but accepts additional options.
func ScanWithOptions(root string, opts Options) ([]Project, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}

	// Build the effective skip set from built-in + extra dirs.
	effectiveSkip := make(map[string]struct{}, len(skipDirs)+len(opts.ExcludeDirs))
	for k, v := range skipDirs {
		effectiveSkip[k] = v
	}
	for _, d := range opts.ExcludeDirs {
		if d != "" {
			effectiveSkip[d] = struct{}{}
		}
	}

	var (
		projects []Project
		walkErrs []error
	)

	walkErr := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Record the error for this entry but keep walking siblings.
			walkErrs = append(walkErrs, fmt.Errorf("%s: %w", path, err))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if !d.IsDir() {
			return nil
		}

		// Skip noise directories. We still descend into the root itself
		// even if its name happens to match.
		if path != abs {
			if _, skip := effectiveSkip[d.Name()]; skip {
				return fs.SkipDir
			}
		}

		if proj, ok := detectNPMProject(path); ok {
			projects = append(projects, proj)
		}
		if proj, ok := detectPyPIProject(path); ok {
			projects = append(projects, proj)
		}
		if proj, ok := detectGoProject(path); ok {
			projects = append(projects, proj)
		}
		if proj, ok := detectRustProject(path); ok {
			projects = append(projects, proj)
		}
		if proj, ok := detectRubyProject(path); ok {
			projects = append(projects, proj)
		}
		if proj, ok := detectPHPProject(path); ok {
			projects = append(projects, proj)
		}
		if proj, ok := detectDotnetProject(path); ok {
			projects = append(projects, proj)
		}

		return nil
	})

	if walkErr != nil {
		walkErrs = append(walkErrs, walkErr)
	}

	sort.Slice(projects, func(i, j int) bool {
		return projects[i].Path < projects[j].Path
	})

	if len(walkErrs) > 0 {
		return projects, errors.Join(walkErrs...)
	}
	return projects, nil
}

// detectNPMProject reports whether dir is the root of a Node.js project.
// Requires package.json plus any recognised lockfile. Priority order:
// package-lock.json > yarn.lock > pnpm-lock.yaml.
func detectNPMProject(dir string) (Project, bool) {
	if !fileExists(filepath.Join(dir, "package.json")) {
		return Project{}, false
	}
	for _, lockfile := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		lock := filepath.Join(dir, lockfile)
		if fileExists(lock) {
			return Project{Path: dir, Ecosystem: EcosystemNPM, LockfilePath: lock}, true
		}
	}
	return Project{}, false
}

// detectGoProject reports whether dir is the root of a Go module.
// We require both go.mod (module definition) and go.sum (pinned checksums).
func detectGoProject(dir string) (Project, bool) {
	gomod := filepath.Join(dir, "go.mod")
	gosum := filepath.Join(dir, "go.sum")
	if !fileExists(gomod) || !fileExists(gosum) {
		return Project{}, false
	}
	return Project{Path: dir, Ecosystem: EcosystemGo, LockfilePath: gosum}, true
}

// detectRustProject reports whether dir is the root of a Cargo workspace or
// crate. We require both Cargo.toml (manifest) and Cargo.lock (pinned deps).
func detectRustProject(dir string) (Project, bool) {
	toml := filepath.Join(dir, "Cargo.toml")
	lock := filepath.Join(dir, "Cargo.lock")
	if !fileExists(toml) || !fileExists(lock) {
		return Project{}, false
	}
	return Project{Path: dir, Ecosystem: EcosystemCratesIO, LockfilePath: lock}, true
}

// detectPyPIProject reports whether dir contains a Python dependency file.
// Priority: poetry.lock > uv.lock > Pipfile.lock > requirements.txt.
func detectPyPIProject(dir string) (Project, bool) {
	for _, lockfile := range []string{"poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt"} {
		lock := filepath.Join(dir, lockfile)
		if fileExists(lock) {
			return Project{Path: dir, Ecosystem: EcosystemPyPI, LockfilePath: lock}, true
		}
	}
	return Project{}, false
}

// detectRubyProject reports whether dir is the root of a Bundler project.
// Requires both Gemfile (declares deps) and Gemfile.lock (pinned versions).
func detectRubyProject(dir string) (Project, bool) {
	if !fileExists(filepath.Join(dir, "Gemfile")) {
		return Project{}, false
	}
	lock := filepath.Join(dir, "Gemfile.lock")
	if !fileExists(lock) {
		return Project{}, false
	}
	return Project{Path: dir, Ecosystem: EcosystemRubyGems, LockfilePath: lock}, true
}

// detectPHPProject reports whether dir is the root of a Composer project.
// Requires both composer.json (manifest) and composer.lock (pinned versions).
func detectPHPProject(dir string) (Project, bool) {
	if !fileExists(filepath.Join(dir, "composer.json")) {
		return Project{}, false
	}
	lock := filepath.Join(dir, "composer.lock")
	if !fileExists(lock) {
		return Project{}, false
	}
	return Project{Path: dir, Ecosystem: EcosystemPackagist, LockfilePath: lock}, true
}

// detectDotnetProject reports whether dir contains a .NET packages.lock.json.
// This file is generated by `dotnet restore --use-lock-file` and contains
// all resolved NuGet packages.
func detectDotnetProject(dir string) (Project, bool) {
	lock := filepath.Join(dir, "packages.lock.json")
	if !fileExists(lock) {
		return Project{}, false
	}
	return Project{Path: dir, Ecosystem: EcosystemNuGet, LockfilePath: lock}, true
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
