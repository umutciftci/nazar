package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// pipfileLockFile is the JSON shape of Pipfile.lock.
// Both "default" (production) and "develop" sections are scanned.
type pipfileLockFile struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	// Version is a PEP 440 specifier like "==2.31.0". Entries that come from
	// git or local paths may omit this field.
	Version string `json:"version"`
}

// ParsePipfileLock extracts installed packages from a Pipfile.lock JSON file.
// Both the "default" and "develop" sections are included. The version prefix
// "==" is stripped so the version matches OSV's expected format.
// All packages are marked Direct=false because Pipfile.lock records the full
// transitive closure; direct deps are defined in Pipfile.
func ParsePipfileLock(path string) ([]Package, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open Pipfile.lock: %w", err)
	}
	var lock pipfileLockFile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	var pkgs []Package
	seen := map[string]struct{}{}

	add := func(name string, e pipfileEntry) {
		ver := strings.TrimPrefix(strings.TrimSpace(e.Version), "==")
		if ver == "" {
			return // git / path / editable source — no pinned version
		}
		key := name + "@" + ver
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, Package{Name: name, Version: ver, Direct: false})
	}

	for name, e := range lock.Default {
		add(name, e)
	}
	for name, e := range lock.Develop {
		add(name, e)
	}
	return pkgs, nil
}
