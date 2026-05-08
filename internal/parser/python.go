package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParsePythonLockfile dispatches to the right parser based on filename.
func ParsePythonLockfile(path string) ([]Package, error) {
	switch filepath.Base(path) {
	case "poetry.lock", "uv.lock":
		// uv.lock uses the same [[package]] TOML structure as poetry.lock.
		return ParsePoetryLock(path)
	case "Pipfile.lock":
		return ParsePipfileLock(path)
	default:
		return ParseRequirementsTxt(path)
	}
}

// ParseRequirementsTxt extracts pinned packages from a requirements.txt file.
// Only `name==version` lines are processed. Version ranges, VCS requirements,
// options (-r, -e, etc.) and unpinned entries are silently skipped.
func ParseRequirementsTxt(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open requirements: %w", err)
	}
	defer f.Close()

	var pkgs []Package
	seen := map[string]struct{}{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comment.
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Only process pinned == versions.
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if name == "" || version == "" {
			continue
		}
		// Strip extras: "requests[security]==2.31.0" → "requests".
		if idx := strings.IndexByte(name, '['); idx >= 0 {
			name = strings.TrimSpace(name[:idx])
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, Package{Name: name, Version: version, Direct: true})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read requirements: %w", err)
	}
	return pkgs, nil
}

// ParsePoetryLock extracts all packages from a poetry.lock file.
// All entries are marked Direct=false because the full dependency closure
// is recorded in the lockfile; direct deps are in pyproject.toml which we
// do not parse here.
func ParsePoetryLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open poetry.lock: %w", err)
	}
	defer f.Close()

	var pkgs []Package
	seen := map[string]struct{}{}

	var curName, curVersion string
	inPkg := false

	commit := func() {
		if curName != "" && curVersion != "" {
			key := curName + "@" + curVersion
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				pkgs = append(pkgs, Package{Name: curName, Version: curVersion, Direct: false})
			}
		}
		curName, curVersion = "", ""
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if line == "[[package]]" {
			commit()
			inPkg = true
			continue
		}
		// Any other section header ends the current [[package]] block.
		if strings.HasPrefix(line, "[") {
			commit()
			inPkg = false
			continue
		}
		if !inPkg {
			continue
		}
		if v, ok := tomlStringField(line, "name"); ok {
			curName = v
		}
		if v, ok := tomlStringField(line, "version"); ok {
			curVersion = v
		}
	}
	commit() // flush the last package if file ends without a new section

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read poetry.lock: %w", err)
	}
	return pkgs, nil
}

// tomlStringField parses `key = "value"` lines from TOML.
func tomlStringField(line, key string) (string, bool) {
	prefix := key + ` = "`
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := line[len(prefix):]
	if idx := strings.IndexByte(rest, '"'); idx >= 0 {
		return rest[:idx], true
	}
	return "", false
}
