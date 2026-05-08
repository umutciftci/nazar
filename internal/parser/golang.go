package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseGoSum parses a go.sum file and returns the list of modules as packages.
//
// It co-reads go.mod from the same directory (best-effort) to mark direct
// dependencies. Modules that only appear with a /go.mod hash line in go.sum
// are skipped — those checksums verify the go.mod file itself, not the module
// download, and OSV does not expect them as separate query coordinates.
func ParseGoSum(sumPath string) ([]Package, error) {
	directMods := parseGoMod(filepath.Join(filepath.Dir(sumPath), "go.mod"))

	f, err := os.Open(sumPath)
	if err != nil {
		return nil, fmt.Errorf("open go.sum: %w", err)
	}
	defer f.Close()

	var pkgs []Package
	seen := map[string]struct{}{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		modPath := fields[0]
		ver := fields[1]

		// Skip checksum entries for go.mod files — they exist so the toolchain
		// can verify module metadata, but they do not represent a dependency
		// that a vulnerability scanner needs to query.
		if strings.HasSuffix(ver, "/go.mod") {
			continue
		}

		key := modPath + "@" + ver
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		_, direct := directMods[modPath]
		pkgs = append(pkgs, Package{Name: modPath, Version: ver, Direct: direct})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read go.sum: %w", err)
	}
	return pkgs, nil
}

// parseGoMod returns a set of module paths listed in go.mod's require blocks
// WITHOUT the "// indirect" annotation. These are the caller's direct deps.
// Errors are silently swallowed because go.mod is optional for nazar's
// purposes (it only enriches the Direct field).
func parseGoMod(path string) map[string]struct{} {
	direct := map[string]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		return direct
	}
	defer f.Close()

	inRequire := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)

		switch {
		case line == "require (":
			inRequire = true
		case inRequire && line == ")":
			inRequire = false
		case inRequire:
			addDirectIfNotIndirect(direct, line)
		case strings.HasPrefix(line, "require ") && !strings.Contains(line, "("):
			// Single-line form: "require github.com/foo/bar v1.2.3"
			addDirectIfNotIndirect(direct, strings.TrimPrefix(line, "require "))
		}
	}
	return direct
}

// addDirectIfNotIndirect records modLine's module path as direct if the
// line does not carry a "// indirect" comment.
func addDirectIfNotIndirect(direct map[string]struct{}, modLine string) {
	modLine = strings.TrimSpace(modLine)
	if modLine == "" || strings.HasPrefix(modLine, "//") {
		return
	}
	if strings.Contains(modLine, "// indirect") {
		return
	}
	fields := strings.Fields(modLine)
	if len(fields) >= 1 {
		direct[fields[0]] = struct{}{}
	}
}
