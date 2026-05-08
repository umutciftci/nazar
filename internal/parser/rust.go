package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseCargoLock extracts packages from a Cargo.lock file.
//
// Only packages with a `source` field that contains "registry+" are included —
// those are crates from crates.io. Workspace members (no source field) and
// packages from git or path sources are skipped because OSV only covers
// crates.io packages under the "crates.io" ecosystem.
//
// All returned packages are marked Direct=false because Cargo.lock represents
// the full resolved closure; direct deps live in Cargo.toml which we do not
// parse here.
func ParseCargoLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Cargo.lock: %w", err)
	}
	defer f.Close()

	var pkgs []Package
	seen := map[string]struct{}{}

	var curName, curVersion, curSource string
	inPkg := false

	commit := func() {
		if curName != "" && curVersion != "" && strings.Contains(curSource, "registry+") {
			key := curName + "@" + curVersion
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				pkgs = append(pkgs, Package{Name: curName, Version: curVersion, Direct: false})
			}
		}
		curName, curVersion, curSource = "", "", ""
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
		if v, ok := tomlStringField(line, "source"); ok {
			curSource = v
		}
	}
	commit() // flush last package

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read Cargo.lock: %w", err)
	}
	return pkgs, nil
}
