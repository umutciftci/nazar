package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseYarnLock parses both classic (v1) and berry (v2+) yarn.lock files.
//
// Classic lockfiles begin with `# yarn lockfile v1`; berry lockfiles begin
// with a `__metadata` block. Both use the same key-then-version structure:
//
//	"lodash@^4.17.0":          ← package entry line (not indented)
//	  version "4.17.21"        ← classic: quoted version
//
//	"lodash@npm:^4.17.0":      ← berry entry
//	  version: 4.17.21         ← berry: unquoted version
//
// All packages are marked Direct=false; yarn.lock is the full closure and
// the package.json required for detection is not re-parsed here.
func ParseYarnLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open yarn.lock: %w", err)
	}
	defer f.Close()

	var pkgs []Package
	seen := map[string]struct{}{}
	var curName string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()

		// Skip comments, blank lines, and the berry __metadata block.
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(strings.TrimSpace(line), "__metadata") {
			continue
		}

		// Package entry: not indented, ends with ':'.
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			curName = yarnKeyToName(line)
			continue
		}

		// Version line (must follow a package entry).
		if curName == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:") {
			ver := yarnExtractVersion(trimmed)
			if ver != "" {
				key := curName + "@" + ver
				if _, dup := seen[key]; !dup {
					seen[key] = struct{}{}
					pkgs = append(pkgs, Package{Name: curName, Version: ver, Direct: false})
				}
				curName = ""
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read yarn.lock: %w", err)
	}
	return pkgs, nil
}

// yarnKeyToName extracts the npm package name from a yarn.lock key line.
// The line may have multiple comma-separated specifiers and surrounding
// quotes; we take the first specifier and strip the version range:
//
//	`"lodash@^4.17.0, lodash@~4.0.0":` → "lodash"
//	`"@scope/pkg@npm:^1.0.0":` → "@scope/pkg"
func yarnKeyToName(line string) string {
	// Strip trailing colon.
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")
	// Take the first entry in a comma-separated list.
	first := strings.SplitN(line, ",", 2)[0]
	// Strip surrounding quotes.
	first = strings.Trim(first, `"`)
	// Strip leading/trailing whitespace.
	first = strings.TrimSpace(first)
	// The package name ends at the last '@' that isn't at position 0.
	// Position 0 is the scope marker for "@scope/pkg@range".
	at := strings.LastIndex(first, "@")
	if at <= 0 {
		return first
	}
	return first[:at]
}

// yarnExtractVersion pulls the resolved version string from lines like:
//
//	version "4.17.21"   (classic)
//	version: 4.17.21    (berry, unquoted)
//	version: "4.17.21"  (berry, quoted)
func yarnExtractVersion(line string) string {
	var rest string
	switch {
	case strings.HasPrefix(line, "version:"):
		rest = strings.TrimPrefix(line, "version:")
	case strings.HasPrefix(line, "version "):
		rest = strings.TrimPrefix(line, "version ")
	default:
		return ""
	}
	return strings.Trim(strings.TrimSpace(rest), `"`)
}
