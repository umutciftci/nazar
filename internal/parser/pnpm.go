package parser

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ParsePnpmLock parses a pnpm-lock.yaml file and returns the list of installed
// packages. It handles both the v6 format (pnpm 8.x, keys like `/name/version`)
// and the v9 format (pnpm 9.x, keys like `name@version`).
//
// All packages are marked Direct=false; the importers section is not parsed.
func ParsePnpmLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pnpm-lock.yaml: %w", err)
	}
	defer f.Close()

	var pkgs []Package
	seen := map[string]struct{}{}
	var lockfileVersion string
	inPackages := false

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB buffer for large lockfiles

	for sc.Scan() {
		line := sc.Text()

		// Capture lockfile version from the header.
		if strings.HasPrefix(line, "lockfileVersion:") {
			lockfileVersion = pnpmExtractVersion(line)
			continue
		}

		// Track the packages: section.
		if line == "packages:" {
			inPackages = true
			continue
		}
		// Any top-level non-blank, non-comment key ends the section.
		if inPackages && len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			inPackages = false
		}

		if !inPackages {
			continue
		}

		// Package keys are exactly 2-space indented lines that end with ':'.
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}

		key := strings.TrimSuffix(trimmed, ":")
		key = strings.Trim(key, `'"`)
		// Strip peer-dep suffixes like "(react@18.2.0)" that pnpm appends.
		if idx := strings.IndexByte(key, '('); idx >= 0 {
			key = strings.TrimSpace(key[:idx])
		}

		var name, ver string
		if pnpmIsV9OrLater(lockfileVersion) {
			// v9: "name@version"
			at := strings.LastIndex(key, "@")
			if at <= 0 {
				continue
			}
			name = key[:at]
			ver = key[at+1:]
		} else {
			// v6: "/name/version" (scoped: "/@scope/pkg/version")
			key = strings.TrimPrefix(key, "/")
			slash := strings.LastIndex(key, "/")
			if slash < 0 {
				continue
			}
			name = key[:slash]
			ver = key[slash+1:]
		}

		if name == "" || ver == "" {
			continue
		}
		dedup := name + "@" + ver
		if _, dup := seen[dedup]; dup {
			continue
		}
		seen[dedup] = struct{}{}
		pkgs = append(pkgs, Package{Name: name, Version: ver, Direct: false})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read pnpm-lock.yaml: %w", err)
	}
	return pkgs, nil
}

// pnpmExtractVersion parses the lockfileVersion field value, handling both
// quoted ("9.0") and unquoted (9.0) forms.
func pnpmExtractVersion(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(parts[1]), `'"`)
}

// pnpmIsV9OrLater reports whether the lockfile uses the v9+ package key format
// ("name@version") as opposed to v6's "/name/version" format.
func pnpmIsV9OrLater(version string) bool {
	parts := strings.SplitN(version, ".", 2)
	if len(parts) == 0 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	return err == nil && major >= 9
}
