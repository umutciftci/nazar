// Package ignore implements suppression of accepted-risk vulnerabilities.
//
// Two sources feed an Ignore set:
//
//  1. A `.nazarignore` file at the scan root. One rule per line; blank
//     lines and `#`-prefixed lines are comments. Rules use the same
//     grammar as inline `--ignore` values:
//
//       GHSA-xxxx-xxxx-xxxx              # ignore everywhere
//       CVE-2024-1234                    # same, CVE form
//       lodash@4.17.20:GHSA-xxxx         # only this package@version pair
//       lodash@*:GHSA-xxxx               # any version of lodash
//
//  2. One or more `--ignore` flag values on the command line, using the
//     same grammar.
//
// The matcher is intentionally simple: no globs beyond `*` for version,
// no severity-based suppression. Patches and severity rules can come
// later — accepting a known CVE is the common case.
package ignore

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Rule is one suppression entry.
//
// All fields are case-sensitive. An empty PackageName / Version means the
// rule applies to any package — i.e. the user wants to ignore an OSV ID
// across the entire scan.
type Rule struct {
	PackageName string // "" or e.g. "lodash" / "@scope/utils"
	Version     string // "", "*" or an exact version like "4.17.20"
	VulnID      string // "GHSA-..." or "CVE-..."
}

// Set is a precompiled collection of Rules with a fast Match check.
type Set struct {
	rules []Rule
}

// IsEmpty reports whether the set contains zero rules.
func (s *Set) IsEmpty() bool { return s == nil || len(s.rules) == 0 }

// Match reports whether the given (pkg, version, vuln) triple is suppressed
// by any rule in the set. Match is safe to call on a nil receiver.
func (s *Set) Match(pkg, version, vulnID string) bool {
	if s == nil {
		return false
	}
	for _, r := range s.rules {
		if r.VulnID != vulnID {
			continue
		}
		if r.PackageName != "" && r.PackageName != pkg {
			continue
		}
		if r.Version != "" && r.Version != "*" && r.Version != version {
			continue
		}
		return true
	}
	return false
}

// ParseRules parses a slice of free-form rule strings. Lines starting with
// `#` and blank lines are skipped. A descriptive error is returned at the
// first invalid line so the user can see exactly which one needs fixing.
func ParseRules(lines []string) (*Set, error) {
	out := &Set{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments: "lodash@*:GHSA-x  # comment"
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		r, err := parseOne(line)
		if err != nil {
			return nil, fmt.Errorf("ignore rule on line %d (%q): %w", i+1, raw, err)
		}
		out.rules = append(out.rules, r)
	}
	return out, nil
}

// LoadFile reads a `.nazarignore` file. Returns an empty set if the file
// doesn't exist (the file is optional).
func LoadFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Set{}, nil
		}
		return nil, fmt.Errorf("open ignore file: %w", err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ignore file: %w", err)
	}
	return ParseRules(lines)
}

// Merge returns a new Set containing the rules from a and b. Either may
// be nil.
func Merge(a, b *Set) *Set {
	out := &Set{}
	if a != nil {
		out.rules = append(out.rules, a.rules...)
	}
	if b != nil {
		out.rules = append(out.rules, b.rules...)
	}
	return out
}

// parseOne parses a single rule line. See the package doc for the grammar.
func parseOne(s string) (Rule, error) {
	// Forms:
	//   GHSA-xxx
	//   CVE-2024-1234
	//   pkg@ver:GHSA-xxx
	//   pkg@*:GHSA-xxx
	//   @scope/pkg@ver:GHSA-xxx     ← scoped npm names contain '/'
	if !strings.Contains(s, ":") {
		// "ID-only" form. Sanity-check: must look vaguely like an OSV ID.
		if !looksLikeID(s) {
			return Rule{}, fmt.Errorf("expected an OSV ID (e.g. GHSA-xxxx or CVE-2024-1234)")
		}
		return Rule{VulnID: s}, nil
	}

	colon := strings.LastIndex(s, ":")
	pkgPart := s[:colon]
	idPart := s[colon+1:]
	if !looksLikeID(idPart) {
		return Rule{}, fmt.Errorf("invalid OSV ID after ':' (got %q)", idPart)
	}

	// LastIndex finds the rightmost '@'. For "@scope/pkg" alone (no version)
	// that's the leading scope marker, which we don't want to split on.
	at := strings.LastIndex(pkgPart, "@")
	switch {
	case at < 0:
		// "pkg:GHSA-x" without @version is allowed: "any version".
		return Rule{PackageName: pkgPart, Version: "*", VulnID: idPart}, nil
	case at == 0:
		// pkgPart starts with '@'. Either a scoped name without version
		// ("@scope/pkg") or an invalid rule like "@1.2.3".
		if !strings.Contains(pkgPart, "/") {
			return Rule{}, fmt.Errorf("package@version requires both sides (got %q)", pkgPart)
		}
		return Rule{PackageName: pkgPart, Version: "*", VulnID: idPart}, nil
	}
	name := pkgPart[:at]
	ver := pkgPart[at+1:]
	if name == "" || ver == "" {
		return Rule{}, fmt.Errorf("package@version requires both sides")
	}
	return Rule{PackageName: name, Version: ver, VulnID: idPart}, nil
}

// looksLikeID is a deliberately loose sanity check. Anything starting with
// "GHSA-", "CVE-", or another well-known OSV prefix (PYSEC, GO, RUSTSEC,
// MAL, OSV) is accepted.
func looksLikeID(s string) bool {
	known := []string{"GHSA-", "CVE-", "PYSEC-", "GO-", "RUSTSEC-", "MAL-", "OSV-"}
	for _, p := range known {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
