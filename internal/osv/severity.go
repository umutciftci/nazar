package osv

import (
	"strconv"
	"strings"
	"time"
)

// Severity is a coarse-grained vulnerability severity bucket. We normalise
// every OSV severity hint (CVSS vector, GHSA database_specific.severity, etc.)
// into one of these five values so the report can colour and aggregate them
// uniformly.
type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Rank gives a Severity a numeric weight. Useful for picking the worst
// severity across a project's package set with simple Max comparisons.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// MaxSeverity returns the worst severity in the slice. Returns SeverityUnknown
// if the slice is empty or contains only unknowns.
func MaxSeverity(svs []Severity) Severity {
	worst := SeverityUnknown
	for _, s := range svs {
		if s.Rank() > worst.Rank() {
			worst = s
		}
	}
	return worst
}

// VulnDetail is the subset of /v1/vulns/{id} we care about.
type VulnDetail struct {
	ID               string            `json:"id"`
	Published        string            `json:"published,omitempty"` // RFC3339, e.g. "2024-01-15T00:00:00Z"
	Modified         string            `json:"modified,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Severity         []SeverityScore   `json:"severity,omitempty"`
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
	Affected         []AffectedEntry   `json:"affected,omitempty"`
}

// PublishedTime parses the Published field into a time.Time.
// Returns the zero value if Published is empty or unparseable.
func (vd *VulnDetail) PublishedTime() time.Time {
	if vd == nil || vd.Published == "" {
		return time.Time{}
	}
	// Try common formats.
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, vd.Published); err == nil {
			return t
		}
	}
	return time.Time{}
}

// AffectedEntry describes which package versions are affected by a vuln.
type AffectedEntry struct {
	Package AffectedPackage `json:"package"`
	Ranges  []AffectedRange `json:"ranges,omitempty"`
}

// AffectedPackage names the package an AffectedEntry applies to.
type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// AffectedRange is a single version range (SEMVER, GIT, or ECOSYSTEM).
type AffectedRange struct {
	Type   string       `json:"type"`
	Events []RangeEvent `json:"events"`
}

// RangeEvent marks the start or end of an affected range. Exactly one of
// Introduced or Fixed will be non-empty per event.
type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// SeverityScore is a single OSV severity entry. The Score field for CVSS
// types is the full vector string (e.g. "CVSS:3.1/AV:N/AC:L/...").
type SeverityScore struct {
	Type  string `json:"type"`  // "CVSS_V2", "CVSS_V3", "CVSS_V4"
	Score string `json:"score"`
}

// DatabaseSpecific holds vendor-specific metadata. GitHub's GHSA entries
// expose a coarse severity string here ("LOW"/"MODERATE"/"HIGH"/"CRITICAL")
// which is much easier to consume than parsing the CVSS vector.
type DatabaseSpecific struct {
	Severity string `json:"severity,omitempty"`
}

// DeriveSeverity normalises the various severity hints in a VulnDetail
// into a single Severity bucket.
//
// Preference order:
//  1. database_specific.severity (cheap string lookup, used by GHSA)
//  2. The highest CVSS score among the severity[] entries
//
// Falls back to SeverityUnknown when neither is present or parseable.
func DeriveSeverity(vd *VulnDetail) Severity {
	if vd == nil {
		return SeverityUnknown
	}

	if vd.DatabaseSpecific != nil {
		if s := normaliseSeverityString(vd.DatabaseSpecific.Severity); s != SeverityUnknown {
			return s
		}
	}

	worst := SeverityUnknown
	for _, sev := range vd.Severity {
		if score, ok := parseCVSSBaseScore(sev.Score); ok {
			s := severityFromCVSS(score)
			if s.Rank() > worst.Rank() {
				worst = s
			}
		}
	}
	return worst
}

// normaliseSeverityString maps the various textual severity labels OSV
// sources use ("MODERATE", "MEDIUM", "Important", etc.) to our enum.
func normaliseSeverityString(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH", "IMPORTANT":
		return SeverityHigh
	case "MEDIUM", "MODERATE":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// severityFromCVSS turns a numeric CVSS base score into the standard
// FIRST.org qualitative bucket.
//
//	0.0          -> UNKNOWN (treated as "no impact"; OSV usually omits these)
//	0.1 – 3.9    -> LOW
//	4.0 – 6.9    -> MEDIUM
//	7.0 – 8.9    -> HIGH
//	9.0 – 10.0   -> CRITICAL
func severityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// parseCVSSBaseScore extracts the numeric base score from a CVSS vector
// string. Both bare numbers ("7.5") and full vectors ("CVSS:3.1/AV:N/...")
// are handled, with vectors scored via a small implementation of the
// CVSS v3.x base equation. CVSS v4 vectors fall through (we return false)
// — for v4 we'll only have severity if database_specific provides it.
//
// Returns (score, true) on success.
func parseCVSSBaseScore(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}

	// Bare number ("7.5", "9.8" etc.).
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return v, true
	}

	// CVSS vector. Looks like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
	if !strings.HasPrefix(strings.ToUpper(s), "CVSS:") {
		return 0, false
	}
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return 0, false
	}

	// CVSS v3 only. v4 uses a different metric set.
	header := strings.ToUpper(parts[0])
	if !strings.HasPrefix(header, "CVSS:3.") {
		return 0, false
	}

	metrics := map[string]string{}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[strings.ToUpper(kv[0])] = strings.ToUpper(kv[1])
	}

	score, ok := cvss3Score(metrics)
	if !ok {
		return 0, false
	}
	return score, true
}

// cvss3Score implements the CVSS v3.1 base score formula.
//
// Reference: https://www.first.org/cvss/v3.1/specification-document
//
// We only need the base score (no temporal/environmental), which is what
// OSV publishes. The formula is straightforward but verbose; we keep the
// full table inline so it's auditable.
func cvss3Score(m map[string]string) (float64, bool) {
	av, avOK := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac, acOK := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, uiOK := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	c, cOK := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[m["C"]]
	i, iOK := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[m["I"]]
	a, aOK := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}[m["A"]]
	scope := m["S"] // "U" (unchanged) or "C" (changed)

	// PR depends on Scope.
	prTable := map[string]map[string]float64{
		"U": {"N": 0.85, "L": 0.62, "H": 0.27},
		"C": {"N": 0.85, "L": 0.68, "H": 0.5},
	}
	prMap, prOK := prTable[scope]
	pr, prKeyOK := 0.0, false
	if prOK {
		pr, prKeyOK = prMap[m["PR"]]
	}

	if !(avOK && acOK && uiOK && cOK && iOK && aOK && prOK && prKeyOK) {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	}
	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0, true
	}
	var base float64
	if scope == "U" {
		base = roundUp(min(impact+exploitability, 10))
	} else {
		base = roundUp(min(1.08*(impact+exploitability), 10))
	}
	return base, true
}

// roundUp rounds to one decimal place using CVSS's "round up" rule (any
// fractional component rounds upward).
func roundUp(x float64) float64 {
	scaled := x * 10
	intPart := float64(int(scaled))
	if scaled-intPart > 0 {
		return (intPart + 1) / 10
	}
	return intPart / 10
}

// DeriveFixedVersion finds the fixed version for (ecosystem, pkgName) inside
// vd.Affected. It returns the last SEMVER fixed event for the matching entry —
// the version a user should upgrade to in order to resolve the vulnerability.
// Returns "" when no fix is recorded (e.g. the issue is still open).
func DeriveFixedVersion(vd *VulnDetail, ecosystem, pkgName string) string {
	if vd == nil {
		return ""
	}
	// When ecosystem/pkgName are empty (e.g. nazar show), return the first
	// fixed version found across all affected entries.
	if ecosystem == "" {
		for _, a := range vd.Affected {
			for _, r := range a.Ranges {
				if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
					continue
				}
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
		return ""
	}
	for _, a := range vd.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, ecosystem) {
			continue
		}
		if !strings.EqualFold(a.Package.Name, pkgName) {
			continue
		}
		// Collect every SEMVER fixed event and return the last one.
		// For a vuln with a single range [introduced:0, fixed:X], this is X.
		// For a vuln re-introduced and re-fixed, this is the most recent fix.
		last := ""
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed != "" {
					last = e.Fixed
				}
			}
		}
		if last != "" {
			return last
		}
	}
	return ""
}

func pow(base float64, exp int) float64 {
	out := 1.0
	for i := 0; i < exp; i++ {
		out *= base
	}
	return out
}
