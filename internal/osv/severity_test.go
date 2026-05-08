package osv

import "testing"

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		s    Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityUnknown, 0},
		{Severity(""), 0},
	}
	for _, c := range cases {
		if got := c.s.Rank(); got != c.want {
			t.Errorf("Rank(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestMaxSeverity(t *testing.T) {
	got := MaxSeverity([]Severity{SeverityLow, SeverityHigh, SeverityMedium})
	if got != SeverityHigh {
		t.Errorf("want HIGH, got %s", got)
	}
	if got := MaxSeverity(nil); got != SeverityUnknown {
		t.Errorf("empty: want UNKNOWN, got %s", got)
	}
	if got := MaxSeverity([]Severity{SeverityCritical, SeverityLow}); got != SeverityCritical {
		t.Errorf("want CRITICAL, got %s", got)
	}
}

func TestNormaliseSeverityString(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL":  SeverityCritical,
		"high":      SeverityHigh,
		"Important": SeverityHigh,
		"MODERATE":  SeverityMedium,
		"medium":    SeverityMedium,
		"low":       SeverityLow,
		"":          SeverityUnknown,
		"weird":     SeverityUnknown,
	}
	for in, want := range cases {
		if got := normaliseSeverityString(in); got != want {
			t.Errorf("normaliseSeverityString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{0, SeverityUnknown},
		{0.5, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10.0, SeverityCritical},
	}
	for _, c := range cases {
		if got := severityFromCVSS(c.score); got != c.want {
			t.Errorf("severityFromCVSS(%v) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestParseCVSSBaseScore_BareNumber(t *testing.T) {
	got, ok := parseCVSSBaseScore("9.8")
	if !ok || got != 9.8 {
		t.Errorf("got (%v, %v), want (9.8, true)", got, ok)
	}
}

func TestParseCVSSBaseScore_V3Vector(t *testing.T) {
	// Classic "remote, network attack vector, no privileges, no UI, full
	// CIA impact" — should be 9.8 (CRITICAL).
	got, ok := parseCVSSBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if !ok {
		t.Fatal("failed to parse known-good v3.1 vector")
	}
	if got != 9.8 {
		t.Errorf("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> %v, want 9.8", got)
	}
}

func TestParseCVSSBaseScore_V3MediumVector(t *testing.T) {
	// CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L should land in MEDIUM.
	got, ok := parseCVSSBaseScore("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L")
	if !ok {
		t.Fatal("failed to parse v3.1 medium vector")
	}
	if severityFromCVSS(got) != SeverityMedium {
		t.Errorf("score %v should be MEDIUM, derived %s", got, severityFromCVSS(got))
	}
}

func TestParseCVSSBaseScore_V4NotSupported(t *testing.T) {
	// We don't implement CVSS v4 scoring; should return false so the caller
	// falls back to database_specific.severity.
	if _, ok := parseCVSSBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"); ok {
		t.Error("CVSS v4 should not be parsed by this implementation")
	}
}

func TestDeriveSeverity_PrefersDatabaseSpecific(t *testing.T) {
	vd := &VulnDetail{
		Severity: []SeverityScore{{Type: "CVSS_V3", Score: "1.0"}}, // would be LOW
		DatabaseSpecific: &DatabaseSpecific{Severity: "CRITICAL"},
	}
	if got := DeriveSeverity(vd); got != SeverityCritical {
		t.Errorf("DeriveSeverity should prefer database_specific (CRITICAL), got %s", got)
	}
}

func TestDeriveSeverity_FallsBackToCVSS(t *testing.T) {
	vd := &VulnDetail{
		Severity: []SeverityScore{
			{Type: "CVSS_V3", Score: "5.5"},
			{Type: "CVSS_V3", Score: "9.1"}, // worst -> CRITICAL
		},
	}
	if got := DeriveSeverity(vd); got != SeverityCritical {
		t.Errorf("want CRITICAL from worst CVSS, got %s", got)
	}
}

func TestDeriveSeverity_Unknown(t *testing.T) {
	if got := DeriveSeverity(&VulnDetail{}); got != SeverityUnknown {
		t.Errorf("empty detail: want UNKNOWN, got %s", got)
	}
	if got := DeriveSeverity(nil); got != SeverityUnknown {
		t.Errorf("nil detail: want UNKNOWN, got %s", got)
	}
}
