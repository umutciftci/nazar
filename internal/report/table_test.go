package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/parser"
	"github.com/umutciftci/nazar/internal/scanner"
)

func sampleResults() []Result {
	return []Result{
		{
			Project: scanner.Project{
				Path:         "/tmp/scan/app-a",
				Ecosystem:    scanner.EcosystemNPM,
				LockfilePath: "/tmp/scan/app-a/package-lock.json",
			},
			Packages: []PackageVulns{
				{
					Package: parser.Package{Name: "lodash", Version: "4.17.20", Direct: true},
					Vulns: []osv.Vuln{
						{ID: "GHSA-xxxx", Severity: osv.SeverityCritical, Summary: "Prototype pollution in lodash"},
						{ID: "CVE-2021-23337", Severity: osv.SeverityHigh},
					},
				},
				{
					Package: parser.Package{Name: "debug", Version: "4.3.4", Direct: false},
					Vulns:   []osv.Vuln{{ID: "GHSA-medi", Severity: osv.SeverityMedium}},
				},
			},
		},
		{
			Project: scanner.Project{
				Path:         "/tmp/scan/app-b",
				Ecosystem:    scanner.EcosystemNPM,
				LockfilePath: "/tmp/scan/app-b/package-lock.json",
			},
			Packages: []PackageVulns{
				{Package: parser.Package{Name: "react", Version: "18.2.0", Direct: true}},
			},
		},
	}
}

func TestRenderText_IncludesProjectsAndCounts(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, "/tmp/scan", false, sampleResults(), RenderOptions{ShowDetail: true})
	out := buf.String()

	mustContain := []string{
		"app-a", "app-b",
		"npm",
		"2 project(s)",
		"crit", // summary line
		"vulnerabilities",
		"Vulnerable packages:",
		"lodash@4.17.20",
		"GHSA-xxxx",
		"CVE-2021-23337",
		"[CRITICAL]",
		"[MEDIUM]",
		"Prototype pollution in lodash", // summary text
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("RenderText output missing %q. Got:\n%s", want, out)
		}
	}
}

func TestRenderText_OfflineMode(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, "/tmp/scan", true, sampleResults(), RenderOptions{})
	out := buf.String()

	if !strings.Contains(out, "offline mode") {
		t.Errorf("expected 'offline mode' note, got:\n%s", out)
	}
	if strings.Contains(out, "Vulnerable packages:") {
		t.Errorf("offline mode must not show vuln detail section, got:\n%s", out)
	}
	if !strings.Contains(out, "vulnerability check skipped") {
		t.Errorf("offline mode summary should say skipped, got:\n%s", out)
	}
}

func TestRenderText_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, "/tmp/scan", false, nil, RenderOptions{})
	if !strings.Contains(buf.String(), "No projects detected.") {
		t.Errorf("expected 'No projects detected.' in output, got:\n%s", buf.String())
	}
}

func TestRenderText_IgnoredCount(t *testing.T) {
	results := sampleResults()
	results[0].IgnoredCount = 3
	var buf bytes.Buffer
	RenderText(&buf, "/tmp/scan", false, results, RenderOptions{})
	if !strings.Contains(buf.String(), "3 vulnerability match(es) suppressed") {
		t.Errorf("expected ignored-suppression note, got:\n%s", buf.String())
	}
}

func TestRenderText_SeverityFilter(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, "/tmp/scan", false, sampleResults(), RenderOptions{MinSeverity: osv.SeverityCritical, ShowDetail: true})
	out := buf.String()

	// CRITICAL vuln should appear.
	if !strings.Contains(out, "GHSA-xxxx") {
		t.Errorf("expected CRITICAL vuln in filtered output, got:\n%s", out)
	}
	// MEDIUM vuln should be filtered out.
	if strings.Contains(out, "GHSA-medi") {
		t.Errorf("MEDIUM vuln should be hidden when filtering to CRITICAL+, got:\n%s", out)
	}
	// Filter note should be present.
	if !strings.Contains(out, "filtered to CRITICAL") {
		t.Errorf("expected filter note in output, got:\n%s", out)
	}
}

func TestRenderJSON_ProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, "/tmp/scan", false, sampleResults(), RenderOptions{}); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var doc struct {
		Root     string `json:"root"`
		Offline  bool   `json:"offline"`
		Projects []struct {
			Project struct {
				Path      string `json:"path"`
				Ecosystem string `json:"ecosystem"`
			} `json:"project"`
			Packages []PackageVulns `json:"packages"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if doc.Root != "/tmp/scan" {
		t.Errorf("root: want /tmp/scan, got %q", doc.Root)
	}
	if doc.Offline {
		t.Error("offline should be false")
	}
	if len(doc.Projects) != 2 {
		t.Fatalf("projects: want 2, got %d", len(doc.Projects))
	}
	if len(doc.Projects[0].Packages[0].Vulns) != 2 {
		t.Errorf("app-a lodash: want 2 vulns, got %d", len(doc.Projects[0].Packages[0].Vulns))
	}
	if doc.Projects[0].Packages[0].Vulns[0].Severity != osv.SeverityCritical {
		t.Errorf("severity should round-trip via JSON")
	}
}

func TestRenderJSON_OfflineFlagAndIgnoredTotal(t *testing.T) {
	results := sampleResults()
	results[0].IgnoredCount = 2
	var buf bytes.Buffer
	if err := RenderJSON(&buf, "/tmp/scan", true, results, RenderOptions{}); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		Offline      bool `json:"offline"`
		IgnoredTotal int  `json:"ignored_total"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !doc.Offline {
		t.Error("offline=true should round-trip")
	}
	if doc.IgnoredTotal != 2 {
		t.Errorf("ignored_total: want 2, got %d", doc.IgnoredTotal)
	}
}

func TestRenderText_DefaultHidesDetail(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, "/tmp/scan", false, sampleResults(), RenderOptions{})
	out := buf.String()
	// Default (ShowDetail=false) must NOT show the detail section.
	if strings.Contains(out, "Vulnerable packages:") {
		t.Errorf("detail section should be hidden by default, got:\n%s", out)
	}
	// But the hint to enable it must be visible.
	if !strings.Contains(out, "--detail") {
		t.Errorf("expected --detail hint in default output, got:\n%s", out)
	}
}

func TestRenderText_ProjectFilter(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, "/tmp/scan", false, sampleResults(), RenderOptions{ProjectFilter: "app-a"})
	out := buf.String()
	// app-a detail must be shown.
	if !strings.Contains(out, "lodash@4.17.20") {
		t.Errorf("expected app-a detail, got:\n%s", out)
	}
	// app-b has no vulns so nothing to check there.
}

func TestRenderCSV_ProducesRows(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCSV(&buf, "/tmp/scan", sampleResults()); err != nil {
		t.Fatalf("RenderCSV: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// 1 header + 3 vuln rows (GHSA-xxxx, CVE-2021-23337, GHSA-medi)
	if len(lines) != 4 {
		t.Fatalf("want 4 lines (header+3), got %d:\n%s", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "project,ecosystem") {
		t.Errorf("first line should be CSV header, got: %s", lines[0])
	}
	if !strings.Contains(buf.String(), "lodash") {
		t.Errorf("CSV should contain lodash row")
	}
	if !strings.Contains(buf.String(), "GHSA-xxxx") {
		t.Errorf("CSV should contain GHSA-xxxx")
	}
}
