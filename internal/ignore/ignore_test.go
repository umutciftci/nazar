package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRules_IDOnly(t *testing.T) {
	s, err := ParseRules([]string{"GHSA-xxxx-xxxx-xxxx"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if !s.Match("anything", "1.0.0", "GHSA-xxxx-xxxx-xxxx") {
		t.Error("ID-only rule should match any package + version")
	}
	if s.Match("anything", "1.0.0", "CVE-9999-9999") {
		t.Error("rule should not match unrelated vuln")
	}
}

func TestParseRules_PackageVersion(t *testing.T) {
	s, err := ParseRules([]string{"lodash@4.17.20:GHSA-aa"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if !s.Match("lodash", "4.17.20", "GHSA-aa") {
		t.Error("pkg@ver:id should match exact triple")
	}
	if s.Match("lodash", "4.17.21", "GHSA-aa") {
		t.Error("pkg@ver:id should not match wrong version")
	}
	if s.Match("axios", "4.17.20", "GHSA-aa") {
		t.Error("pkg@ver:id should not match wrong package")
	}
}

func TestParseRules_StarVersion(t *testing.T) {
	s, err := ParseRules([]string{"lodash@*:GHSA-bb"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if !s.Match("lodash", "4.17.20", "GHSA-bb") {
		t.Error("pkg@*:id should match any version of pkg")
	}
	if s.Match("axios", "4.17.20", "GHSA-bb") {
		t.Error("pkg@*:id should not match wrong package")
	}
}

func TestParseRules_PackageOnly(t *testing.T) {
	s, err := ParseRules([]string{"lodash:GHSA-cc"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if !s.Match("lodash", "1.0.0", "GHSA-cc") {
		t.Error("pkg:id (no @version) should match any version")
	}
	if s.Match("debug", "1.0.0", "GHSA-cc") {
		t.Error("pkg:id should not match other packages")
	}
}

func TestParseRules_Scoped(t *testing.T) {
	s, err := ParseRules([]string{"@scope/utils@1.2.3:GHSA-dd"})
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if !s.Match("@scope/utils", "1.2.3", "GHSA-dd") {
		t.Error("scoped pkg should match")
	}
}

func TestParseRules_CommentsAndBlankLines(t *testing.T) {
	in := []string{
		"# this is a comment",
		"",
		"   ",
		"GHSA-xx  # inline comment",
	}
	s, err := ParseRules(in)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if !s.Match("any", "v", "GHSA-xx") {
		t.Error("rule with inline comment should still parse")
	}
}

func TestParseRules_RejectsGarbage(t *testing.T) {
	cases := []string{
		"not-an-id",
		"lodash@",
		"@4.17.20:GHSA-x",
		"lodash@1:notanid",
	}
	for _, c := range cases {
		if _, err := ParseRules([]string{c}); err == nil {
			t.Errorf("expected ParseRules to reject %q", c)
		}
	}
}

func TestLoadFile_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".nazarignore")
	contents := `# our accepted CVEs
GHSA-aa
lodash@4.17.20:GHSA-bb
@scope/utils@*:CVE-2024-0001
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	s, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !s.Match("anything", "v", "GHSA-aa") {
		t.Error("loaded rule GHSA-aa should match")
	}
	if !s.Match("lodash", "4.17.20", "GHSA-bb") {
		t.Error("loaded pkg@ver rule should match")
	}
	if !s.Match("@scope/utils", "9.9.9", "CVE-2024-0001") {
		t.Error("loaded scoped pkg@* rule should match")
	}
}

func TestLoadFile_MissingFileIsEmpty(t *testing.T) {
	s, err := LoadFile(filepath.Join(t.TempDir(), "no-such-file"))
	if err != nil {
		t.Fatalf("LoadFile on missing file should not error: %v", err)
	}
	if !s.IsEmpty() {
		t.Error("missing file should yield empty set")
	}
}

func TestMerge(t *testing.T) {
	a, _ := ParseRules([]string{"GHSA-aa"})
	b, _ := ParseRules([]string{"GHSA-bb"})
	m := Merge(a, b)
	if !m.Match("x", "y", "GHSA-aa") || !m.Match("x", "y", "GHSA-bb") {
		t.Error("merged set should match rules from both sources")
	}
	if Merge(nil, nil).IsEmpty() == false {
		t.Error("merging two nils should yield empty set")
	}
}
