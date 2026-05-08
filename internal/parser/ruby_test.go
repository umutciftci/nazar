package parser

import (
	"testing"
)

func TestParseGemfileLock(t *testing.T) {
	pkgs, err := ParseGemfileLock("testdata/Gemfile.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected gems from the testdata GEM specs section.
	want := map[string]string{
		"actioncable":  "7.1.3",
		"actionpack":   "7.1.3",
		"rack":         "3.0.8",
		"rails":        "7.1.3",
		"tzinfo":       "2.0.6",
	}

	if len(pkgs) != len(want) {
		t.Errorf("got %d packages, want %d", len(pkgs), len(want))
	}

	byName := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		byName[p.Name] = p.Version
	}

	for name, wantVer := range want {
		if gotVer, ok := byName[name]; !ok {
			t.Errorf("missing gem %q", name)
		} else if gotVer != wantVer {
			t.Errorf("gem %q: got version %q, want %q", name, gotVer, wantVer)
		}
	}

	// Dependency constraints ("~> 2.0", ">= 1.0") must NOT appear.
	for _, p := range pkgs {
		if p.Version[0] < '0' || p.Version[0] > '9' {
			t.Errorf("gem %q has constraint-style version %q", p.Name, p.Version)
		}
	}
}

func TestParseGemfileLock_NoConstraints(t *testing.T) {
	// All returned versions must start with a digit (no "~>", ">=", etc.).
	pkgs, err := ParseGemfileLock("testdata/Gemfile.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range pkgs {
		if len(p.Version) == 0 || p.Version[0] < '0' || p.Version[0] > '9' {
			t.Errorf("constraint leaked into gem %q version %q", p.Name, p.Version)
		}
	}
}

func TestParseGemfileLock_NotExist(t *testing.T) {
	_, err := ParseGemfileLock("testdata/nonexistent.lock")
	if err == nil {
		t.Fatal("expected an error for missing file")
	}
}
