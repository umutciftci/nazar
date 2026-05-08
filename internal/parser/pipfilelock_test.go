package parser

import (
	"testing"
)

func TestParsePipfileLock(t *testing.T) {
	pkgs, err := ParsePipfileLock("testdata/Pipfile.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// requests, urllib3, pytest = 3 packages.
	// local-pkg has no version (editable) and must be skipped.
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	cases := []struct{ name, version string }{
		{"requests", "2.31.0"},
		{"urllib3", "2.2.1"},
		{"pytest", "7.4.0"},
	}
	for _, c := range cases {
		p, ok := byName[c.name]
		if !ok {
			t.Errorf("missing %q", c.name)
			continue
		}
		if p.Version != c.version {
			t.Errorf("%s: want %q, got %q", c.name, c.version, p.Version)
		}
		if p.Direct {
			t.Errorf("%s: want Direct=false", c.name)
		}
	}

	if _, ok := byName["local-pkg"]; ok {
		t.Error("local-pkg (editable, no version) should be excluded")
	}
}
