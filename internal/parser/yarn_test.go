package parser

import (
	"testing"
)

func TestParseYarnLock_Classic(t *testing.T) {
	pkgs, err := ParseYarnLock("testdata/yarn-classic.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// lodash appears twice in the key line but resolves to one version.
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	cases := []struct{ name, version string }{
		{"lodash", "4.17.21"},
		{"react", "18.2.0"},
		{"@scope/utils", "1.2.3"},
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
			t.Errorf("%s: want Direct=false (yarn.lock is full closure)", c.name)
		}
	}
}

func TestParseYarnLock_Berry(t *testing.T) {
	pkgs, err := ParseYarnLock("testdata/yarn-berry.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if p, ok := byName["lodash"]; !ok || p.Version != "4.17.21" {
		t.Errorf("lodash: want 4.17.21, got %+v", byName["lodash"])
	}
	if p, ok := byName["react"]; !ok || p.Version != "18.2.0" {
		t.Errorf("react: want 18.2.0, got %+v", p)
	}
	if p, ok := byName["@scope/utils"]; !ok || p.Version != "1.2.3" {
		t.Errorf("@scope/utils: want 1.2.3, got %+v", p)
	}
}
