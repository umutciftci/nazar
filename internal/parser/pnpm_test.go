package parser

import (
	"testing"
)

func testPnpmExpected(t *testing.T, pkgs []Package) {
	t.Helper()
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
			t.Errorf("%s: want Direct=false", c.name)
		}
	}
}

func TestParsePnpmLock_V6(t *testing.T) {
	pkgs, err := ParsePnpmLock("testdata/pnpm-lock-v6.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testPnpmExpected(t, pkgs)
}

func TestParsePnpmLock_V9(t *testing.T) {
	pkgs, err := ParsePnpmLock("testdata/pnpm-lock-v9.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	testPnpmExpected(t, pkgs)
}
