package parser

import (
	"testing"
)

func TestParseCargoLock(t *testing.T) {
	pkgs, err := ParseCargoLock("testdata/Cargo.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// myapp (workspace member, no source) and my-git-dep (git source) must
	// be skipped. Only serde and tokio have "registry+" sources.
	if len(pkgs) != 2 {
		t.Fatalf("want 2 packages, got %d: %v", len(pkgs), pkgs)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	cases := []struct{ name, version string }{
		{"serde", "1.0.197"},
		{"tokio", "1.35.1"},
	}
	for _, c := range cases {
		p, ok := byName[c.name]
		if !ok {
			t.Errorf("missing crate %q", c.name)
			continue
		}
		if p.Version != c.version {
			t.Errorf("%s: want version %q, got %q", c.name, c.version, p.Version)
		}
		if p.Direct {
			t.Errorf("%s: want Direct=false (Cargo.lock is full closure)", c.name)
		}
	}

	// Workspace member and git dep must not appear.
	if _, ok := byName["myapp"]; ok {
		t.Error("myapp (workspace member) should be excluded")
	}
	if _, ok := byName["my-git-dep"]; ok {
		t.Error("my-git-dep (git source) should be excluded")
	}
}
