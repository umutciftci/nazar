package parser

import (
	"path/filepath"
	"testing"
)

// pkgIndex turns a slice of Package into a name@version → Package map for
// quick assertions in tests.
func pkgIndex(pkgs []Package) map[string]Package {
	m := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		m[p.Name+"@"+p.Version] = p
	}
	return m
}

func TestParseNPMLockfile_V1(t *testing.T) {
	pkgs, err := ParseNPMLockfile(filepath.Join("testdata", "v1.json"))
	if err != nil {
		t.Fatalf("parse v1: %v", err)
	}

	idx := pkgIndex(pkgs)

	// Both top-level and nested-resolution packages should be present.
	cases := []struct {
		key    string
		direct bool
	}{
		{"lodash@4.17.20", true},
		{"express@4.17.1", true},
		{"debug@4.3.1", true},  // direct top-level
		{"debug@2.6.9", false}, // nested under express
		{"accepts@1.3.7", false},
	}
	for _, c := range cases {
		got, ok := idx[c.key]
		if !ok {
			t.Errorf("v1: missing package %q", c.key)
			continue
		}
		if got.Direct != c.direct {
			t.Errorf("v1 %q direct: want %v, got %v", c.key, c.direct, got.Direct)
		}
	}
}

func TestParseNPMLockfile_V2(t *testing.T) {
	pkgs, err := ParseNPMLockfile(filepath.Join("testdata", "v2.json"))
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}

	idx := pkgIndex(pkgs)

	cases := []struct {
		key    string
		direct bool
	}{
		{"lodash@4.17.21", true},
		{"express@4.18.2", true},
		{"debug@4.3.4", true},  // direct
		{"debug@2.6.9", false}, // nested under express
	}
	for _, c := range cases {
		got, ok := idx[c.key]
		if !ok {
			t.Errorf("v2: missing package %q", c.key)
			continue
		}
		if got.Direct != c.direct {
			t.Errorf("v2 %q direct: want %v, got %v", c.key, c.direct, got.Direct)
		}
	}

	// The "" entry (root project) and the workspace-alias `link: true`
	// entry must both be skipped.
	for _, banned := range []string{"v2-fixture@1.0.0", "workspace-alias@"} {
		if _, present := idx[banned]; present {
			t.Errorf("v2: did not expect %q in output", banned)
		}
	}
}

func TestParseNPMLockfile_V3(t *testing.T) {
	pkgs, err := ParseNPMLockfile(filepath.Join("testdata", "v3.json"))
	if err != nil {
		t.Fatalf("parse v3: %v", err)
	}

	idx := pkgIndex(pkgs)

	wantDirect := []string{
		"react@18.2.0",
		"@scope/utils@1.0.3", // scoped package, top-level
		"loose-envify@1.4.0", // top-level (transitively pulled but installed at root)
	}
	for _, k := range wantDirect {
		got, ok := idx[k]
		if !ok {
			t.Errorf("v3: missing %q", k)
			continue
		}
		if !got.Direct {
			t.Errorf("v3 %q: expected Direct=true", k)
		}
	}

	// Nested loose-envify@1.3.0 under react should be present but transitive.
	if got, ok := idx["loose-envify@1.3.0"]; !ok {
		t.Error("v3: missing nested loose-envify@1.3.0")
	} else if got.Direct {
		t.Error("v3: nested loose-envify@1.3.0 should be Direct=false")
	}
}

func TestParseNPMLockfile_Empty(t *testing.T) {
	pkgs, err := ParseNPMLockfile(filepath.Join("testdata", "empty.json"))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("empty lockfile: expected 0 packages, got %d: %+v", len(pkgs), pkgs)
	}
}

func TestParseNPMLockfile_OutputIsSorted(t *testing.T) {
	pkgs, err := ParseNPMLockfile(filepath.Join("testdata", "v3.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := 1; i < len(pkgs); i++ {
		prev, cur := pkgs[i-1], pkgs[i]
		if prev.Name > cur.Name || (prev.Name == cur.Name && prev.Version > cur.Version) {
			t.Errorf("output not sorted: %v then %v", prev, cur)
		}
	}
}

func TestParseNPMLockfile_MissingFile(t *testing.T) {
	_, err := ParseNPMLockfile(filepath.Join("testdata", "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
