package parser

import (
	"testing"
)

func TestParseRequirementsTxt(t *testing.T) {
	pkgs, err := ParseRequirementsTxt("testdata/requirements.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// django (range), -r, -e lines must be skipped.
	// requests[security] is a duplicate of requests==2.31.0 and must be deduped.
	// Expected: requests, flask, urllib3 (3 packages, all Direct=true).
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	cases := []struct{ name, version string }{
		{"requests", "2.31.0"},
		{"flask", "3.0.3"},
		{"urllib3", "2.0.7"},
	}
	for _, c := range cases {
		p, ok := byName[c.name]
		if !ok {
			t.Errorf("missing package %q", c.name)
			continue
		}
		if p.Version != c.version {
			t.Errorf("%s: want version %q, got %q", c.name, c.version, p.Version)
		}
		if !p.Direct {
			t.Errorf("%s: want Direct=true", c.name)
		}
	}
}

func TestParseRequirementsTxt_Empty(t *testing.T) {
	pkgs, err := ParseRequirementsTxt("testdata/empty.json") // reuse empty fixture
	if err != nil {
		// empty.json is valid JSON — open should succeed, scanner.Scan returns false immediately
		// so we get 0 packages and no error.
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("want 0 packages from empty file, got %d", len(pkgs))
	}
}

func TestParsePoetryLock(t *testing.T) {
	pkgs, err := ParsePoetryLock("testdata/poetry.lock")
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

	cases := []struct{ name, version string }{
		{"requests", "2.31.0"},
		{"flask", "3.0.3"},
		{"certifi", "2024.2.2"},
	}
	for _, c := range cases {
		p, ok := byName[c.name]
		if !ok {
			t.Errorf("missing package %q", c.name)
			continue
		}
		if p.Version != c.version {
			t.Errorf("%s: want version %q, got %q", c.name, c.version, p.Version)
		}
		if p.Direct {
			t.Errorf("%s: want Direct=false (poetry.lock is full closure)", c.name)
		}
	}
}

func TestParsePythonLockfile_Dispatch(t *testing.T) {
	pkgs, err := ParsePythonLockfile("testdata/requirements.txt")
	if err != nil {
		t.Fatalf("requirements dispatch: %v", err)
	}
	if len(pkgs) == 0 {
		t.Error("requirements dispatch returned 0 packages")
	}

	pkgs, err = ParsePythonLockfile("testdata/poetry.lock")
	if err != nil {
		t.Fatalf("poetry dispatch: %v", err)
	}
	if len(pkgs) == 0 {
		t.Error("poetry dispatch returned 0 packages")
	}
}
