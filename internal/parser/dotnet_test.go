package parser

import (
	"testing"
)

func TestParseDotnetPackagesLock(t *testing.T) {
	pkgs, err := ParseDotnetPackagesLock("testdata/packages.lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 distinct packages in the testdata (Newtonsoft.Json, Microsoft.Extensions.Logging,
	// Microsoft.Extensions.DependencyInjection).
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}

	byName := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	newtonsoft, ok := byName["Newtonsoft.Json"]
	if !ok {
		t.Fatal("missing Newtonsoft.Json")
	}
	if newtonsoft.Version != "13.0.3" {
		t.Errorf("Newtonsoft.Json version: got %q, want 13.0.3", newtonsoft.Version)
	}
	if !newtonsoft.Direct {
		t.Error("Newtonsoft.Json should be Direct")
	}

	logging, ok := byName["Microsoft.Extensions.Logging"]
	if !ok {
		t.Fatal("missing Microsoft.Extensions.Logging")
	}
	if logging.Direct {
		t.Error("Microsoft.Extensions.Logging should be Transitive (not Direct)")
	}

	di, ok := byName["Microsoft.Extensions.DependencyInjection"]
	if !ok {
		t.Fatal("missing Microsoft.Extensions.DependencyInjection")
	}
	if !di.Direct {
		t.Error("Microsoft.Extensions.DependencyInjection should be Direct")
	}
}

func TestParseDotnetPackagesLock_NotExist(t *testing.T) {
	_, err := ParseDotnetPackagesLock("testdata/nonexistent.json")
	if err == nil {
		t.Fatal("expected an error for missing file")
	}
}
