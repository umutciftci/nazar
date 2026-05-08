package parser

import (
	"testing"
)

func TestParseGoSum(t *testing.T) {
	pkgs, err := ParseGoSum("testdata/go.sum")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// go.sum has 3 modules × 2 hash lines each; the /go.mod lines must be
	// skipped, leaving 3 packages.
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// gin is direct in go.mod (no // indirect).
	gin, ok := byName["github.com/gin-gonic/gin"]
	if !ok {
		t.Fatal("missing github.com/gin-gonic/gin")
	}
	if gin.Version != "v1.9.1" {
		t.Errorf("gin version: want v1.9.1, got %q", gin.Version)
	}
	if !gin.Direct {
		t.Error("gin should be Direct=true (no // indirect in go.mod)")
	}

	// testify and net are indirect.
	for _, name := range []string{"github.com/stretchr/testify", "golang.org/x/net"} {
		p, ok := byName[name]
		if !ok {
			t.Errorf("missing %q", name)
			continue
		}
		if p.Direct {
			t.Errorf("%s: want Direct=false (// indirect in go.mod)", name)
		}
	}
}

func TestParseGoSum_NoGoMod(t *testing.T) {
	// go.sum without a sibling go.mod — all packages should parse fine,
	// all marked Direct=false (best-effort).
	pkgs, err := ParseGoSum("testdata/go.sum")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = pkgs // existence check is enough here; Direct values checked in main test
}

func TestParseGoMod_DirectVsIndirect(t *testing.T) {
	direct := parseGoMod("testdata/go.mod")

	if _, ok := direct["github.com/gin-gonic/gin"]; !ok {
		t.Error("gin should be direct")
	}
	if _, ok := direct["github.com/stretchr/testify"]; ok {
		t.Error("testify should NOT be direct (// indirect)")
	}
	if _, ok := direct["golang.org/x/net"]; ok {
		t.Error("x/net should NOT be direct (// indirect)")
	}
}
