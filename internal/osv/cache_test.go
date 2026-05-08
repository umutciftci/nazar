package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCache_PutGetRoundtrip(t *testing.T) {
	c, err := NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	coord := Coordinate{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	want := []Vuln{{ID: "GHSA-x"}, {ID: "CVE-2021-23337"}}

	if err := c.Put(coord, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, hit := c.Get(coord)
	if !hit {
		t.Fatal("expected cache hit")
	}
	if len(got) != len(want) || got[0].ID != want[0].ID {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c, err := NewCache(t.TempDir(), time.Nanosecond) // expire instantly
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	coord := Coordinate{Ecosystem: "npm", Name: "x", Version: "1"}
	if err := c.Put(coord, []Vuln{{ID: "y"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, hit := c.Get(coord); hit {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestCache_Miss(t *testing.T) {
	c, err := NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	if _, hit := c.Get(Coordinate{Ecosystem: "npm", Name: "never", Version: "0"}); hit {
		t.Error("expected cache miss for unknown coordinate")
	}
}

func TestCache_ScopedPackages(t *testing.T) {
	// npm scoped names contain a slash; the cache must handle them.
	c, err := NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	coord := Coordinate{Ecosystem: "npm", Name: "@scope/utils", Version: "1.2.3"}
	if err := c.Put(coord, []Vuln{{ID: "scoped-1"}}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, hit := c.Get(coord)
	if !hit || len(got) != 1 || got[0].ID != "scoped-1" {
		t.Errorf("scoped package roundtrip failed: hit=%v got=%+v", hit, got)
	}
}

func TestLookup_HitsCacheBeforeNetwork(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var req BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := BatchResponse{Results: make([]BatchResult, len(req.Queries))}
		// Mark every requested coordinate as "vulnerable to FRESH-1".
		for i := range resp.Results {
			resp.Results[i].Vulns = []Vuln{{ID: "FRESH-1"}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cache, err := NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	client := NewClient(WithBaseURL(srv.URL))

	cached := Coordinate{Ecosystem: "npm", Name: "cached", Version: "1"}
	if err := cache.Put(cached, []Vuln{{ID: "CACHED-1"}}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	missed := Coordinate{Ecosystem: "npm", Name: "missed", Version: "2"}

	out, err := Lookup(context.Background(), client, cache, []Coordinate{cached, missed}, false)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if got := out[cached]; len(got) != 1 || got[0].ID != "CACHED-1" {
		t.Errorf("cached coord should return cached vuln, got %+v", got)
	}
	if got := out[missed]; len(got) != 1 || got[0].ID != "FRESH-1" {
		t.Errorf("missed coord should return fresh vuln, got %+v", got)
	}

	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Errorf("expected exactly 1 HTTP request (only for the miss), got %d", c)
	}

	// And the new coord must now be persisted.
	if _, hit := cache.Get(missed); !hit {
		t.Error("missed coord should be cached after Lookup")
	}
}

func TestLookup_BypassCache(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var req BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := BatchResponse{Results: make([]BatchResult, len(req.Queries))}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cache, err := NewCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	client := NewClient(WithBaseURL(srv.URL))

	c1 := Coordinate{Ecosystem: "npm", Name: "a", Version: "1"}
	_ = cache.Put(c1, []Vuln{{ID: "STALE"}})

	if _, err := Lookup(context.Background(), client, cache, []Coordinate{c1}, true); err != nil {
		t.Fatalf("Lookup bypass: %v", err)
	}
	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Errorf("expected 1 HTTP request when bypass=true, got %d", c)
	}
}
