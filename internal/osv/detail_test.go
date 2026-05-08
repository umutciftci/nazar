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

func TestClient_GetVuln_Roundtrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/vulns/GHSA-xxxx" {
			http.Error(w, "bad route: "+r.URL.Path, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(VulnDetail{
			ID:               "GHSA-xxxx",
			Summary:          "test summary",
			DatabaseSpecific: &DatabaseSpecific{Severity: "HIGH"},
		})
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	got, err := c.GetVuln(context.Background(), "GHSA-xxxx")
	if err != nil {
		t.Fatalf("GetVuln: %v", err)
	}
	if got.Summary != "test summary" {
		t.Errorf("summary: got %q", got.Summary)
	}
	if DeriveSeverity(got) != SeverityHigh {
		t.Errorf("severity: want HIGH, got %s", DeriveSeverity(got))
	}
}

func TestClient_GetVuln_404ReturnsPlaceholder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "withdrawn", http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	got, err := c.GetVuln(context.Background(), "GHSA-gone")
	if err != nil {
		t.Fatalf("GetVuln on 404 should not error, got: %v", err)
	}
	if got == nil || got.ID != "GHSA-gone" {
		t.Errorf("expected placeholder VulnDetail, got %+v", got)
	}
}

func TestDetailCache_Roundtrip(t *testing.T) {
	cache, err := NewDetailCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewDetailCache: %v", err)
	}
	want := &VulnDetail{ID: "GHSA-1", Summary: "x"}
	if err := cache.Put("GHSA-1", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, hit := cache.Get("GHSA-1")
	if !hit {
		t.Fatal("expected hit")
	}
	if got.ID != want.ID || got.Summary != want.Summary {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestDetailCache_TTLExpiry(t *testing.T) {
	cache, err := NewDetailCache(t.TempDir(), time.Nanosecond)
	if err != nil {
		t.Fatalf("NewDetailCache: %v", err)
	}
	_ = cache.Put("X", &VulnDetail{ID: "X"})
	time.Sleep(2 * time.Millisecond)
	if _, hit := cache.Get("X"); hit {
		t.Error("expected miss after TTL")
	}
}

func TestFetchDetails_HitsCacheBeforeNetwork(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		id := r.URL.Path[len("/v1/vulns/"):]
		_ = json.NewEncoder(w).Encode(VulnDetail{
			ID:               id,
			DatabaseSpecific: &DatabaseSpecific{Severity: "MEDIUM"},
		})
	}))
	defer srv.Close()

	cache, err := NewDetailCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewDetailCache: %v", err)
	}
	client := NewClient(WithBaseURL(srv.URL))

	// Pre-seed cache for "CACHED-1".
	_ = cache.Put("CACHED-1", &VulnDetail{
		ID:               "CACHED-1",
		DatabaseSpecific: &DatabaseSpecific{Severity: "CRITICAL"},
	})

	got, err := FetchDetails(context.Background(), client, cache,
		[]string{"CACHED-1", "FRESH-1", "FRESH-2"}, false, 4, nil)
	if err != nil {
		t.Fatalf("FetchDetails: %v", err)
	}

	if c := atomic.LoadInt32(&calls); c != 2 {
		t.Errorf("expected 2 HTTP calls (only the misses), got %d", c)
	}
	if DeriveSeverity(got["CACHED-1"]) != SeverityCritical {
		t.Errorf("cached severity: want CRITICAL, got %s", DeriveSeverity(got["CACHED-1"]))
	}
	if DeriveSeverity(got["FRESH-1"]) != SeverityMedium {
		t.Errorf("fresh severity: want MEDIUM, got %s", DeriveSeverity(got["FRESH-1"]))
	}
	if _, ok := got["FRESH-2"]; !ok {
		t.Error("FRESH-2 should be present in result")
	}
}

func TestFetchDetails_RunsInParallel(t *testing.T) {
	// If parallelism is honoured, N concurrent slow requests should take
	// roughly the time of one, not N.
	const reqDelay = 50 * time.Millisecond

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(reqDelay)
		id := r.URL.Path[len("/v1/vulns/"):]
		_ = json.NewEncoder(w).Encode(VulnDetail{ID: id})
	}))
	defer srv.Close()

	cache, err := NewDetailCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatalf("NewDetailCache: %v", err)
	}
	client := NewClient(WithBaseURL(srv.URL))

	ids := []string{"A", "B", "C", "D", "E", "F", "G", "H"}
	start := time.Now()
	if _, err := FetchDetails(context.Background(), client, cache, ids, false, len(ids), nil); err != nil {
		t.Fatalf("FetchDetails: %v", err)
	}
	elapsed := time.Since(start)

	// Sequential would take ~8 * 50ms = 400ms. Parallel should take ~50ms
	// plus scheduling overhead. Allow a generous 250ms cap to keep the
	// test stable on busy CI runners but still meaningfully detect the
	// "all sequential" regression.
	if elapsed > 250*time.Millisecond {
		t.Errorf("parallel fetch took %v; expected well under 400ms (sequential)", elapsed)
	}
}
