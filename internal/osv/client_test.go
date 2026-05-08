package osv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_QueryBatch_Roundtrip(t *testing.T) {
	var got BatchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/querybatch" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		// Echo back two results: lodash has a CVE, debug does not.
		resp := BatchResponse{
			Results: []BatchResult{
				{Vulns: []Vuln{{ID: "GHSA-test-lodash"}}},
				{Vulns: nil},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	coords := []Coordinate{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "npm", Name: "debug", Version: "4.3.4"},
	}
	out, err := c.QueryBatch(context.Background(), coords)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}

	if len(got.Queries) != 2 {
		t.Errorf("expected 2 queries on the wire, got %d", len(got.Queries))
	}
	if got.Queries[0].Package.Name != "lodash" || got.Queries[0].Package.Ecosystem != "npm" {
		t.Errorf("first query payload wrong: %+v", got.Queries[0])
	}

	if len(out[coords[0]]) != 1 || out[coords[0]][0].ID != "GHSA-test-lodash" {
		t.Errorf("expected lodash vuln to be present, got %+v", out[coords[0]])
	}
	if len(out[coords[1]]) != 0 {
		t.Errorf("expected debug to have no vulns, got %+v", out[coords[1]])
	}
}

func TestClient_QueryBatch_ChunksAt1000(t *testing.T) {
	var batches int
	var totalQueries int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batches++
		var req BatchRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		totalQueries += len(req.Queries)
		// Echo back empty vulns for every query.
		resp := BatchResponse{Results: make([]BatchResult, len(req.Queries))}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	coords := make([]Coordinate, 2500)
	for i := range coords {
		coords[i] = Coordinate{Ecosystem: "npm", Name: "p", Version: "1.0.0"}
	}
	if _, err := c.QueryBatch(context.Background(), coords); err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if batches != 3 {
		t.Errorf("expected 3 chunks for 2500 queries (1000+1000+500), got %d", batches)
	}
	if totalQueries != 2500 {
		t.Errorf("expected 2500 total queries on the wire, got %d", totalQueries)
	}
}

func TestClient_QueryBatch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal kaboom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(WithBaseURL(srv.URL))
	_, err := c.QueryBatch(context.Background(), []Coordinate{{Ecosystem: "npm", Name: "x", Version: "1"}})
	if err == nil {
		t.Fatal("expected error on 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status 500, got: %v", err)
	}
}
