package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultBaseURL is the public OSV.dev API endpoint.
const DefaultBaseURL = "https://api.osv.dev"

// maxBatchSize is OSV.dev's documented per-request query cap.
const maxBatchSize = 1000

// Client queries OSV.dev for vulnerabilities affecting installed packages.
// The zero value is not usable — construct with NewClient.
type Client struct {
	baseURL    string
	http       *http.Client
	userAgent  string
}

// Option customises a Client at construction time.
type Option func(*Client)

// WithBaseURL overrides the OSV API endpoint. Used in tests.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = u }
}

// WithHTTPClient swaps the underlying http.Client. Used in tests.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithUserAgent sets the User-Agent header. Defaults to "nazar/<version>".
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// NewClient returns a Client ready to talk to OSV.dev.
func NewClient(opts ...Option) *Client {
	c := &Client{
		baseURL:   DefaultBaseURL,
		http:      &http.Client{Timeout: 30 * time.Second},
		userAgent: "nazar/dev",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// QueryBatch looks up vulnerabilities for every coordinate in coords and
// returns a map keyed by Coordinate. Coordinates with no known vulns are
// still present in the map with an empty slice — callers can therefore
// distinguish "checked, none found" from "skipped".
//
// Coordinates are split into chunks of 1000 and dispatched sequentially.
// Errors from any one chunk abort the call.
func (c *Client) QueryBatch(ctx context.Context, coords []Coordinate) (map[Coordinate][]Vuln, error) {
	out := make(map[Coordinate][]Vuln, len(coords))

	for start := 0; start < len(coords); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(coords) {
			end = len(coords)
		}
		chunk := coords[start:end]

		queries := make([]Query, len(chunk))
		for i, co := range chunk {
			queries[i] = Query{
				Package: QueryPackage{Name: co.Name, Ecosystem: co.Ecosystem},
				Version: co.Version,
			}
		}

		resp, err := c.postBatch(ctx, BatchRequest{Queries: queries})
		if err != nil {
			return nil, fmt.Errorf("querybatch chunk [%d:%d]: %w", start, end, err)
		}

		// OSV guarantees positional alignment between queries and results.
		// If the server gives us fewer results than queries, treat the
		// missing tail as empty rather than panicking.
		for i, co := range chunk {
			if i < len(resp.Results) {
				out[co] = resp.Results[i].Vulns
			} else {
				out[co] = nil
			}
		}
	}

	return out, nil
}

// GetVuln fetches the full record for a single OSV vulnerability ID.
//
// Used to enrich the lean BatchResult with severity and summary text.
// Callers should cache the response — vuln records change rarely once
// published, so a per-ID cache is enough.
func (c *Client) GetVuln(ctx context.Context, id string) (*VulnDetail, error) {
	if id == "" {
		return nil, fmt.Errorf("vuln id is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// OSV occasionally has IDs in batch results that aren't queryable
		// (e.g. withdrawn entries). Return a placeholder rather than an
		// error so the caller can still display the ID.
		return &VulnDetail{ID: id}, nil
	}
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("osv returned %d for %s: %s", resp.StatusCode, id, bytes.TrimSpace(snippet))
	}

	var out VulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// postBatch is the raw HTTP wrapper around POST /v1/querybatch.
func (c *Client) postBatch(ctx context.Context, body BatchRequest) (*BatchResponse, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/querybatch", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		// Read a snippet of the body to surface OSV's own error message.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("osv returned %d: %s", resp.StatusCode, bytes.TrimSpace(snippet))
	}

	var out BatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}
