// Package osv talks to OSV.dev — Google's open vulnerability database.
//
// We use the /v1/querybatch endpoint exclusively: it accepts up to 1000
// (ecosystem, name, version) queries per request and returns the matching
// vulnerability IDs. That's enough for the "this project has N CVEs" view
// nazar prints. Full vulnerability details (severity, summary, references)
// can be fetched lazily later via /v1/vulns/{id}.
package osv

// Query is a single vulnerability lookup against OSV.dev.
//
// The JSON shape mirrors what OSV expects on the wire:
//
//	{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}
type Query struct {
	Package QueryPackage `json:"package"`
	Version string       `json:"version"`
}

// QueryPackage names the package to query in a particular ecosystem.
// OSV ecosystem identifiers are case-sensitive: "npm", "PyPI", "Go", etc.
type QueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// BatchRequest is the body we POST to /v1/querybatch.
type BatchRequest struct {
	Queries []Query `json:"queries"`
}

// BatchResponse is the JSON returned by /v1/querybatch.
//
// The Results slice lines up positionally with BatchRequest.Queries — the
// OSV docs explicitly guarantee this. Each Result.Vulns may be empty.
type BatchResponse struct {
	Results []BatchResult `json:"results"`
}

// BatchResult is the per-query response slot.
type BatchResult struct {
	Vulns []Vuln `json:"vulns"`
}

// Vuln is the minimal vulnerability info /v1/querybatch returns, optionally
// enriched by FetchDetails with a derived Severity, short Summary, and the
// earliest known FixedIn version for the affected package.
//
// ID is an OSV identifier (e.g. "GHSA-xxxx-xxxx-xxxx" or "CVE-2024-1234");
// Modified is an ISO-8601 timestamp the caller can use as a cache-busting
// hint. Severity and FixedIn are empty until details are fetched.
type Vuln struct {
	ID       string   `json:"id"`
	Modified string   `json:"modified,omitempty"`
	Severity Severity `json:"severity,omitempty"`
	Summary  string   `json:"summary,omitempty"`
	FixedIn  string   `json:"fixed_in,omitempty"`
}

// Coordinate is the local cache key for a single (ecosystem, name, version)
// triple. It also serves as a stable identity across the parser→osv→report
// pipeline so we don't need to thread Query values around.
type Coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

// String returns a canonical, filename-safe form of the coordinate.
// Used as the cache filename; npm scoped packages contain '/' so we
// replace it with the URL-safe '%' sentinel.
func (c Coordinate) String() string {
	return c.Ecosystem + ":" + sanitize(c.Name) + "@" + c.Version
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '/':
			out = append(out, '%')
		case ch == 0:
			// drop
		default:
			out = append(out, ch)
		}
	}
	return string(out)
}
