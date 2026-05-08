package osv

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultDetailTTL is the freshness window for individual vuln-detail
// records. Once a vuln is published its severity rarely changes, so we
// keep details around longer than coordinate lookups (which have to
// account for *new* vulns landing).
const DefaultDetailTTL = 7 * 24 * time.Hour

// DetailCache stores VulnDetail records on disk by OSV ID.
//
// It mirrors the structure of Cache but is intentionally a separate type
// (and a separate directory) because the cardinality and lifecycle differ:
// coordinates churn with every dependency bump, IDs do not.
type DetailCache struct {
	root string
	ttl  time.Duration
}

// NewDetailCache returns a DetailCache rooted at root. If root is empty,
// "<user-cache>/nazar/vulns" is used.
func NewDetailCache(root string, ttl time.Duration) (*DetailCache, error) {
	if root == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("locate user cache dir: %w", err)
		}
		root = filepath.Join(base, "nazar", "vulns")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir %s: %w", root, err)
	}
	if ttl <= 0 {
		ttl = DefaultDetailTTL
	}
	return &DetailCache{root: root, ttl: ttl}, nil
}

// detailEntry is the on-disk shape for a single cached vuln detail.
type detailEntry struct {
	FetchedAt time.Time   `json:"fetched_at"`
	Detail    *VulnDetail `json:"detail"`
}

func (c *DetailCache) pathFor(id string) string {
	sum := sha1.Sum([]byte(id))
	hashed := hex.EncodeToString(sum[:])
	return filepath.Join(c.root, hashed[:2], hashed+".json")
}

// Get returns the cached detail for id, plus a hit flag.
func (c *DetailCache) Get(id string) (*VulnDetail, bool) {
	raw, err := os.ReadFile(c.pathFor(id))
	if err != nil {
		return nil, false
	}
	var ent detailEntry
	if err := json.Unmarshal(raw, &ent); err != nil {
		return nil, false
	}
	if time.Since(ent.FetchedAt) > c.ttl {
		return nil, false
	}
	return ent.Detail, true
}

// Put stores detail for id with the current timestamp.
func (c *DetailCache) Put(id string, detail *VulnDetail) error {
	path := c.pathFor(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir cache shard: %w", err)
	}
	ent := detailEntry{FetchedAt: time.Now(), Detail: detail}
	raw, err := json.Marshal(ent)
	if err != nil {
		return fmt.Errorf("marshal detail entry: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("write detail cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename detail cache: %w", err)
	}
	return nil
}

// ProgressFunc is called after each completed severity detail fetch.
// done is the number of IDs processed so far; total is the full count of
// cache-miss IDs being fetched. Cache hits are not reported.
type ProgressFunc func(done, total int)

// FetchDetails fetches the VulnDetail for every ID in ids, going to the
// network only on cache misses. It uses a small worker pool because
// /v1/vulns/{id} is one HTTP request per ID and otherwise quickly
// dominates total scan time on cold runs.
//
// `parallelism` of 0 or below defaults to 8. progress may be nil.
func FetchDetails(
	ctx context.Context,
	client *Client,
	cache *DetailCache,
	ids []string,
	bypassCache bool,
	parallelism int,
	progress ProgressFunc,
) (map[string]*VulnDetail, error) {
	out := make(map[string]*VulnDetail, len(ids))
	var misses []string

	for _, id := range ids {
		if !bypassCache {
			if d, hit := cache.Get(id); hit {
				out[id] = d
				continue
			}
		}
		misses = append(misses, id)
	}

	if len(misses) == 0 {
		return out, nil
	}

	if parallelism <= 0 {
		parallelism = 8
	}
	if parallelism > len(misses) {
		parallelism = len(misses)
	}

	type result struct {
		id     string
		detail *VulnDetail
		err    error
	}

	jobs := make(chan string)
	results := make(chan result)

	var wg sync.WaitGroup
	wg.Add(parallelism)
	for i := 0; i < parallelism; i++ {
		go func() {
			defer wg.Done()
			for id := range jobs {
				if ctx.Err() != nil {
					results <- result{id: id, err: ctx.Err()}
					continue
				}
				d, err := client.GetVuln(ctx, id)
				results <- result{id: id, detail: d, err: err}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, id := range misses {
			select {
			case <-ctx.Done():
				return
			case jobs <- id:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var errs []error
	var cacheErrs []error
	done := 0
	for r := range results {
		done++
		if progress != nil {
			progress(done, len(misses))
		}
		if r.err != nil {
			errs = append(errs, fmt.Errorf("get %s: %w", r.id, r.err))
			continue
		}
		out[r.id] = r.detail
		if err := cache.Put(r.id, r.detail); err != nil {
			cacheErrs = append(cacheErrs, err)
		}
	}

	if len(errs) > 0 {
		return out, fmt.Errorf("vuln detail fetch had errors: %w", errors.Join(errs...))
	}
	if len(cacheErrs) > 0 {
		return out, fmt.Errorf("partial detail-cache write failure: %w", errors.Join(cacheErrs...))
	}
	return out, nil
}
