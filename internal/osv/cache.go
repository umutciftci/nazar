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
	"time"
)

// DefaultTTL is the cache freshness window. OSV publishes data slowly and
// nazar is meant to be cheap to run; one day strikes a reasonable balance
// between staleness and request volume.
const DefaultTTL = 24 * time.Hour

// Cache stores OSV lookup results on disk so repeated scans don't hammer
// the API. One file per coordinate keeps invalidation trivial — drop the
// directory and the next scan refetches everything.
type Cache struct {
	root string
	ttl  time.Duration
}

// NewCache returns a Cache rooted at root with the given freshness window.
// If root is empty, os.UserCacheDir()+"/nazar" is used.
func NewCache(root string, ttl time.Duration) (*Cache, error) {
	if root == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("locate user cache dir: %w", err)
		}
		root = filepath.Join(base, "nazar", "osv")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir %s: %w", root, err)
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{root: root, ttl: ttl}, nil
}

// cacheEntry is the on-disk representation of a single cached coordinate.
type cacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	Vulns     []Vuln    `json:"vulns"`
}

// pathFor returns the on-disk path for a coordinate's cache file.
//
// We hash the canonical string to avoid filesystem trouble with weird
// characters (npm scoped names, very long versions). The hash collisions
// risk is irrelevant here — it's a cache; on collision we'd just refetch.
func (c *Cache) pathFor(coord Coordinate) string {
	sum := sha1.Sum([]byte(coord.String()))
	hashed := hex.EncodeToString(sum[:])
	// Two-level shard so individual directories don't get massive.
	return filepath.Join(c.root, hashed[:2], hashed+".json")
}

// Get returns the cached vulns for coord, plus a boolean indicating
// whether the entry was present and still fresh.
func (c *Cache) Get(coord Coordinate) ([]Vuln, bool) {
	path := c.pathFor(coord)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var ent cacheEntry
	if err := json.Unmarshal(raw, &ent); err != nil {
		// Corrupt entry — treat as a miss so we refetch and overwrite.
		return nil, false
	}
	if time.Since(ent.FetchedAt) > c.ttl {
		return nil, false
	}
	return ent.Vulns, true
}

// Put stores vulns for coord with the current timestamp.
func (c *Cache) Put(coord Coordinate, vulns []Vuln) error {
	path := c.pathFor(coord)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir cache shard: %w", err)
	}
	ent := cacheEntry{FetchedAt: time.Now(), Vulns: vulns}
	raw, err := json.Marshal(ent)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	// Write to a temp file and rename so concurrent scans can't see a
	// half-written cache file. (Not concurrency-safe across processes,
	// but at least atomic per file.)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

// Lookup looks up every coord, serving fresh entries from cache and
// querying the client for the rest. Newly fetched entries are cached.
//
// Setting bypassCache=true skips reads (but still writes the fresh
// results back so subsequent runs benefit).
func Lookup(
	ctx context.Context,
	client *Client,
	cache *Cache,
	coords []Coordinate,
	bypassCache bool,
) (map[Coordinate][]Vuln, error) {
	out := make(map[Coordinate][]Vuln, len(coords))
	var misses []Coordinate

	for _, c := range coords {
		if !bypassCache {
			if v, hit := cache.Get(c); hit {
				out[c] = v
				continue
			}
		}
		misses = append(misses, c)
	}

	if len(misses) == 0 {
		return out, nil
	}

	fresh, err := client.QueryBatch(ctx, misses)
	if err != nil {
		return nil, err
	}

	var cacheErrs []error
	for c, v := range fresh {
		out[c] = v
		if err := cache.Put(c, v); err != nil {
			cacheErrs = append(cacheErrs, err)
		}
	}
	if len(cacheErrs) > 0 {
		// Cache write failures shouldn't kill the scan, but surface them.
		return out, fmt.Errorf("partial cache write failure: %w", errors.Join(cacheErrs...))
	}
	return out, nil
}
