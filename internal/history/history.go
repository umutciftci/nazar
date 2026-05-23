// Package history persists scan results so nazar diff can show what changed.
package history

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/umutciftci/nazar/internal/osv"
	"github.com/umutciftci/nazar/internal/report"
)

// Item is one (project, package, vuln) triple stored in history.
type Item struct {
	Project  string       `json:"project"`
	Package  string       `json:"package"`
	Version  string       `json:"version"`
	VulnID   string       `json:"vuln_id"`
	Severity osv.Severity `json:"severity"`
	FixedIn  string       `json:"fixed_in,omitempty"`
}

// Snapshot is the full state of a scan at a point in time.
type Snapshot struct {
	Timestamp time.Time `json:"timestamp"`
	Root      string    `json:"root"`
	Items     []Item    `json:"items"`
}

// FromResults converts scan results into a Snapshot.
func FromResults(root string, results []report.Result) *Snapshot {
	s := &Snapshot{
		Timestamp: time.Now().UTC(),
		Root:      root,
	}
	for _, r := range results {
		for _, pv := range r.Packages {
			for _, v := range pv.Vulns {
				s.Items = append(s.Items, Item{
					Project:  r.Project.Path,
					Package:  pv.Package.Name,
					Version:  pv.Package.Version,
					VulnID:   v.ID,
					Severity: v.Severity,
					FixedIn:  v.FixedIn,
				})
			}
		}
	}
	return s
}

// Save writes the snapshot to the history file for root.
func Save(s *Snapshot, historyDir string) error {
	if err := os.MkdirAll(historyDir, 0o755); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(historyDir, key(s.Root)), raw, 0o644)
}

// Load returns the last saved snapshot for root, or nil if none exists.
func Load(root, historyDir string) (*Snapshot, error) {
	raw, err := os.ReadFile(filepath.Join(historyDir, key(root)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse history: %w", err)
	}
	return &s, nil
}

// Diff compares two snapshots and returns what changed.
type Diff struct {
	New      []Item // appeared in current, absent in prev
	Resolved []Item // present in prev, absent in current
}

// Compare returns a Diff between prev (older) and curr (newer).
// If prev is nil, all items in curr are considered new.
func Compare(prev, curr *Snapshot) Diff {
	currSet := make(map[string]Item, len(curr.Items))
	for _, it := range curr.Items {
		currSet[itemKey(it)] = it
	}

	if prev == nil {
		return Diff{New: append([]Item(nil), curr.Items...)}
	}

	prevSet := make(map[string]Item, len(prev.Items))
	for _, it := range prev.Items {
		prevSet[itemKey(it)] = it
	}

	var d Diff
	for k, it := range currSet {
		if _, ok := prevSet[k]; !ok {
			d.New = append(d.New, it)
		}
	}
	for k, it := range prevSet {
		if _, ok := currSet[k]; !ok {
			d.Resolved = append(d.Resolved, it)
		}
	}
	return d
}

func key(root string) string {
	sum := sha256.Sum256([]byte(root))
	return fmt.Sprintf("%x.json", sum[:8])
}

func itemKey(it Item) string {
	return it.Project + "|" + it.Package + "@" + it.Version + "|" + it.VulnID
}

// HistoryDir returns the default directory for history files.
func HistoryDir(cacheDir string) string {
	if cacheDir != "" {
		return filepath.Join(cacheDir, "history")
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "nazar", "history")
	}
	return filepath.Join(base, "nazar", "history")
}
