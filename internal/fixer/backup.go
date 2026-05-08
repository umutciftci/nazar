// Package fixer applies package-manager upgrades for known-vulnerable packages,
// backing up lockfiles first so every change can be rolled back.
package fixer

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const manifestFile = "manifest.json"

// Manifest records every lockfile that was backed up in one fix session.
// It is written to the session directory so --rollback can restore everything.
type Manifest struct {
	Timestamp time.Time `json:"timestamp"`
	Entries   []Entry   `json:"entries"`
}

// Entry is one backed-up lockfile.
type Entry struct {
	LockfilePath string `json:"lockfile_path"` // original absolute path
	BackupPath   string `json:"backup_path"`   // where the copy lives
}

// BackupLockfile copies the lockfile at lockfilePath into backupDir and
// returns the resulting Entry. A random suffix prevents collisions when the
// same filename appears in multiple projects.
func BackupLockfile(lockfilePath, backupDir string) (Entry, error) {
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return Entry{}, fmt.Errorf("create backup dir: %w", err)
	}

	var rnd [6]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return Entry{}, fmt.Errorf("gen random suffix: %w", err)
	}
	name := filepath.Base(lockfilePath) + "." + hex.EncodeToString(rnd[:])
	backupPath := filepath.Join(backupDir, name)

	if err := copyFile(lockfilePath, backupPath); err != nil {
		return Entry{}, fmt.Errorf("copy lockfile: %w", err)
	}
	return Entry{LockfilePath: lockfilePath, BackupPath: backupPath}, nil
}

// SaveManifest writes m as JSON to sessionDir/manifest.json.
func SaveManifest(sessionDir string, m *Manifest) error {
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sessionDir, manifestFile), raw, 0o644)
}

// LoadLatestManifest scans backupRoot for subdirectories that contain a
// manifest.json, returning the one with the most recent modification time.
func LoadLatestManifest(backupRoot string) (*Manifest, string, error) {
	dirs, err := os.ReadDir(backupRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("no fix sessions found (backup root does not exist: %s)", backupRoot)
		}
		return nil, "", fmt.Errorf("read backup root: %w", err)
	}

	var latestPath string
	var latestMod time.Time
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		mpath := filepath.Join(backupRoot, d.Name(), manifestFile)
		info, err := os.Stat(mpath)
		if err != nil {
			continue
		}
		if info.ModTime().After(latestMod) {
			latestMod = info.ModTime()
			latestPath = mpath
		}
	}
	if latestPath == "" {
		return nil, "", fmt.Errorf("no fix sessions found in %s", backupRoot)
	}

	raw, err := os.ReadFile(latestPath)
	if err != nil {
		return nil, "", err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "", fmt.Errorf("parse manifest: %w", err)
	}
	return &m, filepath.Dir(latestPath), nil
}

// Rollback restores every lockfile recorded in m to its original path.
func Rollback(m *Manifest) error {
	var errs []error
	for _, e := range m.Entries {
		if err := copyFile(e.BackupPath, e.LockfilePath); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", e.LockfilePath, err))
		}
	}
	return errors.Join(errs...)
}

// SessionDir returns a timestamped path inside backupRoot for a new session.
func SessionDir(backupRoot string) string {
	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	return filepath.Join(backupRoot, ts)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
