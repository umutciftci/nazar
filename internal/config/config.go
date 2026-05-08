// Package config loads nazar's optional user configuration file.
//
// The config file is located at:
//
//	~/.config/nazar/config.json   (XDG default)
//
// or, when $XDG_CONFIG_HOME is set:
//
//	$XDG_CONFIG_HOME/nazar/config.json
//
// All fields are optional. Flags supplied on the command line always take
// precedence over config file values.
//
// Example config.json:
//
//	{
//	  "sort":             "worst",
//	  "top":              10,
//	  "severity":         "high",
//	  "severity-workers": 16,
//	  "osv-timeout":      "2m",
//	  "safe-only":        true
//	}
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Config holds the subset of nazar flags that can be persisted.
// All fields are pointers so we can distinguish "set by user" from "not set"
// after JSON decoding.
type Config struct {
	// Scan / shared
	Sort            *string `json:"sort,omitempty"`
	Top             *int    `json:"top,omitempty"`
	Severity        *string `json:"severity,omitempty"`
	SeverityWorkers *int    `json:"severity-workers,omitempty"`
	OsvTimeout      *string `json:"osv-timeout,omitempty"` // e.g. "90s", "2m"
	NoCache         *bool   `json:"no-cache,omitempty"`
	CacheDir        *string `json:"cache-dir,omitempty"`

	// Fix
	SafeOnly *bool   `json:"safe-only,omitempty"`
	RunTests *string `json:"run-tests,omitempty"`

	// Watch
	Interval *string `json:"interval,omitempty"` // e.g. "1h", "6h"
}

// DefaultPath returns the platform default config path.
func DefaultPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "nazar", "config.json")
}

// Load reads the config file at path.  When path is empty, DefaultPath() is
// used.  If the file does not exist, an empty Config is returned without error.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes cfg to path in indented JSON.  Intermediate directories are
// created automatically.
func Save(cfg *Config, path string) error {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
