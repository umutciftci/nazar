package fixer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── BackupLockfile ────────────────────────────────────────────────────────────

func TestBackupLockfile_CopiesFile(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "package-lock.json")
	if err := os.WriteFile(src, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	backupDir := filepath.Join(tmp, "backups")
	entry, err := BackupLockfile(src, backupDir)
	if err != nil {
		t.Fatalf("BackupLockfile: %v", err)
	}

	if entry.LockfilePath != src {
		t.Errorf("LockfilePath: want %q, got %q", src, entry.LockfilePath)
	}
	if !strings.HasPrefix(filepath.Base(entry.BackupPath), "package-lock.json.") {
		t.Errorf("BackupPath name should start with lockfile name, got %q", entry.BackupPath)
	}

	got, err := os.ReadFile(entry.BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(got) != `{"version":1}` {
		t.Errorf("backup contents mismatch: %s", got)
	}
}

func TestBackupLockfile_UniqueNames(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "package-lock.json")
	_ = os.WriteFile(src, []byte("{}"), 0o644)
	backupDir := filepath.Join(tmp, "backups")

	e1, _ := BackupLockfile(src, backupDir)
	e2, _ := BackupLockfile(src, backupDir)
	if e1.BackupPath == e2.BackupPath {
		t.Error("two backups of the same file should have different paths")
	}
}

// ── Manifest + Rollback ───────────────────────────────────────────────────────

func TestSaveAndLoadManifest(t *testing.T) {
	tmp := t.TempDir()
	sessionDir := filepath.Join(tmp, "sessions", "2026-01-01")

	m := &Manifest{
		Timestamp: time.Now().UTC().Truncate(time.Second),
		Entries: []Entry{
			{LockfilePath: "/proj/package-lock.json", BackupPath: "/backups/foo"},
		},
	}
	if err := SaveManifest(sessionDir, m); err != nil {
		t.Fatalf("SaveManifest: %v", err)
	}

	loaded, dir, err := LoadLatestManifest(filepath.Join(tmp, "sessions"))
	if err != nil {
		t.Fatalf("LoadLatestManifest: %v", err)
	}
	if dir != sessionDir {
		t.Errorf("dir: want %q, got %q", sessionDir, dir)
	}
	if len(loaded.Entries) != 1 || loaded.Entries[0].LockfilePath != "/proj/package-lock.json" {
		t.Errorf("entries not round-tripped: %+v", loaded.Entries)
	}
}

func TestRollback_RestoresFiles(t *testing.T) {
	tmp := t.TempDir()

	original := filepath.Join(tmp, "package-lock.json")
	_ = os.WriteFile(original, []byte("original"), 0o644)

	backupDir := filepath.Join(tmp, "backups")
	entry, _ := BackupLockfile(original, backupDir)

	// Simulate the package manager having modified the lockfile.
	_ = os.WriteFile(original, []byte("modified"), 0o644)

	m := &Manifest{Entries: []Entry{entry}}
	if err := Rollback(m); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	got, _ := os.ReadFile(original)
	if string(got) != "original" {
		t.Errorf("rollback: want %q, got %q", "original", string(got))
	}
}

// ── patchRequirementsTxt ──────────────────────────────────────────────────────

func TestPatchRequirementsTxt(t *testing.T) {
	cases := []struct {
		name    string
		content string
		pkg     string
		ver     string
		want    string
	}{
		{
			name:    "exact pin",
			content: "requests==2.28.0\nflask>=2.0.0\n",
			pkg:     "requests", ver: "2.31.0",
			want: "requests==2.31.0\nflask>=2.0.0\n",
		},
		{
			name:    "ge specifier",
			content: "Flask>=2.0.0\n",
			pkg:     "flask", ver: "3.0.0",
			want: "Flask==3.0.0\n",
		},
		{
			name:    "not found returns error",
			content: "django==4.2\n",
			pkg:     "requests", ver: "2.31.0",
			want: "", // error expected
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "requirements.txt")
			_ = os.WriteFile(path, []byte(tc.content), 0o644)

			err := patchRequirementsTxt(path, tc.pkg, tc.ver)
			if tc.want == "" {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("patchRequirementsTxt: %v", err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.want {
				t.Errorf("want %q, got %q", tc.want, string(got))
			}
		})
	}
}

// ── DryRun ────────────────────────────────────────────────────────────────────

func TestDryRun(t *testing.T) {
	cases := []struct {
		lockfile string
		pkg      string
		ver      string
		contains string
	}{
		{"package-lock.json", "lodash", "4.17.22", "npm install lodash@4.17.22"},
		{"pnpm-lock.yaml", "lodash", "4.17.22", "pnpm update lodash@4.17.22"},
		{"poetry.lock", "requests", "2.31.0", "poetry add requests@^2.31.0"},
		{"go.sum", "golang.org/x/net", "0.20.0", "go get golang.org/x/net@v0.20.0"},
		{"Cargo.lock", "serde", "1.0.195", "cargo update -p serde --precise 1.0.195"},
	}
	for _, tc := range cases {
		a := Action{
			LockfilePath: "/proj/" + tc.lockfile,
			PackageName:  tc.pkg,
			FixedIn:      tc.ver,
		}
		got := DryRun(a)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("DryRun(%s): want %q in %q", tc.lockfile, tc.contains, got)
		}
	}
}
