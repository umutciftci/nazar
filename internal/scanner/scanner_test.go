package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// makeTree builds a small fake project tree under t.TempDir() for use in tests.
// Files are created with placeholder content; only their presence matters.
func makeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

func TestScan_DetectsNPMProjects(t *testing.T) {
	root := makeTree(t, map[string]string{
		"app-a/package.json":      "{}",
		"app-a/package-lock.json": "{}",
		"app-b/package.json":      "{}",
		"app-b/package-lock.json": "{}",
		"docs/README.md":          "hello",
	})

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 projects, got %d: %+v", len(got), got)
	}

	wantPaths := []string{filepath.Join(root, "app-a"), filepath.Join(root, "app-b")}
	gotPaths := []string{got[0].Path, got[1].Path}
	sort.Strings(gotPaths)
	for i, want := range wantPaths {
		if gotPaths[i] != want {
			t.Errorf("project[%d] path: want %q, got %q", i, want, gotPaths[i])
		}
	}
	for _, p := range got {
		if p.Ecosystem != EcosystemNPM {
			t.Errorf("ecosystem: want %q, got %q", EcosystemNPM, p.Ecosystem)
		}
		if p.LockfilePath != filepath.Join(p.Path, "package-lock.json") {
			t.Errorf("lockfile path: got %q", p.LockfilePath)
		}
	}
}

func TestScan_RequiresBothPackageAndLockfile(t *testing.T) {
	root := makeTree(t, map[string]string{
		// Only package.json — should NOT be detected (we need pinned versions).
		"only-pkg/package.json": "{}",
		// Only package-lock.json — should NOT be detected either.
		"only-lock/package-lock.json": "{}",
		// Full pair — should be detected.
		"real/package.json":      "{}",
		"real/package-lock.json": "{}",
	})

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 project, got %d", len(got))
	}
	if got[0].Path != filepath.Join(root, "real") {
		t.Errorf("expected only %q, got %q", filepath.Join(root, "real"), got[0].Path)
	}
}

func TestScan_SkipsKnownNoiseDirectories(t *testing.T) {
	// Each "noise" dir contains a package.json+lockfile pair that should be ignored.
	noise := []string{
		"node_modules", ".git", "vendor", "target", "dist", "build", ".next",
		"__pycache__", ".venv", "venv", "testdata", "fixtures",
	}
	files := map[string]string{
		"real/package.json":      "{}",
		"real/package-lock.json": "{}",
	}
	for _, n := range noise {
		files[filepath.Join(n, "fake/package.json")] = "{}"
		files[filepath.Join(n, "fake/package-lock.json")] = "{}"
	}
	root := makeTree(t, files)

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 project (noise dirs should be skipped), got %d: %+v", len(got), got)
	}
	if got[0].Path != filepath.Join(root, "real") {
		t.Errorf("expected only %q, got %q", filepath.Join(root, "real"), got[0].Path)
	}
}

func TestScan_NestedNPMProjects(t *testing.T) {
	// A monorepo-style layout where nested projects exist outside node_modules.
	// Both should be detected.
	root := makeTree(t, map[string]string{
		"package.json":                   "{}",
		"package-lock.json":              "{}",
		"packages/api/package.json":      "{}",
		"packages/api/package-lock.json": "{}",
	})

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 projects (root + nested), got %d: %+v", len(got), got)
	}
}

func TestScan_DetectsPyPIProjects(t *testing.T) {
	root := makeTree(t, map[string]string{
		"pyapp/requirements.txt": "requests==2.31.0\n",
		"poetry-app/poetry.lock": "[[package]]\nname = \"flask\"\nversion = \"3.0.3\"\n",
		"both/poetry.lock":       "[[package]]\nname = \"django\"\nversion = \"4.2.0\"\n",
		"both/requirements.txt":  "requests==2.31.0\n",
	})

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// 3 PyPI projects: pyapp (req), poetry-app (poetry), both (poetry takes precedence)
	pypi := 0
	for _, p := range got {
		if p.Ecosystem == EcosystemPyPI {
			pypi++
		}
	}
	if pypi != 3 {
		t.Fatalf("expected 3 PyPI projects, got %d: %+v", pypi, got)
	}
	// "both" should use poetry.lock, not requirements.txt
	for _, p := range got {
		if p.Path == filepath.Join(root, "both") {
			if filepath.Base(p.LockfilePath) != "poetry.lock" {
				t.Errorf("expected poetry.lock to take precedence, got %q", p.LockfilePath)
			}
		}
	}
}

func TestScan_PolyglotProjectDetectedTwice(t *testing.T) {
	// A directory with both package-lock.json and requirements.txt should yield
	// two project entries (one npm, one PyPI).
	root := makeTree(t, map[string]string{
		"fullstack/package.json":      "{}",
		"fullstack/package-lock.json": "{}",
		"fullstack/requirements.txt":  "flask==3.0.3\n",
	})

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries for polyglot project, got %d: %+v", len(got), got)
	}
	ecosystems := map[Ecosystem]bool{}
	for _, p := range got {
		ecosystems[p.Ecosystem] = true
	}
	if !ecosystems[EcosystemNPM] || !ecosystems[EcosystemPyPI] {
		t.Errorf("expected both npm and PyPI, got %v", ecosystems)
	}
}

func TestScan_DetectsGoProjects(t *testing.T) {
	root := makeTree(t, map[string]string{
		"goapp/go.mod": "module github.com/example/goapp\ngo 1.21\n",
		"goapp/go.sum": "github.com/some/dep v1.0.0 h1:abc=\n",
		// Only go.mod, no go.sum — should NOT be detected.
		"gomod-only/go.mod": "module github.com/example/x\n",
	})

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	goProjects := 0
	for _, p := range got {
		if p.Ecosystem == EcosystemGo {
			goProjects++
			if filepath.Base(p.LockfilePath) != "go.sum" {
				t.Errorf("Go lockfile should be go.sum, got %q", p.LockfilePath)
			}
		}
	}
	if goProjects != 1 {
		t.Fatalf("expected 1 Go project, got %d: %+v", goProjects, got)
	}
}

func TestScan_DetectsRustProjects(t *testing.T) {
	root := makeTree(t, map[string]string{
		"rustapp/Cargo.toml": "[package]\nname = \"rustapp\"\nversion = \"0.1.0\"\n",
		"rustapp/Cargo.lock": "version = 3\n",
		// Only Cargo.toml, no Cargo.lock — should NOT be detected.
		"toml-only/Cargo.toml": "[package]\nname = \"x\"\n",
	})

	got, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	rustProjects := 0
	for _, p := range got {
		if p.Ecosystem == EcosystemCratesIO {
			rustProjects++
			if filepath.Base(p.LockfilePath) != "Cargo.lock" {
				t.Errorf("Rust lockfile should be Cargo.lock, got %q", p.LockfilePath)
			}
		}
	}
	if rustProjects != 1 {
		t.Fatalf("expected 1 Rust project, got %d: %+v", rustProjects, got)
	}
}

func TestScan_NonexistentRoot(t *testing.T) {
	_, err := Scan(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing root, got nil")
	}
}
