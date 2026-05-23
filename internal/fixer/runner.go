package fixer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Action describes one package upgrade to perform in one project directory.
type Action struct {
	LockfilePath string // absolute path to the lockfile to be modified
	ProjectDir   string // working directory for running the package manager
	PackageName  string // e.g. "lodash" or "@scope/utils"
	OldVersion   string // currently installed version
	FixedIn      string // target version to upgrade to
}

// ApplyResult is the outcome of one Action.
type ApplyResult struct {
	Action  Action
	Backup  Entry  // populated even when Err != nil if backup succeeded
	Output  string // combined stdout+stderr from the package manager
	Err     error
}

// DryRun returns the shell command that would be executed without running it.
func DryRun(a Action) string {
	cmd, err := buildCommand(a)
	if err != nil {
		return fmt.Sprintf("(unsupported: %v)", err)
	}
	if cmd == nil {
		return fmt.Sprintf("(edit %s in-place)", filepath.Base(a.LockfilePath))
	}
	return strings.Join(cmd, " ")
}

// ApplyOptions controls how Apply runs the package manager subprocess.
type ApplyOptions struct {
	// Progress writes status lines (command start). Nil suppresses them.
	Progress func(format string, args ...any)
}

// Apply backs up the lockfile then runs the appropriate package manager.
// If the package manager is not installed the backup is still created and
// the error makes that clear so the user can fix manually.
func Apply(a Action, backupDir string) ApplyResult {
	return ApplyWithOptions(a, backupDir, ApplyOptions{})
}

// ApplyWithOptions is like Apply but can emit progress and stream subprocess output.
func ApplyWithOptions(a Action, backupDir string, opts ApplyOptions) ApplyResult {
	backup, err := BackupLockfile(a.LockfilePath, backupDir)
	if err != nil {
		return ApplyResult{Action: a, Err: fmt.Errorf("backup: %w", err)}
	}

	// requirements.txt is edited in-place — no subprocess needed.
	if filepath.Base(a.LockfilePath) == "requirements.txt" {
		if err := patchRequirementsTxt(a.LockfilePath, a.PackageName, a.FixedIn); err != nil {
			return ApplyResult{Action: a, Backup: backup, Err: fmt.Errorf("patch requirements.txt: %w", err)}
		}
		return ApplyResult{Action: a, Backup: backup}
	}

	args, err := buildCommand(a)
	if err != nil {
		return ApplyResult{Action: a, Backup: backup, Err: err}
	}

	// Verify the tool is on PATH before attempting.
	if _, lerr := exec.LookPath(args[0]); lerr != nil {
		return ApplyResult{Action: a, Backup: backup,
			Err: fmt.Errorf("%s not found on PATH — install it or fix manually", args[0])}
	}

	c := exec.Command(args[0], args[1:]...)
	c.Dir = a.ProjectDir
	if opts.Progress != nil {
		opts.Progress("running %s…", strings.Join(args, " "))
	}
	// Stream to stderr so npm/yarn/pnpm progress bars stay visible.
	c.Stdout = os.Stderr
	c.Stderr = os.Stderr
	err = c.Run()
	if err != nil {
		return ApplyResult{Action: a, Backup: backup,
			Err: fmt.Errorf("%s: %w", strings.Join(args, " "), err)}
	}
	return ApplyResult{Action: a, Backup: backup}
}

// buildCommand returns the argv for the package manager upgrade. Returns nil
// for lockfiles that are patched in-place (requirements.txt).
func buildCommand(a Action) ([]string, error) {
	pkg := a.PackageName
	ver := a.FixedIn

	switch filepath.Base(a.LockfilePath) {
	case "package-lock.json":
		return []string{"npm", "install", pkg + "@" + ver}, nil

	case "yarn.lock":
		if isYarnBerry(a.LockfilePath) {
			return []string{"yarn", "up", pkg + "@" + ver}, nil
		}
		return []string{"yarn", "upgrade", pkg + "@" + ver}, nil

	case "pnpm-lock.yaml":
		return []string{"pnpm", "update", pkg + "@" + ver}, nil

	case "poetry.lock":
		return []string{"poetry", "add", pkg + "@^" + ver}, nil

	case "uv.lock":
		return []string{"uv", "add", pkg + ">=" + ver}, nil

	case "Pipfile.lock":
		return []string{"pipenv", "install", pkg + "==" + ver}, nil

	case "requirements.txt":
		return nil, nil // handled via patchRequirementsTxt

	case "go.sum":
		// go get needs the module path with a v-prefixed semver.
		vver := ver
		if !strings.HasPrefix(vver, "v") {
			vver = "v" + vver
		}
		return []string{"go", "get", pkg + "@" + vver}, nil

	case "Cargo.lock":
		return []string{"cargo", "update", "-p", pkg, "--precise", ver}, nil
	}
	return nil, fmt.Errorf("unsupported lockfile: %s", filepath.Base(a.LockfilePath))
}

// isYarnBerry peeks at the first few lines of yarn.lock to detect Berry (v2+).
func isYarnBerry(lockfilePath string) bool {
	f, err := os.Open(lockfilePath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for i := 0; i < 5 && sc.Scan(); i++ {
		if strings.Contains(sc.Text(), "__metadata") {
			return true
		}
	}
	return false
}

// patchRequirementsTxt finds the line for pkgName and rewrites its version
// specifier to ==newVersion. Returns an error if the package is not found.
func patchRequirementsTxt(path, pkgName, newVersion string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	lower := strings.ToLower(pkgName)
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		norm := strings.ToLower(trimmed)
		// Match "pkg==x", "pkg>=x", "pkg>x", "pkg~=x", etc.
		if strings.HasPrefix(norm, lower+"==") ||
			strings.HasPrefix(norm, lower+">=") ||
			strings.HasPrefix(norm, lower+">") ||
			strings.HasPrefix(norm, lower+"~=") {
			// Preserve original capitalisation of the package name.
			idx := strings.IndexAny(trimmed, "=><~!")
			if idx > 0 {
				lines[i] = trimmed[:idx] + "==" + newVersion
				found = true
			}
		}
	}
	if !found {
		return fmt.Errorf("%s not found in requirements.txt", pkgName)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}
