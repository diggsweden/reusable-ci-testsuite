// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// runOpts customises a single binary invocation.
type runOpts struct {
	dir string            // working directory
	env map[string]string // extra environment (added to a clean PATH-only base)
}

// run invokes the reusable-ci binary with args, returns combined output + exit code.
//
// The environment is reset to a minimal PATH/HOME-only base by default
// so a developer's locale / git config / GNUPGHOME doesn't leak in.
// Per-test additions (GNUPGHOME, GITHUB_OUTPUT, …) go via opts.env.
func run(t *testing.T, opts runOpts, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	cmd := exec.Command(binPath, args...)
	cmd.Dir = opts.dir
	cmd.Env = isolatedEnv(opts.env)

	var outBuf, errBuf bytes.Buffer

	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run %v: %v", args, err)
	}

	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

// isolatedEnv returns a minimal environment plus the supplied
// overrides. Excluding the developer's locale/git/gpg state is the
// whole point.
//
// JAVA_HOME, ANDROID_HOME, and CARGO_HOME are passed through when
// present so mvn/gradle/cargo can locate their toolchains; clean-
// slate environments would silently fail otherwise. These are
// install-location pointers, not user state.
//
// PATH gets a mise-augmented prefix: many developers manage node /
// java / cargo via mise but haven't activated it in the shell that
// invoked `go test`. Probing `mise bin-paths` finds the installed
// toolchains regardless, so tests that previously skipped with
// "npm not on PATH" can actually run.
func isolatedEnv(extra map[string]string) []string {
	base := map[string]string{
		"PATH":               misePath(os.Getenv("PATH")),
		"HOME":               os.Getenv("HOME"),
		"LANG":               "C",
		"LC_ALL":             "C",
		"GIT_CONFIG_GLOBAL":  os.DevNull,
		"GIT_CONFIG_SYSTEM":  os.DevNull,
		"GIT_AUTHOR_NAME":    "Integration Test",
		"GIT_AUTHOR_EMAIL":   "integration@test.example",
		"GIT_COMMITTER_NAME": "Integration Test",
		"GIT_COMMITTER_EMAIL": "integration@test.example",
		// Default to a no-swap fixture so signing tests on hosts with
		// swap on (most Linux developer laptops) aren't blocked by
		// the swap-refusal policy. Tests that explicitly exercise
		// the policy (see swap_refusal_test.go) override this with a
		// swap-on fixture. The override is a TEST-ONLY redirection
		// of the /proc/swaps path — it does NOT bypass the policy
		// in production code; production reads /proc/swaps directly
		// because REUSABLE_CI_PROC_SWAPS is not set in workflows.
		"REUSABLE_CI_PROC_SWAPS": defaultNoSwapFixture(),
	}

	for _, name := range []string{"JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "CARGO_HOME", "RUSTUP_HOME", "GOPATH", "GOCACHE", "GOMODCACHE", "GRADLE_USER_HOME"} {
		v := os.Getenv(name)
		if v == "" {
			continue
		}

		// JAVA_HOME pointing at a deleted toolchain (common on
		// mise/asdf hosts after an update) makes mvn refuse to
		// start with a misleading error. Drop the var so the
		// java on PATH wins instead.
		if name == "JAVA_HOME" {
			if _, err := os.Stat(filepath.Join(v, "bin", "java")); err != nil {
				continue
			}
		}

		base[name] = v
	}

	for k, v := range extra {
		base[k] = v
	}

	out := make([]string, 0, len(base))
	for k, v := range base {
		out = append(out, k+"="+v)
	}

	return out
}

// copyTree clones src to dst (called per-test so fixtures stay
// pristine). Preserves file modes so executable bits on `gradlew`
// etc. carry over.
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()

	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)

		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}

			return os.Symlink(link, target)
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}

			return copyFile(path, target, info.Mode().Perm())
		}
	})
	if err != nil {
		t.Fatalf("copy %s → %s: %v", src, dst, err)
	}

	return dst
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}

	defer out.Close()

	_, err = io.Copy(out, in)

	return err
}

// fixture resolves a path under the testsuite root (the directory
// containing the ecosystem hello-world projects).
func fixture(name string) string { return filepath.Join(suiteDir, name) }

// sha256File returns the hex SHA256 of path. Fails the test on error.
func sha256File(t *testing.T, path string) string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}

	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// requireTool skips the test if the named command is not on PATH.
// Lets the suite run in environments missing optional toolchains
// (npm, cyclonedx-gomod, etc.) without failing.
//
// Looks up the binary against the *augmented* PATH (host PATH +
// every mise-managed install dir) so a clean `go test` invocation
// can still find node / java / cargo etc. when mise hasn't been
// activated in the calling shell.
func requireTool(t *testing.T, name string) {
	t.Helper()

	if lookupTool(name) == "" {
		t.Skipf("skipping: %s not on PATH (looked at host PATH + mise bin-paths)", name)
	}
}

// lookupTool returns the absolute path to `name` searching the
// augmented PATH; empty string when not found.
func lookupTool(name string) string {
	augmented := misePath(os.Getenv("PATH"))
	for _, dir := range strings.Split(augmented, string(os.PathListSeparator)) {
		if dir == "" {
			continue
		}

		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}

	return ""
}

// readFile reads path, failing the test on error.
func readFile(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(body)
}

// fileExists reports whether path is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)

	return err == nil && info.Mode().IsRegular()
}

// defaultNoSwapFixture returns a path to a process-wide /proc/swaps
// fixture that reports no active swap. Computed lazily so tests that
// run before the helper is touched don't see a partial file. Same
// file is reused across the process — it's just header-only data.
//
//nolint:gochecknoglobals // process-wide cached file path.
var (
	noSwapFixtureOnce sync.Once
	noSwapFixturePath string
)

func defaultNoSwapFixture() string {
	noSwapFixtureOnce.Do(func() {
		f, err := os.CreateTemp("", "reusable-ci-no-swap-*")
		if err != nil {
			panic("integration: cannot create no-swap fixture: " + err.Error())
		}

		// Header-only /proc/swaps body. The kernel always writes
		// this header even when no swap is configured.
		if _, err := f.WriteString("Filename\tType\tSize\tUsed\tPriority\n"); err != nil {
			panic("integration: cannot write no-swap fixture: " + err.Error())
		}

		_ = f.Close()
		noSwapFixturePath = f.Name()
	})

	return noSwapFixturePath
}

// misePath returns base augmented with every directory reported by
// `mise bin-paths` that isn't already in base. Result: a clean
// shell `go test` invocation still sees mise-managed toolchains
// (node, java, cargo, …) without requiring `mise activate` in the
// caller's environment.
//
// Failures (mise not installed, command error) silently fall back
// to the original PATH so the helper never blocks a test that
// doesn't need mise.
var miseCache string //nolint:gochecknoglobals // memoised once per process (TestMain).

var miseOnce sync.Once //nolint:gochecknoglobals // memoise companion.

func misePath(base string) string {
	miseOnce.Do(func() {
		out, err := exec.Command("mise", "bin-paths").Output()
		if err != nil {
			return
		}

		var add []string

		seen := map[string]bool{}
		for _, p := range strings.Split(base, string(os.PathListSeparator)) {
			seen[p] = true
		}

		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}

			add = append(add, line)
			seen[line] = true
		}

		miseCache = strings.Join(add, string(os.PathListSeparator))
	})

	if miseCache == "" {
		return base
	}

	return miseCache + string(os.PathListSeparator) + base
}

// runTool invokes a plain external binary (npm, mvn, cargo, …) in
// the given directory and returns combined output + exit code.
// Used by tests that need to materialise real artefacts (npm pack,
// mvn package, cargo build) before pointing reusable-ci at them.
func runTool(t *testing.T, dir, name string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	bin := name
	if !strings.ContainsRune(name, os.PathSeparator) {
		if resolved := lookupTool(name); resolved != "" {
			bin = resolved
		}
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = isolatedEnv(nil)

	var outBuf, errBuf bytes.Buffer

	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run %s %v: %v", name, args, err)
	}

	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

// assertContains fails the test when haystack lacks needle.
func assertContains(t *testing.T, label, haystack, needle string) {
	t.Helper()

	if !strings.Contains(haystack, needle) {
		t.Errorf("%s: missing %q in output:\n%s", label, needle, haystack)
	}
}
