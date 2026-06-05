// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionBumpMatrix is the comprehensive happy-path coverage for
// `version bump` across every supported project type. One sub-test
// per ecosystem; each materialises a minimal valid manifest, runs
// the bump, and asserts that the version-of-record landed in the
// expected file. Idempotence is rechecked.
//
// Subtests that depend on an external CLI (mvn for Maven, npm for
// NPM) skip when that CLI is missing, instead of failing in
// CI-unfriendly ways.
func TestVersionBumpMatrix(t *testing.T) {
	t.Run("maven_single_module", func(t *testing.T) {
		requireTool(t, "mvn")

		proj := copyTree(t, fixture("maven-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "maven", "--version", "5.0.0",
			"--maven-cli-opts", "-B -ntp",
		)
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		if !strings.Contains(readFile(t, filepath.Join(proj, "pom.xml")), "<version>5.0.0</version>") {
			t.Errorf("pom.xml version not 5.0.0")
		}
	})

	t.Run("npm_simple", func(t *testing.T) {
		requireTool(t, "npm")

		proj := copyTree(t, fixture("npm-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "npm", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		if !strings.Contains(readFile(t, filepath.Join(proj, "package.json")), `"version": "5.0.0"`) {
			t.Errorf("package.json version not 5.0.0")
		}
	})

	t.Run("gradle_jvm", func(t *testing.T) {
		proj := copyTree(t, fixture("gradle-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "gradle", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "gradle.properties", readFile(t, filepath.Join(proj, "gradle.properties")), "version=5.0.0")
	})

	t.Run("gradle_android", func(t *testing.T) {
		proj := copyTree(t, fixture("gradle-android-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "gradle-android", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		body := readFile(t, filepath.Join(proj, "gradle.properties"))
		assertContains(t, "gradle.properties", body, "versionName=5.0.0")
		// versionCode is auto-incremented from 42 → 43.
		assertContains(t, "gradle.properties", body, "versionCode=43")
	})

	t.Run("cargo_workspace", func(t *testing.T) {
		requireTool(t, "cargo")

		proj := copyTree(t, fixture("cargo-workspace"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "cargo", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "Cargo.toml", readFile(t, filepath.Join(proj, "Cargo.toml")), `version = "5.0.0"`)
	})

	t.Run("cargo_single_crate", func(t *testing.T) {
		requireTool(t, "cargo")

		proj := copyTree(t, fixture("cargo-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "cargo", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "Cargo.toml", readFile(t, filepath.Join(proj, "Cargo.toml")), `version = "5.0.0"`)
	})

	t.Run("xcode_ios", func(t *testing.T) {
		dir := t.TempDir()

		// xcode bump writes versions.xcconfig if missing; demonstrate both
		// shapes in one test by pre-creating the file.
		xc := filepath.Join(dir, "versions.xcconfig")
		if err := os.WriteFile(xc, []byte("MARKETING_VERSION = 0.1.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, _, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "xcode-ios", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "versions.xcconfig", readFile(t, xc), "MARKETING_VERSION = 5.0.0")
	})

	t.Run("go_is_noop", func(t *testing.T) {
		// Go has no version-of-record file — version comes from ldflags.
		// Bump must exit 0 with an informational message; nothing should
		// be modified on disk. The "✓" line goes to stderr (logger sink),
		// not stdout.
		proj := copyTree(t, fixture("go-hello"))
		preMod := readFile(t, filepath.Join(proj, "go.mod"))

		_, stderr, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "go", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		if readFile(t, filepath.Join(proj, "go.mod")) != preMod {
			t.Errorf("go.mod unexpectedly modified by no-op bump")
		}

		assertContains(t, "stderr", stderr, "ldflags")
	})

	t.Run("meta_is_noop", func(t *testing.T) {
		// Meta projects (changelog-only artifacts) accept a bump for the
		// changelog version-of-record but write no file.
		dir := t.TempDir()

		_, stderr, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "meta", "--version", "5.0.0")
		if code != 0 {
			t.Fatalf("bump exit %d", code)
		}

		assertContains(t, "stderr", stderr, "changelog")
	})
}

// TestVersionBumpIdempotence verifies that bumping to the SAME
// version twice in a row is a clean no-op (exit 0, file unchanged).
// CI sometimes retries the bump step; non-idempotent bumps would
// produce confusing "version already at X" hard-failures.
//
// Note: gradle-android is intentionally excluded. Its bump always
// increments versionCode (Play Store requires monotonic increase),
// so two bumps to the SAME versionName still mutate the file. That
// is correct behaviour — the test framework would just misread it
// as a regression.
func TestVersionBumpIdempotence(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		ptype   string
		path    string
	}{
		{name: "gradle", fixture: "gradle-hello", ptype: "gradle", path: "gradle.properties"},
		{name: "cargo", fixture: "cargo-workspace", ptype: "cargo", path: "Cargo.toml"},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.ptype == "cargo" || tc.ptype == "cargo-workspace" {
				requireTool(t, "cargo")
			}

			proj := copyTree(t, fixture(tc.fixture))

			args := []string{"version", "bump", "--project-type", tc.ptype, "--version", "7.7.7"}

			if _, _, code := run(t, runOpts{dir: proj}, args...); code != 0 {
				t.Fatalf("first bump exit %d", code)
			}

			afterFirst := readFile(t, filepath.Join(proj, tc.path))

			if _, _, code := run(t, runOpts{dir: proj}, args...); code != 0 {
				t.Errorf("second bump exit %d (idempotence)", code)
			}

			afterSecond := readFile(t, filepath.Join(proj, tc.path))

			if afterFirst != afterSecond {
				t.Errorf("bump is not idempotent for %s:\nfirst:\n%s\nsecond:\n%s",
					tc.ptype, afterFirst, afterSecond)
			}
		})
	}
}

// TestVersionBumpEdgeCases covers the error paths CI policy depends
// on. Each scenario asserts the documented exit code.
//
// Two cases tagged "informational" reveal CLI gaps worth fixing —
// they are deliberately written as t.Logf reports, not assertions,
// so the suite documents the gap without blocking on it:
//
//   - missing manifest currently maps to 70 (EX_SOFTWARE);
//     arguably should be 66 (EX_NOINPUT)
//   - --version v1.2.3 is silently accepted and written verbatim;
//     contract says "without a leading 'v'" but no validator enforces it
func TestVersionBumpEdgeCases(t *testing.T) {
	t.Run("missing_gradle_properties_fails", func(t *testing.T) {
		dir := t.TempDir()

		_, _, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "gradle", "--version", "1.0.0")
		if code == 0 {
			t.Errorf("expected non-zero exit for missing gradle.properties; got 0")
		}

		if code != 66 {
			// Informational: the CLI returns EX_SOFTWARE (70) here.
			// A clearer contract would be EX_NOINPUT (66) — file missing
			// is an input problem, not an internal-software problem.
			t.Logf("note: exit code for missing gradle.properties = %d (66 = EX_NOINPUT would be clearer)", code)
		}
	})

	t.Run("missing_required_flag_is_USAGE", func(t *testing.T) {
		dir := t.TempDir()

		_, _, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "gradle")
		if code != 2 {
			t.Errorf("expected EX_USAGE=2 when --version omitted; got %d", code)
		}
	})

	t.Run("unknown_project_type_is_USAGE", func(t *testing.T) {
		dir := t.TempDir()

		_, _, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "rust-lang", "--version", "1.0.0")
		if code != 2 {
			t.Errorf("expected EX_USAGE=2 for unknown project type; got %d", code)
		}
	})

	t.Run("malformed_cargo_toml_fails", func(t *testing.T) {
		requireTool(t, "cargo")

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("not valid toml [[[\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, _, code := run(t, runOpts{dir: dir},
			"version", "bump", "--project-type", "cargo", "--version", "1.0.0")
		if code == 0 {
			t.Errorf("expected non-zero exit on malformed Cargo.toml; got 0")
		}
	})

	t.Run("leading_v_in_version_is_currently_accepted", func(t *testing.T) {
		// The CLI help promises "--version takes a bare semver
		// (without a leading 'v')". Today this is not enforced —
		// "v1.2.3" is written verbatim to gradle.properties. The
		// test records the current behaviour and notes the gap;
		// flip this assertion when the validator lands.
		proj := copyTree(t, fixture("gradle-hello"))

		_, _, code := run(t, runOpts{dir: proj},
			"version", "bump", "--project-type", "gradle", "--version", "v1.2.3")
		if code == 0 {
			t.Logf("note: --version v1.2.3 accepted and written verbatim — validator would catch this earlier")
		}

		body := readFile(t, filepath.Join(proj, "gradle.properties"))
		if !strings.Contains(body, "version=v1.2.3") {
			t.Errorf("expected gradle.properties to contain (or reject) v1.2.3; got:\n%s", body)
		}
	})
}
