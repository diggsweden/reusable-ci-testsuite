// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
)

// TestChangelogValidatePresent verifies the "full-changelog" mode:
// when --required is set, the changelog file must exist or the
// command fails (EX_VALIDATION).
func TestChangelogValidatePresent(t *testing.T) {
	dir := t.TempDir()

	body := []byte("# Changelog\n\n## v1.0.0\n\n- initial release\n")

	cl := filepath.Join(dir, "CHANGELOG.md")
	if err := os.WriteFile(cl, body, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(t, runOpts{dir: dir},
		"validate", "changelog", "--path", "CHANGELOG.md", "--required")
	if code != 0 {
		t.Fatalf("validate changelog exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// TestChangelogValidateMissingFails verifies that --required +
// missing file → EX_NOINPUT (66). The CLI distinguishes "input file
// not found" (66) from "content rejected by a check" (1); a missing
// changelog is the former, since there is no content to evaluate.
func TestChangelogValidateMissingFails(t *testing.T) {
	dir := t.TempDir()

	_, _, code := run(t, runOpts{dir: dir},
		"validate", "changelog", "--path", "DOES-NOT-EXIST.md", "--required")
	if code != 66 {
		t.Errorf("expected EX_NOINPUT=66 when --required and file missing; got %d", code)
	}
}

// TestChangelogValidateMinimalModeAbsent verifies that without
// --required, an absent changelog is tolerated (used by the minimal
// changelog mode in the workflow, which has a "No changes for this
// release" fallback).
func TestChangelogValidateMinimalModeAbsent(t *testing.T) {
	dir := t.TempDir()

	_, _, code := run(t, runOpts{dir: dir, env: map[string]string{
		// validate changelog emits via the OutputSink; without
		// GITHUB_OUTPUT it writes to stdout-as-text which is fine.
	}}, "validate", "changelog", "--path", "DOES-NOT-EXIST.md")
	if code != 0 {
		t.Errorf("expected exit 0 in minimal mode with missing file; got %d", code)
	}
}

// TestReleaseNotesFromChangelog verifies that `release notes` reads
// a real git-cliff-style changelog snippet and writes it to the
// target file.
func TestReleaseNotesFromChangelog(t *testing.T) {
	dir := t.TempDir()

	src := filepath.Join(dir, "ReleasenotesTmp")
	if err := os.WriteFile(src, []byte("## v1.2.3\n\n- feat: nice thing\n- fix: tiny bug\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tgt := filepath.Join(dir, "release-notes.md")

	_, _, code := run(t, runOpts{dir: dir},
		"release", "notes",
		"--source-file", "ReleasenotesTmp",
		"--target-file", "release-notes.md",
		"--release-version", "v1.2.3",
		"--release-commit", "deadbeef")
	if code != 0 {
		t.Fatalf("release notes exit %d", code)
	}

	if !fileExists(tgt) {
		t.Fatalf("release notes target file missing: %s", tgt)
	}

	assertContains(t, "release-notes.md", readFile(t, tgt), "feat: nice thing")
}

// TestReleaseNotesFallbackOnMissingChangelog verifies the
// fallback-stub behaviour: when the source changelog is absent,
// `release notes` still produces a target file with a header derived
// from --release-version, rather than failing.
func TestReleaseNotesFallbackOnMissingChangelog(t *testing.T) {
	dir := t.TempDir()

	tgt := filepath.Join(dir, "release-notes.md")

	_, _, code := run(t, runOpts{dir: dir},
		"release", "notes",
		"--source-file", "no-such-file",
		"--target-file", "release-notes.md",
		"--release-version", "v9.9.9",
		"--release-commit", "abc1234")
	if code != 0 {
		t.Fatalf("release notes exit %d", code)
	}

	body := readFile(t, tgt)
	assertContains(t, "fallback", body, "v9.9.9")
}
