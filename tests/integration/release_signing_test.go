// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Release-flow artefact signing: SHA256 manifest generation +
// GPG detached signatures over the manifest and the artefacts it
// references.
//
// Tag-signature verification (the other "signing" surface) lives in
// signing_tags_test.go.
//
// Version-bump coverage lives in version_bump_matrix_test.go.

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestChecksumsRoundTrip verifies that the SHA256 manifest produced
// by `release checksums` round-trips through the standard
// sha256sum --check verifier, and that the bug fix preventing the
// manifest from including itself (empty-file SHA self-poison) holds.
func TestChecksumsRoundTrip(t *testing.T) {
	requireTool(t, "sha256sum")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app-linux-amd64"), []byte("payload-a"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "app-darwin-arm64"), []byte("payload-b"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{dir: dir},
		"release", "checksums", "--release-artifacts-dir", ".")
	if code != 0 {
		t.Fatalf("checksums exit %d", code)
	}

	manifest := filepath.Join(dir, "checksums.sha256")
	if !fileExists(manifest) {
		t.Fatalf("manifest missing")
	}

	if strings.Contains(readFile(t, manifest), "  checksums.sha256\n") {
		t.Errorf("manifest contains a line for itself (regression of self-poison bug)")
	}

	cmd := exec.Command("sha256sum", "--check", "checksums.sha256")
	cmd.Dir = dir

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("sha256sum --check failed: %v\n%s", err, out)
	}
}

// TestReleaseSignWarnsOnEmptyMatch verifies the bug fix that prevents
// `release sign` from silently exiting 0 with zero signatures when
// every file in --release-artifacts-dir fails the extension filter
// (bare binaries — which need --attach-artifacts instead).
func TestReleaseSignWarnsOnEmptyMatch(t *testing.T) {
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app-linux-amd64"), []byte("bare"), 0o600); err != nil {
		t.Fatal(err)
	}

	priv, err := os.ReadFile(key.privateASC)
	if err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")
	if code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	combined := stderr // sign writes its info to stderr
	if !strings.Contains(combined, "no files in") {
		t.Errorf("expected 'no files in ...' warning when filter excludes everything; got:\n%s", combined)
	}
}

// TestReleaseSignGPG verifies a real GPG sign+verify cycle of an
// archive-extension artefact. Host isolation matters: the developer's
// global ~/.gitconfig may set gpg.format=ssh which would otherwise
// break GPG signing entirely.
func TestReleaseSignGPG(t *testing.T) {
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("archive payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	priv, err := os.ReadFile(key.privateASC)
	if err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")
	if code != 0 {
		t.Fatalf("sign exit %d", code)
	}

	sig := filepath.Join(dir, "app.tgz.asc")
	if !fileExists(sig) {
		t.Fatalf("expected detached signature at %s", sig)
	}

	cmd := exec.Command("gpg", "--verify", sig, filepath.Join(ra, "app.tgz"))
	cmd.Env = append(os.Environ(), "GNUPGHOME="+key.gnupgHome)

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("gpg --verify failed: %v\n%s", err, out)
	}
}
