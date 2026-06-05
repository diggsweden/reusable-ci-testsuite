// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Black-box coverage for the new canonical config location and the
// auto-derive fallback. Drives `reusable-ci config parse-artifacts`
// against three layouts:
//
//   1. .reusable-ci/artifacts.yml present → parsed normally.
//   2. No artifacts.yml, single root manifest → auto-derived plan.
//   3. No artifacts.yml, multiple root manifests → actionable error.

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfig_ParsesFromCanonicalLocation verifies the new
// .reusable-ci/artifacts.yml path is read by `config parse-artifacts`
// when supplied via $ARTIFACTS_CONFIG.
func TestConfig_ParsesFromCanonicalLocation(t *testing.T) {
	dir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dir, ".reusable-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	body := `artifacts:
  - name: app
    project-type: maven
    working-directory: .
`
	if err := os.WriteFile(filepath.Join(dir, ".reusable-ci", "artifacts.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"ARTIFACTS_CONFIG": ".reusable-ci/artifacts.yml",
	}}, "config", "parse-artifacts")
	if code != 0 {
		t.Fatalf("config parse-artifacts exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// TestConfig_AutoDerivesFromSingleMavenManifest verifies the
// no-config-file happy path: a repo with just a pom.xml at root
// gets an in-memory Config synthesised. The CLI emits an annotation
// noting that auto-derive ran, so operators can see what happened.
func TestConfig_AutoDerivesFromSingleMavenManifest(t *testing.T) {
	dir := t.TempDir()

	pom := []byte(`<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>se.digg.test</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
</project>`)
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), pom, 0o600); err != nil {
		t.Fatal(err)
	}

	// No .reusable-ci/artifacts.yml — auto-derive must kick in.
	_, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"ARTIFACTS_CONFIG": ".reusable-ci/artifacts.yml",
	}}, "--format", "github", "config", "parse-artifacts")
	if code != 0 {
		t.Fatalf("auto-derive should succeed for single root manifest; got exit %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "auto-derived") {
		t.Errorf("expected annotation announcing auto-derive; got:\n%s", stderr)
	}
}

// TestConfig_AutoDeriveFailsActionablyOnMultipleManifests verifies
// the polyglot-repo case: zero artifacts.yml + two root manifests →
// explicit error naming both manifests, not a silent "first wins"
// pick.
func TestConfig_AutoDeriveFailsActionablyOnMultipleManifests(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "pom.xml"),
		[]byte(`<project><groupId>x</groupId><artifactId>x</artifactId><version>1</version></project>`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: dir, env: map[string]string{
		"ARTIFACTS_CONFIG": ".reusable-ci/artifacts.yml",
	}}, "config", "parse-artifacts")
	if code == 0 {
		t.Fatalf("multi-manifest auto-derive should fail; got exit 0")
	}

	for _, want := range []string{"multiple manifests", "pom.xml", "package.json"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("error should mention %q; got:\n%s", want, stderr)
		}
	}
}
