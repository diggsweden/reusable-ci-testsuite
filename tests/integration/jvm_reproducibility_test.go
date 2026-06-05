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

// TestValidateJVMReproducibility_MavenPasses runs the new validator
// against the maven-hello fixture (which sets
// <project.build.outputTimestamp> in its POM) and asserts the
// validator reports it as configured. Counterpart to the on-disk
// reproducibility test in reproducibility_test.go — this one tests
// the policy-check surface that the release-prerequisites stage runs.
func TestValidateJVMReproducibility_MavenPasses(t *testing.T) {
	proj := copyTree(t, fixture("maven-hello"))

	plan := configPlan(`"maven":[{"name":"maven-hello","project_type":"maven","working_directory":"."}]`)

	// The validator writes diagnostic output to stderr (the "w"
	// parameter the CLI binds to os.Stderr — same pattern as
	// `validate cargo`). stdout is reserved for structured output.
	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{
		"CONFIG_PLAN_JSON": plan,
	}}, "validate", "jvm-reproducibility")
	if code != 0 {
		t.Fatalf("validate exit %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "outputTimestamp=") {
		t.Errorf("expected pass marker in stderr, got:\n%s", stderr)
	}

	if strings.Contains(stderr, "::warning") {
		t.Errorf("unexpected ::warning for properly-configured fixture, got:\n%s", stderr)
	}
}

// TestValidateJVMReproducibility_GradlePasses runs the validator
// against the gradle-hello fixture (which sets
// preserveFileTimestamps=false + reproducibleFileOrder=true).
func TestValidateJVMReproducibility_GradlePasses(t *testing.T) {
	proj := copyTree(t, fixture("gradle-hello"))

	plan := configPlan(`"gradle":[{"name":"gradle-hello","project_type":"gradle","working_directory":"."}]`)

	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{
		"CONFIG_PLAN_JSON": plan,
	}}, "validate", "jvm-reproducibility")
	if code != 0 {
		t.Fatalf("validate exit %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "preserveFileTimestamps=false") {
		t.Errorf("expected pass marker in stderr, got:\n%s", stderr)
	}

	if strings.Contains(stderr, "::warning") {
		t.Errorf("unexpected ::warning for properly-configured fixture, got:\n%s", stderr)
	}
}

// TestValidateJVMReproducibility_MissingTimestampFails verifies the
// negative path on a stripped-down POM (no outputTimestamp). The
// reproducibility setting is a hard gate — the deployable-pipeline
// contract treats determinism as foundational, so a non-reproducible
// JVM artefact cannot pass `validate prerequisites`.
func TestValidateJVMReproducibility_MissingTimestampFails(t *testing.T) {
	proj := t.TempDir()

	pom := []byte(`<?xml version="1.0"?>
<project><modelVersion>4.0.0</modelVersion>
  <groupId>g</groupId><artifactId>a</artifactId><version>1.0.0</version>
</project>`)
	if err := os.WriteFile(filepath.Join(proj, "pom.xml"), pom, 0o600); err != nil {
		t.Fatal(err)
	}

	plan := configPlan(`"maven":[{"name":"a","project_type":"maven","working_directory":"."}]`)

	// --format github forces the annotator into ::error:: prefix
	// regardless of the surrounding env (the run helper unsets
	// GITHUB_ACTIONS by default to keep tests host-independent).
	_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{
		"CONFIG_PLAN_JSON": plan,
	}}, "--format", "github", "validate", "jvm-reproducibility")
	if code == 0 {
		t.Errorf("validator must exit non-zero on missing outputTimestamp; got 0")
	}

	if !strings.Contains(stderr, "::error") {
		t.Errorf("expected ::error annotation, got stderr:\n%s", stderr)
	}

	if !strings.Contains(stderr, "<project.build.outputTimestamp>") {
		t.Errorf("expected actionable fix snippet in stderr, got:\n%s", stderr)
	}
}

// configPlan returns a minimal valid CONFIG_PLAN_JSON envelope with
// the supplied per-type artefact lists slotted in (plus mirrored
// under "all", which is what the validator iterates).
func configPlan(inner string) string {
	allLine := ""

	if inner != "" {
		left := strings.Index(inner, "[")
		right := strings.LastIndex(inner, "]")

		if left != -1 && right > left {
			allLine = `"all":` + inner[left:right+1] + `,`
		}
	}

	return `{"version":1,"artifacts":{` + allLine + inner + `},"containers":{"all":[],"has_containers":false}}`
}

