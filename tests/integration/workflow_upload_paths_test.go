// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Locks the artifact-visibility contract documented in
// docs/verification.md: every `actions/upload-artifact` step's
// `path:` field must be narrow. A bare `.`, `**`, or `/` would
// silently scoop up whatever lives in the working dir at upload
// time — including misplaced keystores, certs, or env-leaked
// secret files.
//
// The test reads every workflow under .github/workflows/ in the
// sibling reusable-ci repo and rejects any forbidden glob it finds.

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// forbiddenPathGlobs are the upload-artifact `path:` values we never
// want to see. A line equal to one of these (or a multi-line entry
// containing one as a standalone line) is the signal of an
// over-broad upload.
//
//nolint:gochecknoglobals // immutable test data.
var forbiddenPathGlobs = []string{
	".",
	"./",
	"/",
	"**",
	"**/*",
	"./**",
	"./**/*",
}

// TestWorkflows_UploadArtifactPathsAreNarrow scans every workflow
// YAML and asserts no `actions/upload-artifact` step uses an
// over-broad path. Locks the visibility contract.
func TestWorkflows_UploadArtifactPathsAreNarrow(t *testing.T) {
	workflowDir := workflowsDir(t)

	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("read workflows dir: %v", err)
	}

	var violations []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}

		path := filepath.Join(workflowDir, e.Name())
		violations = append(violations, scanWorkflow(t, path)...)
	}

	if len(violations) > 0 {
		t.Errorf("upload-artifact path-glob violations:\n  %s", strings.Join(violations, "\n  "))
	}
}

// scanWorkflow walks every step in a workflow YAML, finds
// actions/upload-artifact uses, and returns a violation string for
// every forbidden `path:` glob it sees.
//nolint:cyclop // YAML walk: one branch per shape variant.
func scanWorkflow(t *testing.T, path string) []string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var doc workflowDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var violations []string

	for jobName, job := range doc.Jobs {
		for stepIdx, step := range job.Steps {
			if !strings.Contains(step.Uses, "actions/upload-artifact") {
				continue
			}

			for _, p := range splitPathLines(step.With.Path) {
				if isForbiddenGlob(p) {
					violations = append(violations,
						filepath.Base(path)+": job "+jobName+", step "+itoa(stepIdx)+
							" ("+step.Name+"): path=\""+p+"\" is over-broad",
					)
				}
			}
		}
	}

	return violations
}

// splitPathLines handles upload-artifact's `path:` which can be a
// scalar or a multi-line block scalar listing several globs.
func splitPathLines(raw string) []string {
	if raw == "" {
		return nil
	}

	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))

	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}

		out = append(out, l)
	}

	return out
}

func isForbiddenGlob(p string) bool {
	for _, bad := range forbiddenPathGlobs {
		if p == bad {
			return true
		}
	}

	return false
}

// workflowsDir locates the .github/workflows directory in the
// sibling reusable-ci repository. The testsuite is a sibling of the
// CLI repo (../reusable-ci/.github/workflows).
func workflowsDir(t *testing.T) string {
	t.Helper()

	// suiteDir is set in main_test.go.
	candidate := filepath.Join(suiteDir, "..", "reusable-ci", ".github", "workflows")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	t.Skipf("sibling .github/workflows not found at %s — this test only runs in a checkout with the sibling CLI repo", candidate)

	return ""
}

// itoa avoids strconv import for a one-off integer-to-string in
// error messages.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	var b []byte

	neg := n < 0
	if neg {
		n = -n
	}

	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...) //nolint:mnd // ASCII base-10 digit conversion.
		n /= 10                                    //nolint:mnd
	}

	if neg {
		b = append([]byte{'-'}, b...)
	}

	return string(b)
}

// workflowDoc is the minimal slice of a GitHub Actions workflow we
// need to enumerate upload-artifact steps. Extra fields are
// ignored by go-yaml; we don't have to model the full schema.
type workflowDoc struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string           `yaml:"name"`
	Uses string           `yaml:"uses"`
	With workflowStepWith `yaml:"with"`
}

type workflowStepWith struct {
	Path string `yaml:"path"`
}
