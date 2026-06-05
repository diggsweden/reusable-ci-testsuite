// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGradleSBOMv1AndV2 verifies the build-layer SBOM works for both
// cyclonedx-gradle-plugin v1.x and v2.x. The fix in
// RenderGradleInitScript uses the real artifact coordinate +
// class-based apply<CycloneDxPlugin>() — a regression at either
// version line would surface as a failed `./gradlew cyclonedxBom`.
//
// Skipped when the fixture lacks a gradlew (gradle wrapper bootstrap
// needs a JDK and network).
func TestGradleSBOMv1AndV2(t *testing.T) {
	requireTool(t, "java")

	proj := copyTree(t, fixture("gradle-hello"))

	if !fileExists(filepath.Join(proj, "gradlew")) {
		t.Skipf("gradlew not present in fixture (need a JDK + network to bootstrap)")
	}

	javaHome := strings.TrimSpace(detectJavaHome(t))

	for _, version := range []string{"1.10.0", "2.0.0"} {
		t.Run("v"+version, func(t *testing.T) {
			// Clean per-version so the gradle cache doesn't mask a regression.
			_ = exec.Command("rm", "-rf", filepath.Join(proj, ".gradle"), filepath.Join(proj, "build")).Run()

			_, stderr, code := run(t, runOpts{dir: proj, env: map[string]string{"JAVA_HOME": javaHome}},
				"build", "gradle", "sbom", "--cyclonedx-version", version,
			)
			if code != 0 {
				t.Fatalf("gradle sbom v%s exit %d\nstderr:\n%s", version, code, stderr)
			}

			bom := filepath.Join(proj, "build", "reports", "bom.json")
			if !fileExists(bom) {
				t.Errorf("expected bom.json at %s", bom)
			}
		})
	}
}

// detectJavaHome resolves the active java's JAVA_HOME by walking
// `readlink -f $(which java)` up two directories — works for both the
// system /usr/bin/java symlink and mise/asdf shims.
func detectJavaHome(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("java")
	if err != nil {
		t.Skipf("java missing")
	}

	out, err := exec.Command("readlink", "-f", path).Output()
	if err != nil {
		t.Skipf("readlink: %v", err)
	}

	// .../bin/java → .../
	return filepath.Dir(filepath.Dir(strings.TrimSpace(string(out))))
}
