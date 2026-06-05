// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// NPM-specific integration tests: the analyzed-artifact SBOM flow,
// build-type-specific assertions (application vs pack/lib) live in
// build_type_test.go.
//
// Cross-cutting NPM coverage (version bump, reproducibility, exit
// codes) is in the matrix files (version_bump_matrix_test.go,
// reproducibility_test.go, exit_codes_test.go).

package integration

import (
	"path/filepath"
	"testing"
)

// TestSBOMNPMAnalyzedArtifact verifies the CISA analyzed-artifact
// layer for an NPM project: `npm pack` produces a tarball, then
// `sbom generate all --layers=analyzed-artifact` runs syft against
// it and emits both SPDX and CycloneDX documents.
//
// Skips when `npm` is not on PATH. The matrix test
// TestSBOMAnalyzedArtifactAllEcosystems covers jar/binary variants
// with stubbed artefacts; this test exercises the NPM-specific path
// with a real tarball.
func TestSBOMNPMAnalyzedArtifact(t *testing.T) {
	requireTool(t, "syft")
	requireTool(t, "npm")

	proj := copyTree(t, fixture("npm-hello"))

	if _, _, code := runTool(t, proj, "npm", "pack"); code != 0 {
		t.Fatalf("npm pack failed")
	}

	_, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "npm",
		"--layers", "analyzed-artifact",
		"--version", "0.1.0",
		"--name", "npm-hello")
	if code != 0 {
		t.Fatalf("sbom generate all exit %d", code)
	}

	// At least one SBOM file must land in the project root.
	matches, err := filepath.Glob(filepath.Join(proj, "*analyzed*sbom*.json"))
	if err != nil || len(matches) == 0 {
		t.Errorf("no analyzed SBOM files produced; glob err=%v matches=%v", err, matches)
	}
}
