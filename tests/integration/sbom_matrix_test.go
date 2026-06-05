// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubCycloneDXBOM returns a minimal but schema-valid CycloneDX 1.6
// document body. The CISA build-layer "generator" is really a
// promote-and-rename — the source bom.json is produced by the
// ecosystem-native tool (cyclonedx-maven-plugin, cyclonedx-gomod,
// cargo-cyclonedx, …) during the project's own build. reusable-ci's
// job is only to discover and copy it under the canonical layer
// filename. Stubbing lets the test cover that contract without
// invoking the (often slow) generator.
func stubCycloneDXBOM() []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`)
}

// minimalZip returns the smallest byte sequence that a permissive
// archive scanner (syft) accepts as a valid zip: the 22-byte
// "end of central directory" record with all zero fields.
func minimalZip() []byte {
	return append([]byte{0x50, 0x4b, 0x05, 0x06}, make([]byte, 18)...)
}

// TestSBOMBuildLayerAllEcosystems verifies the CISA Build layer for
// every supported ecosystem. The Build layer is the dependency-list
// SBOM produced by the upstream tool — reusable-ci's role is to
// discover and promote it to the canonical filename. The test stubs
// the upstream output and asserts the promotion.
func TestSBOMBuildLayerAllEcosystems(t *testing.T) {
	cases := []struct {
		name        string
		fixture     string
		projectType string
		// path under the fixture where the upstream tool would drop bom.json
		bomPath string
	}{
		{name: "maven", fixture: "maven-hello", projectType: "maven", bomPath: "target/bom.json"},
		{name: "npm", fixture: "npm-hello", projectType: "npm", bomPath: "bom.json"},
		{name: "gradle", fixture: "gradle-hello", projectType: "gradle", bomPath: "build/reports/bom.json"},
		{name: "cargo", fixture: "cargo-hello", projectType: "cargo", bomPath: "bom.json"},
		{name: "go", fixture: "go-hello", projectType: "go", bomPath: "bom.json"},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proj := copyTree(t, fixture(tc.fixture))

			dst := filepath.Join(proj, tc.bomPath)
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(dst, stubCycloneDXBOM(), 0o600); err != nil {
				t.Fatal(err)
			}

			_, stderr, code := run(t, runOpts{dir: proj},
				"sbom", "generate", "all",
				"--project-type", tc.projectType,
				"--layers", "build",
				"--name", tc.fixture,
				"--version", "1.0.0",
			)
			if code != 0 {
				t.Fatalf("sbom generate all exit %d\nstderr: %s", code, stderr)
			}

			out := filepath.Join(proj, tc.fixture+"-1.0.0-build-sbom.cyclonedx.json")
			if !fileExists(out) {
				t.Fatalf("expected build SBOM at %s", out)
			}

			// Promoted SBOM must remain a valid CycloneDX document.
			var doc struct {
				BomFormat   string `json:"bomFormat"`
				SpecVersion string `json:"specVersion"`
			}
			if err := json.Unmarshal([]byte(readFile(t, out)), &doc); err != nil {
				t.Fatalf("parse promoted SBOM: %v", err)
			}

			if doc.BomFormat != "CycloneDX" || !strings.HasPrefix(doc.SpecVersion, "1.") {
				t.Errorf("CycloneDX header wrong in promoted SBOM: %+v", doc)
			}
		})
	}
}

// TestSBOMAnalyzedArtifactAllEcosystems verifies the CISA
// analyzed-artifact layer for every ecosystem with a binary artefact
// type. Each case materialises a stub artefact in the location
// `findXxx()` (see internal/app/sbom/discovery.go) expects, runs
// `sbom generate all --layers=analyzed-artifact`, and asserts that
// BOTH SPDX 2.3 and CycloneDX SBOMs are produced.
//
// Stubbing instead of "build the real thing": syft accepts minimal
// archives + executables, so a 22-byte empty zip / two-line shell
// script is enough to exercise the syft-invocation pipeline and the
// reusable-ci wrapper logic.
func TestSBOMAnalyzedArtifactAllEcosystems(t *testing.T) {
	requireTool(t, "syft")

	cases := []struct {
		name           string
		fixture        string
		projectType    string
		// artefact path under the fixture and content kind
		artefactPath string
		artefactBody []byte
		// expected SBOM filenames (suffix; we match against the basename)
		expectSPDX string
		expectCDX  string
		// optional: must be executable
		makeExecutable bool
		// optional: assertion key that artefact-layer flavor names must include
		flavourSubstring string
	}{
		{
			name:             "maven_jar",
			fixture:          "maven-hello",
			projectType:      "maven",
			artefactPath:     "target/maven-hello-1.0.0.jar",
			artefactBody:     minimalZip(),
			expectSPDX:       "maven-hello-1.0.0-analyzed-jar-sbom.spdx.json",
			expectCDX:        "maven-hello-1.0.0-analyzed-jar-sbom.cyclonedx.json",
			flavourSubstring: "jar",
		},
		{
			name:             "gradle_jar",
			fixture:          "gradle-hello",
			projectType:      "gradle",
			artefactPath:     "build/libs/gradle-hello-1.0.0.jar",
			artefactBody:     minimalZip(),
			expectSPDX:       "gradle-hello-1.0.0-analyzed-jar-sbom.spdx.json",
			expectCDX:        "gradle-hello-1.0.0-analyzed-jar-sbom.cyclonedx.json",
			flavourSubstring: "jar",
		},
		{
			name:             "cargo_binary",
			fixture:          "cargo-hello",
			projectType:      "cargo",
			artefactPath:     "target/release/cargo-hello",
			artefactBody:     []byte("#!/bin/sh\necho hi\n"),
			expectSPDX:       "cargo-hello-analyzed-binary-sbom.spdx.json",
			expectCDX:        "cargo-hello-analyzed-binary-sbom.cyclonedx.json",
			makeExecutable:   true,
			flavourSubstring: "binary",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proj := copyTree(t, fixture(tc.fixture))

			art := filepath.Join(proj, tc.artefactPath)
			if err := os.MkdirAll(filepath.Dir(art), 0o755); err != nil {
				t.Fatal(err)
			}

			mode := os.FileMode(0o600)
			if tc.makeExecutable {
				mode = 0o755
			}

			if err := os.WriteFile(art, tc.artefactBody, mode); err != nil {
				t.Fatal(err)
			}

			_, stderr, code := run(t, runOpts{dir: proj},
				"sbom", "generate", "all",
				"--project-type", tc.projectType,
				"--layers", "analyzed-artifact",
				"--name", tc.fixture,
				"--version", "1.0.0",
			)
			if code != 0 {
				t.Fatalf("sbom generate all exit %d\nstderr: %s", code, stderr)
			}

			spdx := filepath.Join(proj, tc.expectSPDX)
			cdx := filepath.Join(proj, tc.expectCDX)

			if !fileExists(spdx) {
				t.Errorf("missing SPDX SBOM at %s", spdx)
			}

			if !fileExists(cdx) {
				t.Errorf("missing CycloneDX SBOM at %s", cdx)
			}

			if fileExists(spdx) {
				var doc struct {
					SPDXVersion string `json:"spdxVersion"`
				}
				if err := json.Unmarshal([]byte(readFile(t, spdx)), &doc); err != nil {
					t.Fatalf("parse SPDX: %v", err)
				}

				if doc.SPDXVersion != "SPDX-2.3" {
					t.Errorf("SPDX version = %q, want SPDX-2.3", doc.SPDXVersion)
				}
			}

			if fileExists(cdx) {
				var doc struct {
					BomFormat   string `json:"bomFormat"`
					SpecVersion string `json:"specVersion"`
				}
				if err := json.Unmarshal([]byte(readFile(t, cdx)), &doc); err != nil {
					t.Fatalf("parse CycloneDX: %v", err)
				}

				if doc.BomFormat != "CycloneDX" {
					t.Errorf("CycloneDX bomFormat = %q", doc.BomFormat)
				}
			}
		})
	}
}

// TestSBOMBuildLayerMissingBOMFails verifies the negative path: when
// no bom.json exists, `sbom generate all --layers=build` exits with
// a non-zero validation code rather than silently producing nothing.
// This is the regression that turned "no SBOMs generated" from a
// silent exit-0 into an explicit error.
func TestSBOMBuildLayerMissingBOMFails(t *testing.T) {
	proj := copyTree(t, fixture("maven-hello"))

	_, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "maven",
		"--layers", "build",
		"--name", "maven-hello",
		"--version", "1.0.0",
	)
	if code == 0 {
		t.Errorf("expected non-zero exit when no bom.json source is present; got 0")
	}
}
