// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestGoBuildReproducible verifies that `reusable-ci build go compile`
// produces byte-identical binaries across runs when SOURCE_DATE_EPOCH
// is fixed. Reproducible builds let a SHA256 stand in as a true
// fingerprint of the inputs.
//
// We also assert that a DIFFERENT SOURCE_DATE_EPOCH yields a different
// SHA — otherwise the date isn't actually being baked in (silent
// failure mode of an ldflag injection).
func TestGoBuildReproducible(t *testing.T) {
	requireTool(t, "go")

	proj := copyTree(t, fixture("go-hello"))

	env := map[string]string{
		"SOURCE_DATE_EPOCH": "1700000000",
		"GITHUB_SHA":        "abc123",
	}

	compile := func() string {
		_, _, code := run(t, runOpts{dir: proj, env: env},
			"build", "go", "compile",
			"--version", "v0.1.0", "--platforms", "linux/amd64",
		)
		if code != 0 {
			t.Fatalf("compile exit %d", code)
		}

		return sha256File(t, filepath.Join(proj, "dist", "linux-amd64", "go-hello-linux-amd64"))
	}

	first := compile()

	if err := os.RemoveAll(filepath.Join(proj, "dist")); err != nil {
		t.Fatal(err)
	}

	second := compile()

	if first != second {
		t.Errorf("two compiles with identical inputs produced different SHAs:\n  first:  %s\n  second: %s", first, second)
	}

	// Change SOURCE_DATE_EPOCH; SHA must change.
	if err := os.RemoveAll(filepath.Join(proj, "dist")); err != nil {
		t.Fatal(err)
	}

	envDifferent := map[string]string{"SOURCE_DATE_EPOCH": "1800000000", "GITHUB_SHA": "abc123"}
	_, _, code := run(t, runOpts{dir: proj, env: envDifferent},
		"build", "go", "compile", "--version", "v0.1.0", "--platforms", "linux/amd64")

	if code != 0 {
		t.Fatalf("compile exit %d", code)
	}

	third := sha256File(t, filepath.Join(proj, "dist", "linux-amd64", "go-hello-linux-amd64"))
	if third == first {
		t.Errorf("changing SOURCE_DATE_EPOCH did not change binary SHA — date is not being baked in")
	}
}

// TestGoBuildMultiPlatformReproducible verifies reproducibility holds
// across every platform a release matrix would emit (linux/amd64,
// darwin/arm64, windows/amd64). The .exe suffix on windows is handled
// transparently.
func TestGoBuildMultiPlatformReproducible(t *testing.T) {
	requireTool(t, "go")

	proj := copyTree(t, fixture("go-hello"))

	platforms := "linux/amd64,darwin/arm64,windows/amd64"
	files := map[string]string{
		"linux/amd64":   filepath.Join(proj, "dist", "linux-amd64", "go-hello-linux-amd64"),
		"darwin/arm64":  filepath.Join(proj, "dist", "darwin-arm64", "go-hello-darwin-arm64"),
		"windows/amd64": filepath.Join(proj, "dist", "windows-amd64", "go-hello-windows-amd64.exe"),
	}

	env := map[string]string{"SOURCE_DATE_EPOCH": "1700000000", "GITHUB_SHA": "abc123"}

	compile := func() map[string]string {
		_, _, code := run(t, runOpts{dir: proj, env: env},
			"build", "go", "compile", "--version", "v0.1.0", "--platforms", platforms,
		)
		if code != 0 {
			t.Fatalf("compile exit %d", code)
		}

		hashes := make(map[string]string, len(files))
		for k, p := range files {
			hashes[k] = sha256File(t, p)
		}

		return hashes
	}

	first := compile()

	if err := os.RemoveAll(filepath.Join(proj, "dist")); err != nil {
		t.Fatal(err)
	}

	second := compile()
	for plat, hash := range first {
		if second[plat] != hash {
			t.Errorf("platform %s not reproducible:\n  first:  %s\n  second: %s", plat, hash, second[plat])
		}
	}
}

// TestGoBuildSBOMCISABuildLayer verifies the CISA "build" layer SBOM
// for a Go project via cyclonedx-gomod. The generator writes a
// CycloneDX JSON document under .reusable-ci/go-build-sbom/<name>/
// with components derived from go.mod.
func TestGoBuildSBOMCISABuildLayer(t *testing.T) {
	requireTool(t, "go")
	requireTool(t, "cyclonedx-gomod")

	proj := copyTree(t, fixture("go-hello"))

	_, stderr, code := run(t, runOpts{dir: proj},
		"build", "go", "sbom", "--binary-name", "go-hello")
	if code != 0 {
		t.Fatalf("sbom exit %d\nstderr: %s", code, stderr)
	}

	bomPath := filepath.Join(proj, ".reusable-ci", "go-build-sbom", "go-hello", "bom.json")
	if !fileExists(bomPath) {
		t.Fatalf("expected bom.json at %s", bomPath)
	}

	var bom struct {
		SpecVersion string `json:"specVersion"`
		BomFormat   string `json:"bomFormat"`
		Components  []any  `json:"components"`
	}
	if err := json.Unmarshal([]byte(readFile(t, bomPath)), &bom); err != nil {
		t.Fatalf("parse bom.json: %v", err)
	}

	if bom.BomFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BomFormat)
	}

	if bom.SpecVersion == "" {
		t.Errorf("specVersion missing")
	}

	if len(bom.Components) == 0 {
		t.Errorf("no components — go.mod has cobra dep, so the SBOM should list it")
	}
}

// TestGoSBOMAnalyzedArtifact verifies the CISA "analyzed-artifact"
// layer for Go via syft. After compile, syft analyses the resulting
// binary and emits BOTH SPDX 2.3 and CycloneDX 1.6 documents.
func TestGoSBOMAnalyzedArtifact(t *testing.T) {
	requireTool(t, "go")
	requireTool(t, "syft")

	proj := copyTree(t, fixture("go-hello"))

	_, _, code := run(t, runOpts{dir: proj, env: map[string]string{"SOURCE_DATE_EPOCH": "1700000000"}},
		"build", "go", "compile", "--version", "v0.1.0", "--platforms", "linux/amd64",
	)
	if code != 0 {
		t.Fatalf("compile exit %d", code)
	}

	_, stderr, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--layers", "analyzed-artifact",
		"--version", "0.1.0",
		"--name", "go-hello",
	)
	if code != 0 {
		t.Fatalf("sbom exit %d\nstderr: %s", code, stderr)
	}

	spdxPath := filepath.Join(proj, "go-hello-linux-amd64-analyzed-binary-sbom.spdx.json")
	cdxPath := filepath.Join(proj, "go-hello-linux-amd64-analyzed-binary-sbom.cyclonedx.json")

	for _, p := range []string{spdxPath, cdxPath} {
		if !fileExists(p) {
			t.Errorf("expected SBOM at %s", p)
		}
	}

	var spdx struct {
		SPDXVersion string `json:"spdxVersion"`
		Name        string `json:"name"`
		Packages    []any  `json:"packages"`
	}
	if err := json.Unmarshal([]byte(readFile(t, spdxPath)), &spdx); err != nil {
		t.Fatalf("parse SPDX: %v", err)
	}

	if spdx.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDX version = %q, want SPDX-2.3", spdx.SPDXVersion)
	}

	if spdx.Name == "" {
		t.Errorf("SPDX document name empty")
	}

	if len(spdx.Packages) == 0 {
		t.Errorf("SPDX has no packages")
	}

	var cdx struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []any  `json:"components"`
	}
	if err := json.Unmarshal([]byte(readFile(t, cdxPath)), &cdx); err != nil {
		t.Fatalf("parse CycloneDX: %v", err)
	}

	if cdx.BomFormat != "CycloneDX" {
		t.Errorf("CycloneDX bomFormat = %q", cdx.BomFormat)
	}

	if cdx.SpecVersion == "" {
		t.Errorf("CycloneDX specVersion empty")
	}

	if len(cdx.Components) == 0 {
		t.Errorf("CycloneDX has no components")
	}
}
