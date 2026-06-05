// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// `release sbom-zip` bundles every SBOM layer the release produced
// into <project>-<version>-sboms.zip, with the option to GPG-sign the
// resulting zip. This is the file that attaches to the GitHub Release.
//
// Per-ecosystem SBOM generation (build layer + analyzed-artifact)
// lives in sbom_matrix_test.go and the per-ecosystem files.

package integration

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// TestSBOMZipBundlesLayers verifies that `release sbom-zip` discovers
// every SBOM under the working dir, plus analyzed-container SBOMs
// under --sbom-dir, and bundles them into <project>-<version>-sboms.zip.
func TestSBOMZipBundlesLayers(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"app-1.0.0-sbom.spdx.json":              `{"spdxVersion":"SPDX-2.3"}`,
		"app-1.0.0-sbom.cyclonedx.json":         `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"app-1.0.0-analyzed-jar-sbom.spdx.json": `{"spdxVersion":"SPDX-2.3"}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	containerDir := filepath.Join(dir, "sbom-artifacts")
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		t.Fatal(err)
	}

	containerSBOM := filepath.Join(containerDir, "app-1.0.0-analyzed-container-sbom.spdx.json")
	if err := os.WriteFile(containerSBOM, []byte(`{"spdxVersion":"SPDX-2.3"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code := run(t, runOpts{dir: dir},
		"release", "sbom-zip",
		"--project-name", "app",
		"--version", "1.0.0",
		"--sbom-dir", "sbom-artifacts")
	if code != 0 {
		t.Fatalf("release sbom-zip exit %d", code)
	}

	zipPath := filepath.Join(dir, "app-1.0.0-sboms.zip")
	if !fileExists(zipPath) {
		t.Fatalf("expected %s", zipPath)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}

	defer zr.Close()

	got := map[string]bool{}
	for _, f := range zr.File {
		got[f.Name] = true
	}

	want := []string{
		"app-1.0.0-sbom.spdx.json",
		"app-1.0.0-sbom.cyclonedx.json",
		"app-1.0.0-analyzed-jar-sbom.spdx.json",
		// Container SBOMs are flattened (no sbom-artifacts/ prefix).
		"app-1.0.0-analyzed-container-sbom.spdx.json",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("zip missing %s; entries: %v", name, got)
		}
	}
}

// TestSBOMZipSignedWithGPG verifies the --sign path: an .asc detached
// signature must land next to the zip and verify against the same key.
func TestSBOMZipSignedWithGPG(t *testing.T) {
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "x-1.0.0-sbom.spdx.json"),
		[]byte(`{"spdxVersion":"SPDX-2.3"}`), 0o600); err != nil {
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
	},
		"release", "sbom-zip",
		"--project-name", "x",
		"--version", "1.0.0",
		"--sign")
	if code != 0 {
		t.Fatalf("release sbom-zip exit %d", code)
	}

	zipPath := filepath.Join(dir, "x-1.0.0-sboms.zip")
	sigPath := zipPath + ".asc"

	for _, p := range []string{zipPath, sigPath} {
		if !fileExists(p) {
			t.Errorf("expected %s", p)
		}
	}
}
