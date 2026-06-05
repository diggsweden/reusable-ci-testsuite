// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCargoSBOMSingleCrate verifies cargo-cyclonedx produces a per-crate
// bom.xml. reusable-ci doesn't run cargo here — the SBOM is generated
// by the upstream tool and consumed by sbom-cargo.yml at workflow
// level. This test confirms the contract is honoured.
func TestCargoSBOMSingleCrate(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "cargo-cyclonedx")

	proj := copyTree(t, fixture("cargo-hello"))

	cmd := exec.Command("cargo", "cyclonedx", "--override-filename", "bom")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo cyclonedx: %v\n%s", err, out)
	}

	bom := filepath.Join(proj, "bom.xml")
	if !fileExists(bom) {
		t.Errorf("expected bom.xml at %s", bom)
	}
}

// TestCargoSBOMWorkspace verifies the workspace variant produces one
// bom.xml per workspace member (not one merged file).
func TestCargoSBOMWorkspace(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "cargo-cyclonedx")

	proj := copyTree(t, fixture("cargo-workspace"))

	cmd := exec.Command("cargo", "cyclonedx", "--override-filename", "bom")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo cyclonedx: %v\n%s", err, out)
	}

	for _, crate := range []string{"common", "cli", "server"} {
		bom := filepath.Join(proj, "crates", crate, "bom.xml")
		if !fileExists(bom) {
			t.Errorf("expected bom.xml at %s", bom)
		}
	}
}
