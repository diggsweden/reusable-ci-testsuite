// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestMavenMetadataSingleModule verifies the metadata path for a
// single-module Maven project. reusable-ci reads pom.xml directly
// (no mvn subprocess) and emits typed JSON outputs.
func TestMavenMetadataSingleModule(t *testing.T) {
	proj := copyTree(t, fixture("maven-hello"))

	stdout, _, code := run(t, runOpts{dir: proj}, "--json", "build", "maven", "metadata")
	if code != 0 {
		t.Fatalf("metadata exit %d", code)
	}

	var got struct {
		Version    string `json:"version"`
		GroupID    string `json:"group-id"`
		ArtifactID string `json:"artifact-id"`
		IsSnapshot bool   `json:"is-snapshot"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, stdout)
	}

	if got.Version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", got.Version)
	}

	if got.GroupID != "se.digg.test" {
		t.Errorf("group-id = %q", got.GroupID)
	}

	if got.ArtifactID != "maven-hello" {
		t.Errorf("artifact-id = %q", got.ArtifactID)
	}

	if got.IsSnapshot {
		t.Errorf("is-snapshot should be false (typed bool)")
	}
}

// TestMavenMetadataMultiModule covers parent-pom + child-module
// inheritance:
//   - reading from the root pom returns the parent artifactId
//   - reading from a submodule returns the submodule's artifactId
//     but inherits <version> from <parent>
func TestMavenMetadataMultiModule(t *testing.T) {
	proj := copyTree(t, fixture("maven-multi"))

	stdoutRoot, _, codeRoot := run(t, runOpts{dir: proj},
		"--json", "build", "maven", "metadata")
	if codeRoot != 0 {
		t.Fatalf("root metadata exit %d", codeRoot)
	}

	var root struct {
		Version    string `json:"version"`
		ArtifactID string `json:"artifact-id"`
	}
	if err := json.Unmarshal([]byte(stdoutRoot), &root); err != nil {
		t.Fatalf("parse root: %v", err)
	}

	if root.Version != "2.0.0" {
		t.Errorf("root version = %q, want 2.0.0", root.Version)
	}

	if root.ArtifactID != "maven-multi-parent" {
		t.Errorf("root artifact-id = %q", root.ArtifactID)
	}

	stdoutCore, _, codeCore := run(t, runOpts{dir: filepath.Join(proj, "core")},
		"--json", "build", "maven", "metadata")
	if codeCore != 0 {
		t.Fatalf("submodule metadata exit %d", codeCore)
	}

	var core struct {
		Version    string `json:"version"`
		ArtifactID string `json:"artifact-id"`
	}
	if err := json.Unmarshal([]byte(stdoutCore), &core); err != nil {
		t.Fatalf("parse core: %v", err)
	}

	if core.Version != "2.0.0" {
		t.Errorf("submodule should inherit version 2.0.0, got %q", core.Version)
	}

	if core.ArtifactID != "core" {
		t.Errorf("submodule artifact-id = %q, want core", core.ArtifactID)
	}
}
