// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Package integration drives the compiled reusable-ci binary as a
// black box. Each Test* function builds a per-scenario fixture (Go
// project, Maven multi-module, GPG keyring, …), invokes the binary
// via os/exec, and asserts on the externally-observable result:
// files produced, exit codes, JSON schemas, signatures verifiable
// by sha256sum / gpg / git verify-tag.
//
// Why a separate package + build tag:
//
//   - The reusable-ci unit tests inside internal/... cover internal
//     contracts. They cannot catch failures that only surface when
//     real syft / mvn / gradle / cargo / gpg actually run.
//   - The `integration` build tag lets `go test ./...` ignore these
//     during development and `go test -tags=integration ./...` opt in
//     for the full suite.
//
// Host isolation:
//
//   - Every test seeds its own scratch dir + GIT_CONFIG_GLOBAL +
//     GIT_CONFIG_SYSTEM + GNUPGHOME so the developer's ~/.gitconfig
//     (e.g. gpg.format=ssh) cannot leak into a GPG test.
//
// Running:
//
//	go test -tags=integration ./tests/integration/...
//	go test -tags=integration -run TestGoBuildReproducible ./tests/integration/
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// binPath is the absolute path to the reusable-ci binary built by TestMain.
// Tests use it via exec.Command(binPath, ...).
var binPath string //nolint:gochecknoglobals // intentional: shared by every Test* via TestMain.

// suiteDir is the absolute path to the testsuite root (one level above
// tests/integration). Tests resolve fixtures relative to it.
var suiteDir string //nolint:gochecknoglobals // intentional: shared by every Test*.

// TestMain builds the binary once for the whole package. Tests run
// against this fresh build so a stale system-wide reusable-ci can
// never invalidate the suite.
func TestMain(m *testing.M) {
	// Resolve sibling reusable-ci checkout. The testsuite lives at
	// .../reusable-ci-testsuite/, so the binary source is at ../reusable-ci/.
	_, here, _, _ := runtime.Caller(0)
	suiteDir = filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))

	repo := filepath.Clean(filepath.Join(suiteDir, "..", "reusable-ci"))
	if _, err := os.Stat(filepath.Join(repo, "cmd", "reusable-ci")); err != nil {
		// Allow REUSABLE_CI override for CI runners that pre-build.
		if env := os.Getenv("REUSABLE_CI"); env != "" {
			binPath = env

			os.Exit(m.Run())
		}

		panic("integration: cannot find sibling ../reusable-ci/cmd/reusable-ci — set REUSABLE_CI to override")
	}

	tmp, err := os.MkdirTemp("", "reusable-ci-int-*")
	if err != nil {
		panic("integration: mktemp: " + err.Error())
	}

	defer os.RemoveAll(tmp)

	binPath = filepath.Join(tmp, "reusable-ci")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/reusable-ci") //nolint:gosec // hardcoded args; repo is a typed path under our control.
	cmd.Dir = repo
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		panic("integration: build reusable-ci: " + err.Error())
	}

	os.Exit(m.Run())
}
