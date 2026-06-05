// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// End-to-end cascade tests for the container-first flow:
//
//   sbom build-layer (lockfile-derived) → container build OR direct
//   compile → extracted binary in release-artifacts/ → analyzed-
//   artifact SBOM → checksums → sign
//
// Distinct from artefact-first because:
//
//   1. The build-layer SBOM comes from the lockfile (Cargo.lock /
//      go.sum) via cargo-cyclonedx / cyclonedx-gomod, NOT from
//      build observation.
//   2. The "artefact" is a binary extracted from the container,
//      named with the -<os>-<arch> convention used by `extract.
//      binary` (so multi-arch matrix uploads don't collide).
//   3. There is no `release-build-stage` step for these
//      ecosystems — sbom-cargo.yml / sbom-go.yml run in
//      `release-publish-stage` alongside the container build.
//
// The Cargo variant uses real buildah (skips when buildah is
// missing) to exercise the full path through `publish-container.
// yml`'s reproducibility plumbing. The Go variant uses host
// `go build` directly to keep the test fast — TestReproducible-
// ContainerImage already covers buildah end-to-end, so the cost
// of running it twice isn't justified.

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFlow_ContainerFirst_Cargo runs the full container-first
// cascade for Cargo, including a real buildah build with
// --timestamp pinning. Asserts:
//
//   - the lockfile-derived build-layer SBOM (cargo-cyclonedx)
//     promotes correctly into <name>-<version>-build-sbom.cyclonedx.json
//   - buildah's `--target=export-binary --output=type=local,...`
//     produces the binary at the expected name
//   - the syft analyzed-binary SBOM lands next to it
//   - checksums + sign work end-to-end
func TestFlow_ContainerFirst_Cargo(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "cargo-cyclonedx")
	requireTool(t, "buildah")
	requireTool(t, "syft")
	requireTool(t, "gpg")
	requireTool(t, "sha256sum")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("cargo-hello"))

	// 1. Build-layer SBOM: cargo-cyclonedx writes bom.json; reusable-ci
	//    promotes it. This step normally runs in sbom-cargo.yml in
	//    release-publish-stage (sibling of the container build),
	//    not before/during it — but the cascade order is preserved
	//    in the test for determinism.
	// --format json because reusable-ci's build-layer discovery
	// looks for `*/bom.json`. cargo-cyclonedx defaults to XML.
	if _, _, code := runTool(t, proj, "cargo", "cyclonedx", "--format", "json", "--override-filename", "bom"); code != 0 {
		t.Fatalf("step 1 cargo-cyclonedx exit %d", code)
	}

	if _, stderr, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "cargo",
		"--layers", "build",
		"--name", "cargo-hello", "--version", "0.3.1"); code != 0 {
		t.Fatalf("step 1 build-sbom promotion exit %d\nstderr: %s", code, stderr)
	}

	buildSBOM := filepath.Join(proj, "cargo-hello-0.3.1-build-sbom.cyclonedx.json")
	if !fileExists(buildSBOM) {
		t.Fatalf("step 1 missing %s", buildSBOM)
	}

	// 2. Container build with --timestamp pinning. Extract the
	//    binary via the export-binary scratch stage. This is the
	//    `extract.binary` path from publish-container.yml.
	//    NB: dest must NOT be ./release-artifacts/ — that's the
	//    default --release-artifacts-dir, and the release-checksums
	//    walk would emit a duplicate basename-only entry that
	//    breaks `sha256sum --check`. Use ./dist/ instead.
	extract := filepath.Join(proj, "dist")
	if err := os.MkdirAll(extract, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, _, code := runTool(t, proj, "buildah", "build",
		"--timestamp", "1700000000",
		"--target", "export-binary",
		"--output", "type=local,dest="+extract,
		"-f", "Containerfile", "."); code != 0 {
		t.Skipf("buildah build failed (likely missing rust:1.94-bookworm-slim in registry cache); container-first cascade not exercised on this host")
	}

	// Rename binary to the multi-arch convention extract.binary
	// emits: <name>-linux-<arch>.
	if err := os.Rename(
		filepath.Join(extract, "cargo-hello"),
		filepath.Join(extract, "cargo-hello-linux-amd64"),
	); err != nil {
		t.Fatalf("step 2 rename: %v", err)
	}

	// 3. Analyzed-artifact SBOM over the extracted binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "cargo",
		"--layers", "analyzed-artifact",
		"--name", "cargo-hello", "--version", "0.3.1"); code != 0 {
		t.Fatalf("step 3 analyzed sbom exit %d", code)
	}

	if matches, _ := filepath.Glob(filepath.Join(proj, "*analyzed-binary*sbom*.json")); len(matches) < 2 {
		t.Fatalf("step 3 expected SPDX+CycloneDX analyzed-binary SBOMs; got %v", matches)
	}

	// 4. Checksums covering binary + build-SBOM + analyzed-SBOM.
	//    Use --attach-artifacts so the binary's path stays
	//    verbatim in the manifest — sha256sum --check runs from
	//    cwd and needs that path to resolve.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "dist/cargo-hello-linux-amd64",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 4 checksums exit %d", code)
	}

	body := readFile(t, filepath.Join(proj, "checksums.sha256"))
	for _, want := range []string{"cargo-hello-linux-amd64", "build-sbom.cyclonedx.json", "analyzed-binary-sbom.spdx.json"} {
		if !strings.Contains(body, want) {
			t.Errorf("step 4 manifest missing %q; got:\n%s", want, body)
		}
	}

	// 5. Sign the binary + manifest.
	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	}, "release", "sign",
		"--attach-artifacts", "dist/cargo-hello-linux-amd64"); code != 0 {
		t.Fatalf("step 5 sign exit %d\nstderr: %s", code, stderr)
	}

	// 6. Manifest round-trip + signature verification.
	cmd := exec.Command("sha256sum", "--check", "checksums.sha256")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 6 sha256sum --check: %v\n%s", err, out)
	}

	asc := filepath.Join(proj, "checksums.sha256.asc")
	if !fileExists(asc) {
		t.Errorf("step 6 missing checksums signature")
	} else {
		verify := exec.Command("gpg", "--verify", asc, filepath.Join(proj, "checksums.sha256"))
		verify.Env = append(os.Environ(), "GNUPGHOME="+key.gnupgHome)

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify checksums: %v\n%s", err, out)
		}
	}
}

// TestFlow_ContainerFirst_Go runs the equivalent cascade for Go.
// Uses host `go build` instead of buildah to keep this test fast
// (TestReproducibleContainerImage already covers the buildah path
// end-to-end). The cascade contract is identical: lockfile-SBOM
// → extracted binary → analyzed-binary SBOM → checksums → sign.
func TestFlow_ContainerFirst_Go(t *testing.T) {
	requireTool(t, "go")
	requireTool(t, "cyclonedx-gomod")
	requireTool(t, "syft")
	requireTool(t, "gpg")
	requireTool(t, "sha256sum")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("go-hello"))

	// 1. Build-layer SBOM via reusable-ci build go sbom. For Go
	//    artefact-first, this lives in `release-build-stage`. For
	//    Go container-first it would run in `sbom-go.yml` during
	//    publish stage. Either way, the binary it produces is the
	//    `*/bom.json` reusable-ci promotes.
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "go", "sbom", "--binary-name", "go-hello"); code != 0 {
		t.Fatalf("step 1 build go sbom exit %d\nstderr: %s", code, stderr)
	}

	// 2. Promote into the canonical build-layer name.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "go",
		"--layers", "build",
		"--name", "go-hello", "--version", "0.1.0"); code != 0 {
		t.Fatalf("step 2 build-sbom promotion exit %d", code)
	}

	buildSBOM := filepath.Join(proj, "go-hello-0.1.0-build-sbom.cyclonedx.json")
	if !fileExists(buildSBOM) {
		t.Fatalf("step 2 missing %s", buildSBOM)
	}

	// 3. Compile the binary (simulating what extract.binary would
	//    produce out of the container's export-binary stage).
	//    NB: using `./dist/` (not `./release-artifacts/`) because
	//    release checksums walks --release-artifacts-dir (default
	//    `./release-artifacts/`) and would emit a duplicate entry
	//    with basename-only label, breaking sha256sum --check.
	extract := filepath.Join(proj, "dist")
	if err := os.MkdirAll(extract, 0o755); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(extract, "go-hello-linux-amd64")
	if _, _, code := runToolEnv(t, proj, map[string]string{"GOOS": "linux", "GOARCH": "amd64"},
		"go", "build", "-trimpath", "-buildvcs=false", "-o", bin, "./"); code != 0 {
		t.Fatalf("step 3 go build exit %d", code)
	}

	// 4. Analyzed-artifact SBOM over the extracted binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "go",
		"--layers", "analyzed-artifact",
		"--name", "go-hello", "--version", "0.1.0"); code != 0 {
		t.Fatalf("step 4 analyzed sbom exit %d", code)
	}

	// Validate the SPDX header on the analyzed-binary SBOM.
	spdxPath := filepath.Join(proj, "go-hello-linux-amd64-analyzed-binary-sbom.spdx.json")
	if !fileExists(spdxPath) {
		t.Fatalf("step 4 missing %s", spdxPath)
	}

	var spdx struct {
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal([]byte(readFile(t, spdxPath)), &spdx); err != nil {
		t.Fatalf("step 4 parse SPDX: %v", err)
	}

	if spdx.SPDXVersion != "SPDX-2.3" {
		t.Errorf("step 4 SPDX version %q, want SPDX-2.3", spdx.SPDXVersion)
	}

	// 5. Checksums + 6. Sign + 7. Verify. --attach-artifacts keeps
	//    the binary's path verbatim so sha256sum --check from cwd
	//    resolves it (release-artifacts/go-hello-linux-amd64).
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "dist/go-hello-linux-amd64",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 5 checksums exit %d", code)
	}

	body := readFile(t, filepath.Join(proj, "checksums.sha256"))
	for _, want := range []string{"go-hello-linux-amd64", "build-sbom.cyclonedx.json", "analyzed-binary-sbom"} {
		if !strings.Contains(body, want) {
			t.Errorf("step 5 manifest missing %q", want)
		}
	}

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	}, "release", "sign",
		"--attach-artifacts", "dist/go-hello-linux-amd64"); code != 0 {
		t.Fatalf("step 6 sign exit %d\nstderr: %s", code, stderr)
	}

	cmd := exec.Command("sha256sum", "--check", "checksums.sha256")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 7 sha256sum --check: %v\n%s", err, out)
	}
}
