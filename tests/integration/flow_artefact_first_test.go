// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// End-to-end cascade tests for the artefact-first flow:
//
//   build metadata → build artefact → SBOM (build + analyzed-artifact)
//   → checksums → sign → verify
//
// Each step's output feeds the next. The value of these tests over
// the per-step slice tests is catching contract drift between
// adjacent steps — e.g. the SBOM filename convention must match
// what `release checksums --sbom-dir` discovers, the artefact dir
// must align with what `release sign --release-artifacts-dir`
// expects, and the GPG key plumbing must thread through both.

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFlow_ArtefactFirst_MavenApp runs the canonical cascade for a
// Maven application project. Asserts every output that the next step
// consumes is present and well-formed.
func TestFlow_ArtefactFirst_MavenApp(t *testing.T) {
	requireTool(t, "mvn")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("maven-hello"))

	// 1. build maven application → target/<name>-<version>.jar
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "maven", "application", "--cli-opts", "-B -ntp", "--skip-tests"); code != 0 {
		t.Fatalf("step 1 build exit %d\nstderr: %s", code, stderr)
	}

	mainJar := filepath.Join(proj, "target", "maven-hello-1.0.0.jar")
	if !fileExists(mainJar) {
		t.Fatalf("step 1 missing main jar at %s", mainJar)
	}

	// 2. sbom generate all --layers=analyzed-artifact
	//    (build-layer stubbing isn't part of this cascade — caller
	//    runs cyclonedx-maven-plugin during the build, which this
	//    fixture doesn't to keep the test under 30s; analyzed-
	//    artifact is the layer this cascade exercises.)
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "maven",
		"--layers", "analyzed-artifact",
		"--name", "maven-hello", "--version", "1.0.0"); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	spdx := filepath.Join(proj, "maven-hello-1.0.0-analyzed-jar-sbom.spdx.json")
	cdx := filepath.Join(proj, "maven-hello-1.0.0-analyzed-jar-sbom.cyclonedx.json")

	for _, p := range []string{spdx, cdx} {
		if !fileExists(p) {
			t.Fatalf("step 2 missing SBOM at %s", p)
		}
	}

	// 3. release checksums via --attach-artifacts (the real
	//    workflow's mode: ATTACH_ARTIFACTS env, paths kept verbatim).
	//    --release-artifacts-dir would strip the target/ prefix and
	//    break sha256sum --check, which runs relative to cwd.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "target/maven-hello-1.0.0.jar",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	manifest := filepath.Join(proj, "checksums.sha256")
	if !fileExists(manifest) {
		t.Fatalf("step 3 missing %s", manifest)
	}

	body := readFile(t, manifest)
	for _, want := range []string{"maven-hello-1.0.0.jar", "analyzed-jar-sbom.spdx.json", "analyzed-jar-sbom.cyclonedx.json"} {
		if !strings.Contains(body, want) {
			t.Errorf("step 3 manifest missing %q; got:\n%s", want, body)
		}
	}

	// 4. release sign — same --attach-artifacts shape. .asc files
	//    land in cwd per the sign subcommand's contract.
	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	},
		"release", "sign",
		"--attach-artifacts", "target/maven-hello-1.0.0.jar"); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. verify the manifest round-trips through sha256sum --check.
	cmd := exec.Command("sha256sum", "--check", "checksums.sha256")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. verify GPG detached signatures on the jar AND the manifest.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "maven-hello-1.0.0.jar.asc", subj: "target/maven-hello-1.0.0.jar"},
	} {
		ascPath := filepath.Join(proj, pair.asc)

		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := exec.Command("gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))
		verify.Env = append(os.Environ(), "GNUPGHOME="+key.gnupgHome)

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtefactFirst_MavenLib mirrors the app cascade but uses
// the library shape. The extra contract here: checksums must cover
// the sources jar AND its analyzed-artifact SBOM pair, not just the
// main jar.
func TestFlow_ArtefactFirst_MavenLib(t *testing.T) {
	requireTool(t, "mvn")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("maven-lib"))

	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "maven", "library", "--cli-opts", "-B -ntp", "--skip-tests"); code != 0 {
		t.Fatalf("library build exit %d\nstderr: %s", code, stderr)
	}

	for _, suffix := range []string{".jar", "-sources.jar", "-javadoc.jar"} {
		if !fileExists(filepath.Join(proj, "target", "maven-lib-1.0.0"+suffix)) {
			t.Fatalf("missing maven-lib-1.0.0%s", suffix)
		}
	}

	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "maven",
		"--layers", "analyzed-artifact",
		"--name", "maven-lib", "--version", "1.0.0"); code != 0 {
		t.Fatalf("sbom exit %d", code)
	}

	// Match the production workflow pattern (ATTACH_ARTIFACTS) so
	// paths in the manifest stay relative to cwd and round-trip
	// through sha256sum --check.
	attach := "target/maven-lib-1.0.0.jar,target/maven-lib-1.0.0-sources.jar,target/maven-lib-1.0.0-javadoc.jar"
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", attach,
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("checksums exit %d", code)
	}

	body := readFile(t, filepath.Join(proj, "checksums.sha256"))
	for _, want := range []string{"maven-lib-1.0.0.jar", "maven-lib-1.0.0-sources.jar", "maven-lib-1.0.0-javadoc.jar"} {
		if !strings.Contains(body, want) {
			t.Errorf("checksums manifest missing %q", want)
		}
	}

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	},
		"release", "sign",
		"--attach-artifacts", attach); code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	// .asc files land in cwd (the sign subcommand's contract).
	for _, suffix := range []string{".jar.asc", "-sources.jar.asc", "-javadoc.jar.asc"} {
		ascPath := filepath.Join(proj, "maven-lib-1.0.0"+suffix)
		if !fileExists(ascPath) {
			t.Errorf("missing signature %s", ascPath)
		}
	}
}

// TestFlow_ArtefactFirst_Gradle runs the canonical cascade for a
// Gradle JVM project: build → SBOM → checksums → sign → verify.
// Same contract as the Maven cascade; the value here is catching
// drift in the gradle-specific outputs (build/libs/ vs Maven's
// target/) and confirming the jar lands where downstream steps
// expect it.
func TestFlow_ArtefactFirst_Gradle(t *testing.T) {
	requireTool(t, "java")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("gradle-hello"))

	if !fileExists(filepath.Join(proj, "gradlew")) {
		t.Skipf("gradlew not present in fixture (gradle wrapper bootstrap needs JDK + network)")
	}

	// 1. build gradle application → build/libs/<name>-<version>.jar
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "gradle", "application",
		"--tasks", "build", "--skip-tests"); code != 0 {
		t.Fatalf("step 1 gradle build exit %d\nstderr: %s", code, stderr)
	}

	jars, _ := filepath.Glob(filepath.Join(proj, "build", "libs", "*.jar"))
	if len(jars) < 1 {
		t.Fatalf("step 1 expected at least one jar in build/libs; got %v", jars)
	}
	// gradle-hello pins its version in gradle.properties; the SBOM
	// step extracts the version from the jar filename, so the asserted
	// SBOM names below must match that — not the --version flag.
	mainJar := jars[0]
	jarVersion := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(mainJar), "gradle-hello-"), ".jar")

	// 2. analyzed-artifact SBOM via syft on the produced jar.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "gradle",
		"--layers", "analyzed-artifact",
		"--name", "gradle-hello", "--version", jarVersion); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	for _, suffix := range []string{".spdx.json", ".cyclonedx.json"} {
		path := filepath.Join(proj, "gradle-hello-"+jarVersion+"-analyzed-jar-sbom"+suffix)
		if !fileExists(path) {
			t.Fatalf("step 2 missing SBOM at %s", path)
		}
	}

	// 3. checksums + 4. sign. Use the jar's actual relative path so
	// sha256sum --check round-trips.
	relJar, _ := filepath.Rel(proj, mainJar)

	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", relJar,
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	body := readFile(t, filepath.Join(proj, "checksums.sha256"))
	if !strings.Contains(body, filepath.Base(mainJar)) {
		t.Errorf("step 3 manifest missing jar; got:\n%s", body)
	}

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	},
		"release", "sign",
		"--attach-artifacts", relJar); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. sha256sum --check
	cmd := exec.Command("sha256sum", "--check", "checksums.sha256")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. gpg --verify on the jar + manifest signatures.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: filepath.Base(mainJar) + ".asc", subj: relJar},
	} {
		ascPath := filepath.Join(proj, pair.asc)
		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := exec.Command("gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))
		verify.Env = append(os.Environ(), "GNUPGHOME="+key.gnupgHome)

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtefactFirst_GoBinary runs the artefact-first Go cascade:
// cross-compile platform-specific binaries, SBOM each one, checksum,
// sign, verify. This is the path used by Go CLI releases where the
// binary is the deliverable (not wrapped in a container).
//
// Distinct from container-first Go (covered by TestFlow_ContainerFirst_Go)
// which compiles inside the Containerfile.
func TestFlow_ArtefactFirst_GoBinary(t *testing.T) {
	requireTool(t, "go")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("go-hello"))

	// 1. build go compile → dist/<goos>-<goarch>/<binary>-<goos>-<goarch>
	//    Single-platform to keep the test fast; the multi-platform
	//    matrix is exercised by go_test.go's reproducibility cascade.
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "go", "compile",
		"--version", "v0.1.0",
		"--platforms", "linux/amd64"); code != 0 {
		t.Fatalf("step 1 go compile exit %d\nstderr: %s", code, stderr)
	}

	binary := filepath.Join(proj, "dist", "linux-amd64", "go-hello-linux-amd64")
	if !fileExists(binary) {
		t.Fatalf("step 1 missing compiled binary at %s", binary)
	}

	// 2. analyzed-artifact SBOM via syft on the binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "go",
		"--layers", "analyzed-artifact",
		"--name", "go-hello", "--version", "0.1.0"); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	// 3. checksums covering the binary + 4. sign.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "dist/linux-amd64/go-hello-linux-amd64",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	body := readFile(t, filepath.Join(proj, "checksums.sha256"))
	if !strings.Contains(body, "go-hello-linux-amd64") {
		t.Errorf("step 3 manifest missing binary; got:\n%s", body)
	}

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	},
		"release", "sign",
		"--attach-artifacts", "dist/linux-amd64/go-hello-linux-amd64"); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. sha256sum --check
	cmd := exec.Command("sha256sum", "--check", "checksums.sha256")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. gpg --verify on the binary's signature + the manifest signature.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "go-hello-linux-amd64.asc", subj: "dist/linux-amd64/go-hello-linux-amd64"},
	} {
		ascPath := filepath.Join(proj, pair.asc)
		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := exec.Command("gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))
		verify.Env = append(os.Environ(), "GNUPGHOME="+key.gnupgHome)

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtefactFirst_CargoBinary mirrors the Go-binary cascade for
// Cargo: cross-compile, SBOM, checksum, sign, verify. The dist/ layout
// matches Go intentionally so downstream packaging works uniformly.
//
// Linux/amd64 only — multi-platform cross-compile needs `rustup target
// add` and a matching cross-linker baked into the runtime image, which
// is exercised in CI not in the local testsuite.
func TestFlow_ArtefactFirst_CargoBinary(t *testing.T) {
	requireTool(t, "cargo")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("cargo-hello"))

	// 1. build cargo compile → dist/<goos>-<goarch>/<binary>-<goos>-<goarch>
	if _, stderr, code := run(t, runOpts{dir: proj},
		"build", "cargo", "compile",
		"--version", "v0.3.1",
		"--platforms", "linux/amd64"); code != 0 {
		t.Fatalf("step 1 cargo compile exit %d\nstderr: %s", code, stderr)
	}

	binary := filepath.Join(proj, "dist", "linux-amd64", "cargo-hello-linux-amd64")
	if !fileExists(binary) {
		t.Fatalf("step 1 missing compiled binary at %s", binary)
	}

	// 2. analyzed-artifact SBOM via syft on the binary.
	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "cargo",
		"--layers", "analyzed-artifact",
		"--name", "cargo-hello", "--version", "0.3.1"); code != 0 {
		t.Fatalf("step 2 sbom exit %d", code)
	}

	// 3. checksums covering the binary + 4. sign.
	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "dist/linux-amd64/cargo-hello-linux-amd64",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("step 3 checksums exit %d", code)
	}

	body := readFile(t, filepath.Join(proj, "checksums.sha256"))
	if !strings.Contains(body, "cargo-hello-linux-amd64") {
		t.Errorf("step 3 manifest missing binary; got:\n%s", body)
	}

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	},
		"release", "sign",
		"--attach-artifacts", "dist/linux-amd64/cargo-hello-linux-amd64"); code != 0 {
		t.Fatalf("step 4 sign exit %d\nstderr: %s", code, stderr)
	}

	// 5. sha256sum --check
	cmd := exec.Command("sha256sum", "--check", "checksums.sha256")
	cmd.Dir = proj

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("step 5 sha256sum --check: %v\n%s", err, out)
	}

	// 6. gpg --verify on the binary's signature + the manifest signature.
	for _, pair := range []struct{ asc, subj string }{
		{asc: "checksums.sha256.asc", subj: "checksums.sha256"},
		{asc: "cargo-hello-linux-amd64.asc", subj: "dist/linux-amd64/cargo-hello-linux-amd64"},
	} {
		ascPath := filepath.Join(proj, pair.asc)
		if !fileExists(ascPath) {
			t.Errorf("step 6 missing signature %s", pair.asc)

			continue
		}

		verify := exec.Command("gpg", "--verify", ascPath, filepath.Join(proj, pair.subj))
		verify.Env = append(os.Environ(), "GNUPGHOME="+key.gnupgHome)

		if out, err := verify.CombinedOutput(); err != nil {
			t.Errorf("step 6 gpg --verify %s: %v\n%s", pair.asc, err, out)
		}
	}
}

// TestFlow_ArtefactFirst_NPMLib runs the NPM publish-shape cascade:
// pack the package into a tarball, generate the analyzed-artifact
// SBOM over it, checksum, sign, verify.
func TestFlow_ArtefactFirst_NPMLib(t *testing.T) {
	requireTool(t, "npm")
	requireTool(t, "syft")
	requireTool(t, "sha256sum")
	requireTool(t, "gpg")

	key := bootstrapGPGKey(t)
	priv, err := os.ReadFile(key.privateASC)

	if err != nil {
		t.Fatal(err)
	}

	proj := copyTree(t, fixture("npm-hello"))

	if _, _, code := run(t, runOpts{dir: proj}, "build", "npm", "pack"); code != 0 {
		t.Fatalf("npm pack exit %d", code)
	}

	tgz, _ := filepath.Glob(filepath.Join(proj, "*.tgz"))
	if len(tgz) != 1 {
		t.Fatalf("expected one tarball, got %v", tgz)
	}

	if _, _, code := run(t, runOpts{dir: proj},
		"sbom", "generate", "all",
		"--project-type", "npm",
		"--layers", "analyzed-artifact",
		"--name", "npm-hello", "--version", "0.1.0"); code != 0 {
		t.Fatalf("sbom exit %d", code)
	}

	if _, _, code := run(t, runOpts{dir: proj},
		"release", "checksums",
		"--attach-artifacts", "*.tgz",
		"--sbom-dir", "."); code != 0 {
		t.Fatalf("checksums exit %d", code)
	}

	body := readFile(t, filepath.Join(proj, "checksums.sha256"))
	if !strings.Contains(body, ".tgz") {
		t.Errorf("checksums missing .tgz; got:\n%s", body)
	}

	if _, stderr, code := run(t, runOpts{
		dir: proj,
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
		},
	}, "release", "sign", "--attach-artifacts", "*.tgz"); code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	// Tarball signature lands as <tarball>.asc in cwd.
	asc := filepath.Base(tgz[0]) + ".asc"
	if !fileExists(filepath.Join(proj, asc)) {
		t.Errorf("missing tarball signature %s", asc)
	}
}
