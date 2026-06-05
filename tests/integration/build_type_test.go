// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Tests the build-type distinction at the artefact-shape level:
// `build maven application` vs `build maven library`, `build npm
// application` vs `build npm pack`, and Gradle's task-driven library
// vs application convention.
//
// Cascade-level tests (build → SBOM → checksums → sign) live in
// flow_artefact_first_test.go; this file only verifies what each
// build subcommand produces, in isolation.

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildType_MavenApplication verifies `build maven application`
// produces the main jar. The subcommand's contract is "run `mvn
// clean package` plus optional -DskipTests" — it does not inhibit
// any plugins the POM declares. If the POM attaches the source
// plugin (as maven-hello's does for reproducibility coverage), the
// build naturally produces a sources jar too. The test asserts what
// the subcommand REQUIRES (the main jar exists), not what the
// caller's POM happens to add.
//
// For "no sources/javadoc attached" behaviour, use a POM that
// doesn't declare the corresponding plugins — that's a POM design
// choice, not a CLI behaviour we own.
func TestBuildType_MavenApplication(t *testing.T) {
	requireTool(t, "mvn")

	proj := copyTree(t, fixture("maven-hello"))

	_, stderr, code := run(t, runOpts{dir: proj},
		"build", "maven", "application", "--cli-opts", "-B -ntp", "--skip-tests")
	if code != 0 {
		t.Fatalf("build maven application exit %d\nstderr: %s", code, stderr)
	}

	main := filepath.Join(proj, "target", "maven-hello-1.0.0.jar")
	if !fileExists(main) {
		t.Errorf("expected main jar at %s", main)
	}
}

// TestBuildType_MavenLibrary verifies `build maven library` against
// the library-shaped fixture (maven-lib). Expected shape: main jar
// PLUS -sources.jar PLUS -javadoc.jar in target/.
//
// Heavier than the application test (javadoc generation is ~5s),
// so it's gated on mvn being available.
func TestBuildType_MavenLibrary(t *testing.T) {
	requireTool(t, "mvn")

	proj := copyTree(t, fixture("maven-lib"))

	_, stderr, code := run(t, runOpts{dir: proj},
		"build", "maven", "library", "--cli-opts", "-B -ntp", "--skip-tests")
	if code != 0 {
		t.Fatalf("build maven library exit %d\nstderr: %s", code, stderr)
	}

	for _, suffix := range []string{".jar", "-sources.jar", "-javadoc.jar"} {
		matches, _ := filepath.Glob(filepath.Join(proj, "target", "maven-lib-1.0.0"+suffix))
		if len(matches) != 1 {
			t.Errorf("library build missing maven-lib-1.0.0%s; glob: %v", suffix, matches)
		}
	}
}

// TestBuildType_NPMApplication verifies `build npm application`
// runs the package.json "build" script when present. The npm-app
// fixture's build script writes dist/main.js as a side-effect.
func TestBuildType_NPMApplication(t *testing.T) {
	requireTool(t, "npm")

	proj := copyTree(t, fixture("npm-app"))

	_, stderr, code := run(t, runOpts{dir: proj}, "build", "npm", "application")
	if code != 0 {
		t.Fatalf("build npm application exit %d\nstderr: %s", code, stderr)
	}

	if !fileExists(filepath.Join(proj, "dist", "main.js")) {
		t.Errorf("expected dist/main.js (the build script's side-effect)")
	}
}

// TestBuildType_NPMApplicationNoScriptIsNoop verifies the documented
// no-op behaviour: when package.json has no "build" script,
// `build npm application` exits 0 with an informational message and
// does NOT create dist/. The npm-hello fixture is the "no build
// script" case.
func TestBuildType_NPMApplicationNoScriptIsNoop(t *testing.T) {
	requireTool(t, "npm")

	proj := copyTree(t, fixture("npm-hello"))

	stdout, stderr, code := run(t, runOpts{dir: proj}, "build", "npm", "application")
	if code != 0 {
		t.Fatalf("build npm application (no-script) exit %d\nstderr: %s", code, stderr)
	}

	if fileExists(filepath.Join(proj, "dist")) {
		t.Errorf("no-build-script case should not create dist/")
	}

	combined := stdout + stderr
	if !strings.Contains(combined, "No \"build\"") && !strings.Contains(combined, "skipping") && !strings.Contains(combined, "no-op") {
		// The exact wording is allowed to drift; what matters is
		// SOMETHING explains the no-op.
		t.Errorf("expected an explanatory message for the no-op case; got:\n%s", combined)
	}
}

// TestBuildType_NPMPack verifies `build npm pack` produces a
// publish-ready .tgz at the package.json's <name>-<version>.tgz
// shape — this is the canonical "library" output for NPM.
func TestBuildType_NPMPack(t *testing.T) {
	requireTool(t, "npm")

	proj := copyTree(t, fixture("npm-hello"))

	_, _, code := run(t, runOpts{dir: proj}, "build", "npm", "pack")
	if code != 0 {
		t.Fatalf("build npm pack exit %d", code)
	}

	matches, err := filepath.Glob(filepath.Join(proj, "*.tgz"))
	if err != nil {
		t.Fatal(err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected exactly one .tgz, got %d: %v", len(matches), matches)
	}

	// Scoped package shape: @diggsweden/npm-hello → diggsweden-npm-hello-0.1.0.tgz
	base := filepath.Base(matches[0])
	if !strings.HasPrefix(base, "diggsweden-npm-hello-") || !strings.HasSuffix(base, ".tgz") {
		t.Errorf("unexpected tarball name %q", base)
	}
}

// TestBuildType_GradleApplication verifies `build gradle
// application` runs the gradle wrapper with the supplied tasks and
// produces at least the library jar under build/libs/. The --tasks
// flag is required (no default); we pass "build" — the canonical
// application task — which transitively runs jar.
func TestBuildType_GradleApplication(t *testing.T) {
	requireTool(t, "java")

	proj := copyTree(t, fixture("gradle-hello"))

	_, stderr, code := run(t, runOpts{dir: proj},
		"build", "gradle", "application", "--tasks", "build", "--skip-tests")
	if code != 0 {
		t.Fatalf("build gradle application exit %d\nstderr: %s", code, stderr)
	}

	jars, _ := filepath.Glob(filepath.Join(proj, "build", "libs", "*.jar"))
	if len(jars) < 1 {
		t.Errorf("expected at least one jar in build/libs; got %v", jars)
	}
}

// TestBuildType_GradleLibraryTasks verifies the library convention:
// drive `build gradle application` with explicit
// `--tasks="jar sourcesJar javadocJar"` to produce all three lib
// jars. The gradle-hello build.gradle needs `java { withSourcesJar();
// withJavadocJar() }` for the tasks to register; we wire that up
// inline in the fixture (cheaper than a second gradle-lib fixture).
func TestBuildType_GradleLibraryTasks(t *testing.T) {
	requireTool(t, "java")

	proj := copyTree(t, fixture("gradle-hello"))

	// Augment the build.gradle with library-publishing convention.
	// Cheaper than a second fixture; future tests using gradle-hello
	// stay unaffected because copyTree gives us our own copy.
	body := readFile(t, filepath.Join(proj, "build.gradle"))

	augmented := body + "\njava {\n    withSourcesJar()\n    withJavadocJar()\n}\n"
	if err := os.WriteFile(filepath.Join(proj, "build.gradle"), []byte(augmented), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{dir: proj},
		"build", "gradle", "application",
		"--tasks", "jar sourcesJar javadocJar",
		"--skip-tests",
	)
	if code != 0 {
		t.Fatalf("build gradle application (lib tasks) exit %d\nstderr: %s", code, stderr)
	}

	// Assert presence of the three expected library jars by their
	// Gradle filename conventions: <name>-<ver>.jar (main),
	// <name>-<ver>-sources.jar, <name>-<ver>-javadoc.jar. Globbing
	// `*.jar` would over-match (it'd match -sources.jar too);
	// excluding sources/javadoc from the main check needs a
	// per-file existence test.
	libs := filepath.Join(proj, "build", "libs")

	main, _ := filepath.Glob(filepath.Join(libs, "gradle-hello-*.jar"))

	mainOnly := 0
	for _, p := range main {
		base := filepath.Base(p)
		if !strings.Contains(base, "-sources") && !strings.Contains(base, "-javadoc") {
			mainOnly++
		}
	}

	if mainOnly < 1 {
		t.Errorf("library tasks: no main jar produced; got %v", main)
	}

	for _, want := range []string{"sources", "javadoc"} {
		matches, _ := filepath.Glob(filepath.Join(libs, "*-"+want+".jar"))
		if len(matches) < 1 {
			t.Errorf("library tasks: no %s jar produced; glob: %v", want, matches)
		}
	}
}
