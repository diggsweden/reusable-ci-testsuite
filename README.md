<!--
SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
SPDX-License-Identifier: CC0-1.0
-->

# reusable-ci-testsuite

Companion integration testsuite for `diggsweden/reusable-ci`. Drives the
real CLI binary against per-ecosystem fixtures and asserts the
externally-observable behaviour (files produced, exit codes, JSON
schemas, signatures verifiable by `sha256sum --check` / `gpg --verify`).

## Why it exists

The Go unit tests inside `reusable-ci/internal/...` cover internal
contracts (parsers, planners, error classifications). They cannot
catch:

- Failures that only surface when the **real** toolchain runs (`syft`,
  `cyclonedx-gomod`, `cyclonedx-gradle-plugin`, `cargo-cyclonedx`,
  `gpg`, `git`).
- Reproducibility — same input ⇒ byte-identical output across runs.
- Cross-ecosystem consistency — does `--json` emit a deterministic
  schema for both Go and Maven?
- Host-isolation — does a developer's `~/.gitconfig` (e.g.
  `gpg.format=ssh`) accidentally change a test's outcome?

This testsuite drives the binary as a black box and checks the artefact
outputs.

## Layout

```
.
├── README.md                       ← this file
├── go.mod                          ← module declaration for the test runner
├── go-hello/                       ← realistic Go project (cobra dep, ldflag injection)
├── npm-hello/                      ← scoped npm package (library shape: no build script)
├── npm-app/                        ← npm package with a build script that writes dist/
├── maven-hello/                    ← single-module Maven (application + sources)
├── maven-lib/                      ← library shape: sources + javadoc attached
├── maven-multi/                    ← parent POM + 2 child modules (core, api)
├── gradle-hello/                   ← Gradle 9 wrapper + build.gradle + Containerfile
├── gradle-android-hello/           ← gradle.properties with versionName/versionCode
├── cargo-hello/                    ← single-crate Cargo + Containerfile (container-first)
├── cargo-workspace/                ← resolver=2 workspace with 3 crates (common/cli/server)
├── go-hello/                       ← Go module + Containerfile (container-first)
├── python-hello/                   ← pyproject.toml (PEP 621)
├── monorepo-app/                   ← polyglot monorepo (Go service + NPM package)
└── tests/integration/              ← Go integration package (build tag: integration)
    ├── main_test.go                ← TestMain builds the binary once per package
    ├── helpers_test.go             ← run()/isolatedEnv()/copyTree()/fixture helpers
    ├── keys_test.go                ← throwaway GPG/SSH key bootstrappers + initGitRepo
    ├── go_test.go                  ← reproducible builds + Go-layer SBOMs
    ├── gradle_test.go              ← cyclonedx-gradle-plugin v1.x AND v2.x
    ├── maven_test.go               ← single + multi-module POM metadata
    ├── cargo_test.go               ← single-crate and workspace SBOMs
    ├── npm_test.go                 ← NPM-specific (analyzed-artifact via npm pack + syft)
    ├── sbom_matrix_test.go         ← build + analyzed-artifact for every ecosystem (table-driven)
    ├── sbom_zip_test.go            ← `release sbom-zip` bundling (+ signed variant)
    ├── reproducibility_test.go     ← bit-identical rebuild matrix (Maven/Gradle/Cargo/Go + NPM + OCI image)
    ├── release_signing_test.go     ← checksums round-trip + GPG-sign of release artefacts
    ├── cosign_signing_test.go      ← `release sign --method=kms` round-trip, flag validation matrix, sidecar auto-detect
    ├── signing_tags_test.go        ← `validate tag signature` for GPG and SSH tags
    ├── swap_refusal_test.go        ← `release sign` refuses to run when /proc/swaps shows active swap
    ├── version_bump_matrix_test.go ← bump matrix + idempotence + edge cases
    ├── jvm_reproducibility_test.go ← `validate jvm-reproducibility` happy + missing-knob paths
    ├── build_type_test.go          ← application vs library distinction (Maven, NPM, Gradle)
    ├── flow_artefact_first_test.go ← end-to-end cascade for artefact-first ecosystems
    ├── flow_container_first_test.go← end-to-end cascade for container-first ecosystems (buildah)
    ├── changelog_test.go           ← changelog validation + release-notes assembly
    ├── config_location_test.go     ← `.reusable-ci/artifacts.yml` discovery + auto-derive path
    ├── workflow_upload_paths_test.go ← artefact-upload glob narrowness (no `**` over-fetches)
    ├── security_test.go            ← redacted subprocess output, no-key-on-argv, secret-in-tmp policies
    ├── release_authorization_test.go ← `.reusable-ci/allowed_signers` / `allowed_gpg_fingerprints` enforcement
    └── exit_codes_test.go          ← public exit-code contract (sysexits.h)
```

## What's tested where

| Concern | Test location |
|---|---|
| Per-ecosystem build + SBOM behaviour against real toolchains | testsuite (this repo) |
| Reproducibility of binary + container outputs | testsuite (`reproducibility_test.go`) |
| `release sign --method=gpg` round-trip | testsuite (`release_signing_test.go`) |
| `release sign --method=kms` + `validate artifact-signature` round-trip | testsuite (`cosign_signing_test.go`) |
| `release sign --method=sigstore` (keyless via OIDC) | **not here** — needs live Fulcio + Rekor; argv pinning is unit-tested in `reusable-ci/internal/adapters/cosign` |
| `container sign` / `validate container-signature` | **not here** — needs a real OCI registry; argv pinning is unit-tested in `reusable-ci/internal/adapters/cosign` |
| `reusable-ci doctor` setup-check command | parent repo (`reusable-ci/cmd/reusable-ci/e2e_test.go`) |
| Workflow-input-contract (caller `with:` keys match callee `inputs:`) | parent repo (`reusable-ci/internal/cli/workflowcontract_test.go`) |
| YAML schema for `artifacts.yml` (including the `sign:` block) | parent repo (`reusable-ci/internal/app/config/schema_test.go`) |
| install-reusable-ci.sh cosign-verify behaviour | parent repo (`reusable-ci/scripts/bootstrap/install-reusable-ci_test.sh`) |
| Release authorization (allowed_signers / allowed_gpg_fingerprints) | testsuite (`release_authorization_test.go`) |
| Sigstore-keyless + container signing in CI | exercised by the parent repo's own self-release flow on every tag |

## Running

You need:

- Go ≥ 1.26 — to run `go test` itself.
- A checkout of `diggsweden/reusable-ci` as a **sibling directory** (the
  test suite builds the CLI binary from there).
- Optional toolchains: `mvn`, `npm`, `cargo`, `buildah`, `gpg`,
  `syft`, `cyclonedx-gomod`, `cargo-cyclonedx`. Anything missing makes
  the tests that need it `--- SKIP`; the rest still run.

```bash
# Run the whole suite. First time takes ~65s; later runs reuse caches.
go test -tags=integration ./tests/integration/...

# Run one test (or one pattern):
go test -tags=integration -run TestFlow_ContainerFirst_Go -v ./tests/integration/

# See PASS/SKIP/FAIL lines as they happen:
go test -tags=integration -v ./tests/integration/...
```

The `//go:build integration` tag is the opt-in switch. Without
`-tags=integration`, `go test ./...` ignores this package — so it
won't run by accident if you're testing reusable-ci itself.

### Common gotchas

- **"package diggsweden/reusable-ci/cmd/reusable-ci not found"** —
  the sibling `reusable-ci/` directory is missing. Clone it next to
  this repo, or set `REUSABLE_CI=/path/to/reusable-ci-binary` to
  point at a pre-built binary instead.
- **Loads of `--- SKIP`** — that's expected unless you've got the full
  toolchain installed. Each test's `requireTool(t, "...")` call says
  which tool was missing.
- **"buildah build failed"** in the cargo container-first test — the
  rust base image isn't in your local container cache. Run
  `buildah pull docker.io/library/rust:1-slim` once and re-try.

## Host isolation

`helpers_test.go::isolatedEnv` wipes the developer's environment for
every binary invocation, then layers the per-test overrides on top:

- `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_SYSTEM=/dev/null` — the
  developer's `~/.gitconfig` (e.g. `gpg.format=ssh`) is never read,
  which would otherwise silently break GPG tests.
- `HOME` is kept (so tool caches still resolve) but `LANG=C`,
  `LC_ALL=C` to keep human output deterministic.
- `PATH` is augmented with every directory reported by `mise
  bin-paths`, so toolchains installed via mise (node, java,
  cargo, …) work even when `mise activate` hasn't run in the
  calling shell. The host's PATH still takes precedence.
- A stale `JAVA_HOME` (common after a mise JDK update where the
  shell still points at an old install dir) is detected and
  dropped, so `mvn` falls back to the `java` on PATH.
- `GIT_AUTHOR_*` / `GIT_COMMITTER_*` are pinned to a stable identity.
- Per-test scratch dirs come from `t.TempDir()`, removed automatically
  at end of test by Go's testing framework.
- For GPG tests, `bootstrapGPGKey` creates a throwaway RSA-2048 key in
  an isolated `GNUPGHOME` with ultimate ownertrust so signing succeeds
  without prompts.
- For SSH tests, `bootstrapSSHKey` generates a fresh ed25519 keypair
  plus an `allowed_signers` file.

## What each test covers

| File | Tests | What they assert |
|---|---|---|
| `go_test.go` | `TestGoBuildReproducible` | Two `build go compile` runs with the same `SOURCE_DATE_EPOCH` + `--commit` produce byte-identical binaries. A different `SOURCE_DATE_EPOCH` changes the SHA — proving the date is actually baked in. |
| | `TestGoBuildMultiPlatformReproducible` | Repeats the reproducibility assertion for linux/amd64, darwin/arm64, windows/amd64. |
| | `TestGoBuildSBOMCISABuildLayer` | `build go sbom` writes a valid CycloneDX `bom.json` under `.reusable-ci/go-build-sbom/<name>/` with components derived from `go.mod`. |
| | `TestGoSBOMAnalyzedArtifact` | `sbom generate all --layers analyzed-artifact` runs `syft` against the compiled Go binary and produces BOTH SPDX 2.3 and CycloneDX 1.6 SBOMs with valid headers and ≥1 component. |
| `gradle_test.go` | `TestGradleSBOMv1AndV2` | `build gradle sbom` works for BOTH cyclonedx-gradle-plugin v1.x and v2.x. The init-script uses the stable `CycloneDxPlugin` class + real artifact coordinate (regression for the marker-vs-real-artifact and `CyclonedxPlugin`-vs-`CycloneDxPlugin` bugs). |
| `maven_test.go` | `TestMavenMetadataSingleModule` | `build maven metadata` reads `pom.xml` directly (no `mvn` subprocess) and emits typed JSON outputs for a single-module project. |
| | `TestMavenMetadataMultiModule` | Same, for a multi-module submodule inheriting `<version>` from `<parent>`. |
| `cargo_test.go` | `TestCargoSBOMSingleCrate` | `cargo-cyclonedx` generates a per-crate `bom.xml` for a single crate. |
| | `TestCargoSBOMWorkspace` | Same, for a resolver=2 workspace with 3 member crates. |
| `npm_test.go` | `TestSBOMNPMAnalyzedArtifact` | NPM analyzed-artifact: `npm pack` produces a tarball, syft scans it, SPDX+CycloneDX land in cwd. Skips when `npm` is not on PATH. |
| `sbom_zip_test.go` | `TestSBOMZipBundlesLayers` | `release sbom-zip` discovers `*-sbom.{spdx,cyclonedx}.json` in the working dir AND analyzed-container SBOMs under `--sbom-dir`, bundles them with the correct flat-name layout into `<project>-<version>-sboms.zip`. |
| | `TestSBOMZipSignedWithGPG` | The `--sign` path produces a verifiable `.asc` detached signature alongside the zip. |
| `release_signing_test.go` | `TestChecksumsRoundTrip` | `release checksums` writes a manifest that (a) does NOT include itself (regression for the e3b0c44 self-poison bug) and (b) round-trips through the standard `sha256sum --check` verifier. |
| | `TestReleaseSignGPG` | `release sign` of a `.tgz` artefact produces a `.asc` that `gpg --verify` accepts. |
| | `TestReleaseSignWarnsOnEmptyMatch` | Verifies the "no files in …" warning fires when every artefact fails the extension filter (regression for the silent-no-op bug). |
| `signing_tags_test.go` | `TestGPGSignedTagVerification` | `validate tag signature` accepts a real GPG-signed annotated tag. |
| | `TestGPGSignedTagRejectsLightweight` | Lightweight (unsigned, non-annotated) tag is rejected with a non-zero exit. |
| | `TestSSHSignedTagVerification` | `validate tag signature` accepts an SSH-signed annotated tag (`gpg.format=ssh` path). Host-independent — would otherwise be broken by a global `gpg.format=ssh` leaking into the GPG test. |
| `build_type_test.go` | `TestBuildType_MavenApplication` | `build maven application` produces the main jar from the maven-hello fixture. |
| | `TestBuildType_MavenLibrary` | `build maven library` produces main + sources + javadoc jars from the maven-lib fixture (maven-source-plugin + maven-javadoc-plugin attached, both honour `outputTimestamp`). |
| | `TestBuildType_NPMApplication` | `build npm application` runs the package.json `build` script. The npm-app fixture's script writes `dist/main.js` — the test asserts the side-effect. |
| | `TestBuildType_NPMApplicationNoScriptIsNoop` | When the package has no `build` script (npm-hello), the subcommand exits 0 with an explanatory message and does NOT create `dist/`. |
| | `TestBuildType_NPMPack` | `build npm pack` produces the canonical scoped tarball `diggsweden-npm-hello-<version>.tgz`. |
| | `TestBuildType_GradleApplication` | `build gradle application --tasks=build` runs the wrapper and produces at least one jar in `build/libs/`. |
| | `TestBuildType_GradleLibraryTasks` | `build gradle application --tasks="jar sourcesJar javadocJar"` plus `java { withSourcesJar(); withJavadocJar() }` produces all three library jars. |
| `flow_artefact_first_test.go` | `TestFlow_ArtefactFirst_MavenApp` | End-to-end cascade for Maven application: build → analyzed-artifact SBOM → checksums → sign → `sha256sum --check` + `gpg --verify`. Catches contract drift between adjacent steps. |
| | `TestFlow_ArtefactFirst_MavenLib` | Same cascade for Maven library shape: checksums covers main+sources+javadoc jars AND their analyzed SBOMs; each jar gets its own signature. |
| | `TestFlow_ArtefactFirst_Gradle` | Same cascade for Gradle JVM: `gradle build` → jar in `build/libs/` → analyzed-artifact SBOM → checksums → sign → verify. |
| | `TestFlow_ArtefactFirst_GoBinary` | Artifact-first Go cascade: cross-compile → `dist/<goos>-<goarch>/<binary>-<goos>-<goarch>` → analyzed-binary SBOM → checksums → sign → verify. Distinct from container-first Go in `flow_container_first_test.go`. |
| | `TestFlow_ArtefactFirst_CargoBinary` | Artifact-first Cargo cascade mirroring the Go one: `cargo build --release --target …` → same `dist/` shape → analyzed-binary SBOM → checksums → sign → verify. Distinct from container-first Cargo in `flow_container_first_test.go`. |
| | `TestFlow_ArtefactFirst_NPMLib` | NPM publish-shape cascade: `npm pack` → analyzed-artifact SBOM → checksums via `--attach-artifacts *.tgz` → sign → verify. |
| `flow_container_first_test.go` | `TestFlow_ContainerFirst_Cargo` | Full cascade with real buildah: cargo-cyclonedx (lockfile build SBOM) → `buildah build --timestamp <epoch> --target=export-binary` → analyzed-binary SBOM → checksums → sign → verify. Skips when the rust base image isn't cached locally. |
| | `TestFlow_ContainerFirst_Go` | Equivalent cascade for Go using host `go build` (TestReproducibleContainerImage already exercises buildah end-to-end, so the cost of running it twice isn't justified). |
| `jvm_reproducibility_test.go` | `TestValidateJVMReproducibility_MavenPasses` | The validator emits no warnings when the POM sets `<project.build.outputTimestamp>`. |
| | `TestValidateJVMReproducibility_GradlePasses` | Same, when the build.gradle sets `preserveFileTimestamps=false` + `reproducibleFileOrder=true`. |
| | `TestValidateJVMReproducibility_MissingTimestampFails` | A POM missing the property triggers a `::error::` annotation + actionable fix snippet, and the validator exits non-zero. Reproducibility is foundational to reusable-ci's deterministic-pipeline contract — non-reproducible JVM artefacts cannot pass `validate prerequisites`. |
| `changelog_test.go` | `TestChangelogValidatePresent` | `validate changelog --required` accepts an existing file. |
| | `TestChangelogValidateMissingFails` | `validate changelog --required` on a missing file exits 66 (`EX_NOINPUT`). |
| | `TestChangelogValidateMinimalModeAbsent` | Without `--required` a missing file is tolerated (exit 0). |
| | `TestReleaseNotesFromChangelog` | `release notes` reads a git-cliff-style source file and writes it to the target file. |
| | `TestReleaseNotesFallbackOnMissingChangelog` | `release notes` produces a fallback target file (with the version in the body) when the source is absent. |
| `exit_codes_test.go` | `TestExitCodeMatrix` | Exit-code contract: 2 (`EX_USAGE`) for unknown flag / subcommand / unknown project type, 1 (`EX_VALIDATION`) for invalid tag, 0 for valid tag. |
| `sbom_matrix_test.go` | `TestSBOMBuildLayerAllEcosystems` | The Build-layer CISA SBOM for **every** ecosystem (maven, npm, gradle, cargo, go): stubs the upstream tool's `bom.json` at the expected location and asserts reusable-ci promotes it to the canonical `<name>-<version>-build-sbom.cyclonedx.json`. CycloneDX header re-validated post-promotion. |
| | `TestSBOMAnalyzedArtifactAllEcosystems` | The analyzed-artifact CISA SBOM for every ecosystem with a binary artefact (maven jar, gradle jar, cargo binary): materialises a minimal valid artefact, runs syft via the wrapper, and asserts BOTH SPDX 2.3 and CycloneDX 1.6 files land in the working dir with correct headers. |
| | `TestSBOMBuildLayerMissingBOMFails` | When no `bom.json` source is present, `sbom generate all --layers=build` exits non-zero — regression for the "silently produce nothing" mode. |
| `version_bump_matrix_test.go` | `TestVersionBumpMatrix` | Full happy-path coverage for every supported project type: maven (single + multi-module), npm, gradle (jvm + android), cargo (single + workspace), xcode-ios, go (no-op), meta (no-op). Subtests using mvn/npm skip when the toolchain is missing. |
| | `TestVersionBumpIdempotence` | Bumping to the SAME version twice must be a clean no-op (file unchanged). Excludes `gradle-android` (versionCode monotonic-increment is required by the Play Store). |
| | `TestVersionBumpEdgeCases` | Error-path matrix: missing manifest → non-zero (logs the EX_NOINPUT-vs-EX_SOFTWARE gap), missing required flag → 2, unknown project type → 2, malformed Cargo.toml → non-zero. Records the "leading-v in --version is silently accepted" gap as informational until a validator lands. |
| `reproducibility_test.go` | `TestReproducibleMaven` | Two `mvn package` runs of `maven-hello` produce byte-identical **main jar AND sources jar**. The fixture POM sets `<project.build.outputTimestamp>` and attaches `maven-source-plugin` — without those, manifest entries carry wall-clock mtimes and either assertion would fail. |
| | `TestReproducibleGradle` | Two `./gradlew jar distZip distTar` runs of `gradle-hello` produce byte-identical artefacts across all three archive types. The fixture sets `preserveFileTimestamps=false` and `reproducibleFileOrder=true` on `AbstractArchiveTask` (covers `jar`, `war`, `distZip`, `distTar`, …). |
| | `TestReproducibleCargo` | Two `cargo build --release` runs of `cargo-hello` produce byte-identical binaries. Stock cargo + a fixed toolchain + lockfile is sufficient. |
| | `TestReproducibleCargoCrate` | Two `cargo package` runs of `cargo-hello` produce byte-identical `.crate` source archives — the unit Cargo uploads to crates.io. |
| | `TestReproducibleContainerImage` | Two `buildah build --timestamp <epoch>` runs of an identical Containerfile produce the **same OCI image config digest** (= the canonical "image ID" registries report). The OCI archive *file* will differ run-to-run because the tar wrapper embeds filesystem metadata around the immutable layer blobs — but the layer + config digests are stable. |
| | `TestReproducibleNPM` | Two `npm pack` runs produce byte-identical tarballs. Historically broken (npm/cli#3536); fixed in npm ≥ 10. Test guards against an upstream regression. |
| | `TestReproducibleSourceDateEpochChangesOutput` | The "negative" axis of reproducibility: a different `SOURCE_DATE_EPOCH` MUST change the Go binary SHA. Guards against "accidentally reproducible because the date isn't actually baked in." |

## Adding a new test

1. Add a new `Test*` function to the existing topic file, or create a
   new `<topic>_test.go` with the `//go:build integration` tag.
2. Use `run()` for the binary invocation, `copyTree(t, fixture("…"))`
   for per-test fixture isolation, and `requireTool(t, "name")` to
   `t.Skip` when an optional toolchain is absent.
3. Open the doc comment with: which flow you cover, what inputs you
   build, what you assert.
4. Update the table above.

Useful helpers (all in `helpers_test.go` / `keys_test.go`):

- `run(t, runOpts{dir, env}, args...)` — invoke the binary in an
  isolated environment.
- `fixture("go-hello")` — resolve a path under the testsuite root.
- `copyTree(t, src)` — clone a fixture into `t.TempDir()` preserving
  exec bits.
- `bootstrapGPGKey(t)` / `bootstrapSSHKey(t)` — throwaway signing keys.
- `initGitRepo(t, env, configure)` — fresh repo with host-isolated git
  config.
- `requireTool(t, "syft")` — skip when the tool is unavailable.

## CI

This testsuite runs as the **integration tier** above `reusable-ci`'s
own `go test ./...`. It catches regressions that only surface against
real toolchains (`syft`, `cyclonedx-gomod`, `cargo-cyclonedx`, `gpg`,
`gradle/java`, `mvn`, `cargo`) — exactly what unit tests can't.

The pipeline lives in `.github/workflows/integration.yml`. Trigger surface:

| Trigger | reusable-ci ref tested | Purpose |
|---|---|---|
| `workflow_dispatch` (manual) | `reusable-ci-ref` input — empty = latest release | Ad-hoc validation; run anytime against any tag/branch/SHA |
| `push` to `main` | Latest reusable-ci release | Catch testsuite-side regressions |
| `pull_request` to `main` | Latest reusable-ci release | Pre-merge gate for testsuite changes |
| `schedule` (04:00 UTC daily) | Latest reusable-ci release | Catch regressions in reusable-ci itself that landed since the last push |

### How do we know about new reusable-ci releases?

Three layers, in order from most-immediate to fallback:

1. **Manual dispatch.** When `diggsweden/reusable-ci` cuts a release,
   maintainers can immediately validate it by opening the Actions tab,
   selecting *Integration Tests*, clicking *Run workflow*, and pasting
   the new tag (e.g. `v3.1.0`) into the `reusable-ci-ref` input.
2. **Nightly schedule.** The 04:00 UTC cron job calls the
   `/repos/diggsweden/reusable-ci/releases/latest` endpoint and runs
   against whatever tag it returns. So worst-case latency from a new
   release to "we know if the testsuite passes against it" is ~24h.
3. **Future:** when reusable-ci's release-orchestrator gains a
   `repository_dispatch` step, it can immediately trigger this workflow
   on tag publish. Tracked as a roadmap item; the schedule above covers
   it until then.

### What the workflow actually does

```text
1. step-security/harden-runner       (egress audit)
2. checkout testsuite                (this repo)
3. resolve reusable-ci ref           (manual input OR /releases/latest)
4. checkout diggsweden/reusable-ci   (sibling directory, the way
                                      TestMain expects)
5. setup-go from testsuite's go.mod  (Go 1.26)
6. go vet -tags=integration          (catches typos before the slow path)
7. go test -tags=integration ...     (the testsuite — TestMain builds
                                      the binary from the sibling
                                      checkout, then runs every Test*)
8. job summary                       (which ref, which trigger, SHA)
```

Optional toolchains (mvn, cargo, npm, buildah, syft) are not installed
in this job — tests that need them `requireTool`-skip cleanly. That's
deliberate for the start-simple version: the core surface
(host-isolation, signing, planner, reproducibility, SBOM-discovery,
exit-codes) runs on a bare runner, and ecosystem-specific tests can
move into a per-language matrix job later if the skip rate becomes
inconvenient.

### Running it locally first

If you want to reproduce what the CI does on your laptop:

```bash
# Same as the workflow's last step
cd reusable-ci-testsuite
go test -tags=integration -count=1 ./tests/integration/...
```

The CI runner uses a vanilla `ubuntu-24.04` image — install whatever
optional toolchains you want locally to take coverage past what CI
exercises today.
