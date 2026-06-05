// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// End-to-end coverage for release authorisation: the project commits
// .reusable-ci/allowed_signers (SSH) or .reusable-ci/allowed_gpg_fingerprints
// (GPG); `reusable-ci validate tag signature --require-allowlisted-signer`
// then enforces that the tag's signing-key fingerprint appears in the
// relevant file. Denied releases exit with EX_NOPERM (77) — distinct
// from validation (1) and usage (2).
//
// Tag-signature happy-path coverage (signed = ok, no enforcement) lives
// in signing_tags_test.go; this file is exclusively about the allowlist
// gate.

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runValidateTagSignature is a small wrapper around the CLI call —
// every test in this file uses the same shape, so collapsing it cuts
// boilerplate without hiding behaviour.
func runValidateTagSignature(t *testing.T, dir, tag string, requireAllowlistedSigner bool, env map[string]string) (stdout, stderr string, exitCode int) {
	t.Helper()

	args := []string{"validate", "tag", "signature", "--tag", tag, "--repository", "diggsweden/integration"}
	if requireAllowlistedSigner {
		args = append([]string{"--format", "github"}, args...)
		env = mergeEnv(env, map[string]string{"REQUIRE_ALLOWLISTED_SIGNER": "true"})
	}

	return run(t, runOpts{dir: dir, env: env}, args...)
}

// mergeEnv overlays b on top of a (b wins on conflict). a may be nil.
func mergeEnv(base, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}

	for k, v := range overlay {
		out[k] = v
	}

	return out
}

// TestReleaseAuth_SSH_AllowedSignerPasses creates a repo with an
// allowed_signers file containing the signing key, signs a tag with
// that key, runs the validator with --require-allowlisted-signer, and
// asserts success.
func TestReleaseAuth_SSH_AllowedSignerPasses(t *testing.T) {
	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		writeAllowedSigners(t, repo, "integration@test.example", sshk)
		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, nil)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, ".reusable-ci/allowed_signers") {
		t.Errorf("output should cite the allowlist file; got:\n%s", stderr)
	}
}

// TestReleaseAuth_SSH_UnknownSignerDeniedWith77 mirrors the happy
// path but the allowed_signers file does NOT contain the signing key.
// Expected: exit 77 (EX_NOPERM) + "No principal matched" in output.
func TestReleaseAuth_SSH_UnknownSignerDeniedWith77(t *testing.T) {
	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		// Allowlist exists but lists a DIFFERENT signer key.
		if err := os.MkdirAll(filepath.Join(repo, ".reusable-ci"), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(
			filepath.Join(repo, ".reusable-ci", "allowed_signers"),
			[]byte("eve@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEVERMATCHEVERMATCHEVERMATCHEVERMATCH integration@test.example\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}

		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, nil)
	if code != 77 { //nolint:mnd // EX_NOPERM (sysexits.h §EX_NOPERM)
		t.Errorf("expected EX_NOPERM=77 for unknown signer, got %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "not in") && !strings.Contains(stderr, "No principal matched") {
		t.Errorf("output should explain the denial; got:\n%s", stderr)
	}
}

// TestReleaseAuth_SSH_MissingAllowlistFailsClosed checks the
// fail-closed behaviour: --require-allowlisted-signer + no
// .reusable-ci/allowed_signers → EX_NOPERM, not silent pass.
func TestReleaseAuth_SSH_MissingAllowlistFailsClosed(t *testing.T) {
	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	// No allowlist file is created.
	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, nil)
	if code != 77 { //nolint:mnd // EX_NOPERM
		t.Errorf("expected EX_NOPERM=77 when allowlist missing AND require=true; got %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "missing") && !strings.Contains(stderr, "allowed_signers") {
		t.Errorf("output should explain the missing allowlist; got:\n%s", stderr)
	}
}

// TestReleaseAuth_SSH_MissingAllowlistTolerated checks the
// opt-out path: --require-allowlisted-signer=false + no allowlist file
// → exit 0 (the project didn't opt in; we don't fail closed).
func TestReleaseAuth_SSH_MissingAllowlistTolerated(t *testing.T) {
	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		makeSSHSignedTag(t, runGit, repo, sshk, "v1.0.0")
	})

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", false, nil)
	if code != 0 {
		t.Errorf("expected exit 0 when require=false and no allowlist; got %d\nstderr: %s", code, stderr)
	}
}

// TestReleaseAuth_GPG_AllowedFingerprintPasses creates a GPG-signed
// tag, lists the signer's fingerprint in
// .reusable-ci/allowed_gpg_fingerprints, and asserts success.
func TestReleaseAuth_GPG_AllowedFingerprintPasses(t *testing.T) {
	requireTool(t, "gpg")
	requireTool(t, "git")

	key := bootstrapGPGKey(t)

	repo := initGitRepo(t, map[string]string{"GNUPGHOME": key.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		writeAllowedGPGFingerprints(t, repo, key.fingerprint)
		makeGPGSignedTag(t, runGit, repo, key, "v1.0.0")
	})

	pub, err := os.ReadFile(key.publicASC)
	if err != nil {
		t.Fatal(err)
	}

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, map[string]string{
		"GNUPGHOME":              key.gnupgHome,
		"RELEASE_GPG_PUBLIC_KEY": string(pub),
	})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, key.fingerprint) {
		t.Errorf("output should mention the signing fingerprint; got:\n%s", stderr)
	}
}

// TestReleaseAuth_GPG_UnknownFingerprintDeniedWith77 lists a DIFFERENT
// 40-char fingerprint in the allowlist; expected: exit 77.
func TestReleaseAuth_GPG_UnknownFingerprintDeniedWith77(t *testing.T) {
	requireTool(t, "gpg")
	requireTool(t, "git")

	key := bootstrapGPGKey(t)

	repo := initGitRepo(t, map[string]string{"GNUPGHOME": key.gnupgHome}, func(repo string, runGit func(args ...string) error) {
		// Allowlist contains an unrelated 40-char fingerprint.
		writeAllowedGPGFingerprints(t, repo, "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
		makeGPGSignedTag(t, runGit, repo, key, "v1.0.0")
	})

	pub, err := os.ReadFile(key.publicASC)
	if err != nil {
		t.Fatal(err)
	}

	_, stderr, code := runValidateTagSignature(t, repo, "v1.0.0", true, map[string]string{
		"GNUPGHOME":              key.gnupgHome,
		"RELEASE_GPG_PUBLIC_KEY": string(pub),
	})
	if code != 77 { //nolint:mnd // EX_NOPERM
		t.Errorf("expected EX_NOPERM=77 for unknown fingerprint, got %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "not in") {
		t.Errorf("output should explain the denial; got:\n%s", stderr)
	}
}

// writeAllowedSigners drops the SSH key's public material at
// .reusable-ci/allowed_signers in the canonical OpenSSH format.
func writeAllowedSigners(t *testing.T, repo, principal string, sshk sshKey) {
	t.Helper()

	pub, err := os.ReadFile(sshk.public)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(repo, ".reusable-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	line := principal + " " + strings.TrimSpace(string(pub)) + "\n"
	if err := os.WriteFile(filepath.Join(repo, ".reusable-ci", "allowed_signers"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeAllowedGPGFingerprints writes a single-fingerprint allowlist
// file (one of the most common shapes).
func writeAllowedGPGFingerprints(t *testing.T, repo, fingerprint string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(repo, ".reusable-ci"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, ".reusable-ci", "allowed_gpg_fingerprints"), []byte(fingerprint+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// makeSSHSignedTag configures git to sign with the bootstrapped SSH
// key, commits a placeholder file, and creates an annotated signed
// tag at HEAD.
func makeSSHSignedTag(t *testing.T, runGit func(args ...string) error, repo string, sshk sshKey, tag string) {
	t.Helper()

	mustGit(t, runGit, "config", "user.name", "Integration Test")
	mustGit(t, runGit, "config", "user.email", "integration@test.example")
	mustGit(t, runGit, "config", "gpg.format", "ssh")
	mustGit(t, runGit, "config", "user.signingkey", sshk.private)
	mustGit(t, runGit, "config", "tag.gpgsign", "true")

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Release auth fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mustGit(t, runGit, "add", "README.md")
	mustGit(t, runGit, "commit", "-q", "-m", "initial")
	mustGit(t, runGit, "tag", "-s", "-m", "release "+tag, tag)
}

// makeGPGSignedTag is the GPG counterpart of makeSSHSignedTag.
func makeGPGSignedTag(t *testing.T, runGit func(args ...string) error, repo string, key gpgKey, tag string) {
	t.Helper()

	mustGit(t, runGit, "config", "user.name", "Integration Test")
	mustGit(t, runGit, "config", "user.email", "integration@test.example")
	mustGit(t, runGit, "config", "gpg.format", "openpgp")
	mustGit(t, runGit, "config", "user.signingkey", key.keyID)
	mustGit(t, runGit, "config", "tag.gpgsign", "true")

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Release auth fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mustGit(t, runGit, "add", "README.md")
	mustGit(t, runGit, "commit", "-q", "-m", "initial")
	mustGit(t, runGit, "tag", "-s", "-m", "release "+tag, tag)
}

// Silence the linter about exec being unused — referenced by helpers
// elsewhere; kept here in case future tests need direct shell-out.
var _ = exec.Command
