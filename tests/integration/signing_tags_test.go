// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// `validate tag signature` accepts annotated tags signed either by
// GPG (openpgp) or by SSH (gpg.format=ssh). Both forms have to work
// because release-prerequisites accepts either — different teams use
// different signing infrastructure.
//
// Host isolation matters across this file: a developer's global
// ~/.gitconfig setting (notably gpg.format=ssh) leaking into a GPG
// test would cause git to look up an SSH key for an openpgp-format
// tag and fail with a confusing "Couldn't load public key" error.
// initGitRepo in keys_test.go pins GIT_CONFIG_GLOBAL=/dev/null per
// invocation to neutralise this.
//
// Artefact-level signing (release sign of .tgz / .jar / checksums)
// lives in release_signing_test.go.

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGPGSignedTagVerification verifies the full GPG-signed-tag
// pipeline end-to-end:
//
//  1. bootstrap a throwaway GPG key in an isolated GNUPGHOME
//  2. configure a fresh git repo to sign tags with it
//  3. create a signed annotated tag
//  4. run `reusable-ci validate tag signature` and assert success
func TestGPGSignedTagVerification(t *testing.T) {
	requireTool(t, "gpg")
	requireTool(t, "git")

	key := bootstrapGPGKey(t)

	env := map[string]string{"GNUPGHOME": key.gnupgHome}

	repo := initGitRepo(t, env, func(repo string, runGit func(args ...string) error) {
		mustGit(t, runGit, "config", "user.name", "Integration Test")
		mustGit(t, runGit, "config", "user.email", "integration@test.example")
		mustGit(t, runGit, "config", "gpg.format", "openpgp")
		mustGit(t, runGit, "config", "user.signingkey", key.keyID)
		mustGit(t, runGit, "config", "tag.gpgsign", "true")

		if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "README.md")
		mustGit(t, runGit, "commit", "-q", "-m", "initial")
		mustGit(t, runGit, "tag", "-s", "-m", "release v1.0.0", "v1.0.0")
	})

	pub, err := os.ReadFile(key.publicASC)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := run(t, runOpts{
		dir: repo,
		env: map[string]string{
			"GNUPGHOME":              key.gnupgHome,
			"RELEASE_GPG_PUBLIC_KEY": string(pub),
		},
	}, "validate", "tag", "signature", "--tag", "v1.0.0", "--repository", "diggsweden/integration")
	if code != 0 {
		t.Fatalf("validate tag signature exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// TestGPGSignedTagRejectsLightweight verifies that a lightweight
// (unsigned, non-annotated) tag is rejected by `validate tag
// signature`. The configure step disables tag.gpgsign locally for
// the lightweight-tag-creation step so that a global tag.gpgsign=true
// doesn't auto-promote `git tag light` into a signed tag.
func TestGPGSignedTagRejectsLightweight(t *testing.T) {
	requireTool(t, "git")

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		mustGit(t, runGit, "config", "user.name", "Integration Test")
		mustGit(t, runGit, "config", "user.email", "integration@test.example")

		if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "README.md")
		mustGit(t, runGit, "commit", "-q", "-m", "initial")
		// Bypass any inherited tag.gpgsign for this specific tag.
		mustGit(t, runGit, "-c", "tag.gpgsign=false", "tag", "v0.0.1-lightweight", "HEAD")
	})

	_, _, code := run(t, runOpts{dir: repo},
		"validate", "tag", "signature", "--tag", "v0.0.1-lightweight", "--repository", "diggsweden/integration")
	if code == 0 {
		t.Fatalf("validate tag signature should fail for lightweight tag; got exit 0")
	}
}

// TestSSHSignedTagVerification mirrors TestGPGSignedTagVerification
// but uses an ed25519 key + allowed_signers configuration. The
// release pipeline must accept either format — this test guards the
// SSH branch end-to-end.
//
// The wrinkle: SSH signing only works when gpg.format=ssh AND
// user.signingkey points at the ssh key path. A leftover gpg.format
// from the developer's global config would derail this, which is why
// host isolation (GIT_CONFIG_GLOBAL=/dev/null) is non-negotiable.
func TestSSHSignedTagVerification(t *testing.T) {
	requireTool(t, "git")
	requireTool(t, "ssh-keygen")

	sshk := bootstrapSSHKey(t)

	repo := initGitRepo(t, nil, func(repo string, runGit func(args ...string) error) {
		mustGit(t, runGit, "config", "user.name", "Integration Test")
		mustGit(t, runGit, "config", "user.email", "integration@test.example")
		mustGit(t, runGit, "config", "gpg.format", "ssh")
		mustGit(t, runGit, "config", "user.signingkey", sshk.private)
		mustGit(t, runGit, "config", "gpg.ssh.allowedSignersFile", sshk.allowedSigners)
		mustGit(t, runGit, "config", "tag.gpgsign", "true")

		if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# Hello SSH\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		mustGit(t, runGit, "add", "README.md")
		mustGit(t, runGit, "commit", "-q", "-m", "initial")
		mustGit(t, runGit, "tag", "-s", "-m", "release v2.0.0", "v2.0.0")
	})

	stdout, stderr, code := run(t, runOpts{dir: repo},
		"validate", "tag", "signature", "--tag", "v2.0.0", "--repository", "diggsweden/integration")
	if code != 0 {
		t.Fatalf("validate tag signature exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// The validator writes human output to stderr (stdout is reserved
	// for structured emission). Check both for portability.
	if !strings.Contains(stdout+stderr, "SSH signature") {
		t.Errorf("expected 'SSH signature' mention in output\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

// mustGit is a tiny convenience wrapper for the configure callback
// inside initGitRepo. It fails the test on any git error.
func mustGit(t *testing.T, runGit func(args ...string) error, args ...string) {
	t.Helper()

	if err := runGit(args...); err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
}
