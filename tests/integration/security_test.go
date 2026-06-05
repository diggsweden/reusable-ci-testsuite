// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Black-box coverage for the secret-handling hardening:
//
//   - GPG key flows via stdin, never lands on disk in our tmpdir
//   - Subprocess errors don't echo private-key markers
//   - Process-level hardening doesn't break the happy path

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurity_GPGImportLeavesNoKeyResidue runs a full `release gpg
// import` cycle and asserts the temporary directory it touched
// contains no files whose name suggests a key (key.pgp, key.asc, etc.).
// Pre-hardening, ImportKey wrote /tmp/reusable-ci-gpg-*/key.pgp;
// post-hardening, the key goes straight to gpg on stdin.
func TestSecurity_GPGImportLeavesNoKeyResidue(t *testing.T) {
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	// Isolated TMPDIR so the assertion below is meaningful. The
	// reusable-ci binary will use this for any os.MkdirTemp calls;
	// any residue lands here.
	tmp := t.TempDir()

	priv, err := os.ReadFile(key.privateASC)
	if err != nil {
		t.Fatal(err)
	}

	// --git-config-global=false explicitly so the GIT_CONFIG_GLOBAL=
	// /dev/null env from isolatedEnv (used for git-isolation; not a
	// bool) doesn't trip the CLI's boolean parser for that flag.
	_, stderr, code := run(t, runOpts{
		env: map[string]string{
			"GNUPGHOME":       key.gnupgHome,
			"GPG_PRIVATE_KEY": string(priv),
			"TMPDIR":          tmp,
		},
	}, "release", "gpg", "import", "--git-config-global=false")
	if code != 0 {
		t.Fatalf("release gpg import exit %d\nstderr: %s", code, stderr)
	}

	// Walk the temp dir; any file with a name hinting at a key is a
	// residue regression.
	suspicious := []string{}

	err = filepath.Walk(tmp, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		name := strings.ToLower(filepath.Base(path))
		switch {
		case strings.Contains(name, "key"),
			strings.HasSuffix(name, ".pgp"),
			strings.HasSuffix(name, ".asc"),
			strings.HasSuffix(name, ".gpg"):
			suspicious = append(suspicious, path)
		}

		return nil
	})

	if err != nil {
		t.Fatalf("walk tmpdir: %v", err)
	}

	if len(suspicious) > 0 {
		t.Errorf("found %d suspicious file(s) in TMPDIR after `release gpg import` — the key may have hit disk:\n%s",
			len(suspicious), strings.Join(suspicious, "\n"))
	}
}

// TestSecurity_GPGStderrDoesNotEchoInputKey forces a gpg failure on
// a malformed key and asserts the wrapped error reaching our stderr
// has NO recognisable private-key marker in it. The redactor in
// internal/safeexec/redact.go is the safety net.
func TestSecurity_GPGStderrDoesNotEchoInputKey(t *testing.T) {
	requireTool(t, "gpg")

	tmp := t.TempDir()

	// Pass a deliberately-malformed key that contains a private-key
	// marker. If gpg ever decided to echo input on error, our
	// redactor must catch it before the bytes leave the process.
	malformed := "-----BEGIN PGP PRIVATE KEY BLOCK-----\nthis-is-not-base64-armor-payload\n-----END PGP PRIVATE KEY BLOCK-----\n"

	_, stderr, code := run(t, runOpts{
		env: map[string]string{
			"GNUPGHOME":       t.TempDir(), // isolated empty
			"GPG_PRIVATE_KEY": malformed,
			"TMPDIR":          tmp,
		},
	}, "release", "gpg", "import")

	if code == 0 {
		t.Fatal("malformed key should fail gpg --import")
	}

	// The redactor replaces the body with a notice; the marker may
	// still appear in the replacement text. What MUST NOT appear is
	// the original payload bytes ("this-is-not-base64-armor-payload").
	if strings.Contains(stderr, "this-is-not-base64-armor-payload") {
		t.Errorf("stderr leaked the original input-key payload:\n%s", stderr)
	}
}
