// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Cosign-based artefact signing: end-to-end roundtrip through the
// `release sign --method=kms --key=<local-cosign-key>` and
// `validate artifact-signature --method=kms --key=<pubkey>` paths.
//
// We don't exercise the Sigstore-keyless path here — it requires a
// live Fulcio + Rekor and an OIDC-emitting runner. The wiring is
// unit-tested in internal/adapters/cosign (argv shape) and
// internal/app/release (dispatch).

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cosignKey generates a local cosign keypair (test.key + test.pub)
// in dir, with an empty passphrase (controlled by COSIGN_PASSWORD=).
// Returns the absolute paths to the private and public keys.
func cosignKey(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	requireTool(t, "cosign")

	cmd := exec.Command("cosign", "generate-key-pair", "--output-key-prefix", "test")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign generate-key-pair: %v\n%s", err, out)
	}

	priv := filepath.Join(dir, "test.key")
	pub := filepath.Join(dir, "test.pub")

	if !fileExists(priv) || !fileExists(pub) {
		t.Fatalf("cosign generate-key-pair did not produce expected files in %s", dir)
	}

	return priv, pub
}

// TestReleaseSignCosignKMSRoundtrip verifies the full chain:
// `release sign --method=kms --key=<local-key>` produces a .sig
// sidecar, and `validate artifact-signature` accepts it via the
// matching pubkey. A tampered artefact must fail verification.
func TestReleaseSignCosignKMSRoundtrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := cosignKey(t, dir)

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign.
	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"COSIGN_PASSWORD": "",
		},
	}, "release", "sign",
		"--method=kms",
		"--key", priv,
		"--release-artifacts-dir", "release-artifacts",
	)
	if code != 0 {
		t.Fatalf("sign exit %d\nstderr: %s", code, stderr)
	}

	bundle := filepath.Join(dir, "app.tgz.bundle")
	if !fileExists(bundle) {
		t.Fatalf("expected %s; not produced", bundle)
	}

	// cosign 3.x emits a single bundle for KMS too — no separate
	// .sig or .pem files.
	if fileExists(filepath.Join(dir, "app.tgz.sig")) || fileExists(filepath.Join(dir, "app.tgz.pem")) {
		t.Errorf("cosign 3.x must emit only .bundle; found stray .sig or .pem")
	}

	// Verify (auto-detected method=kms because --key is supplied).
	// The artefact path is relative to dir; we move it next to its
	// bundle so the validate command finds the sidecar.
	artCopy := filepath.Join(dir, "app.tgz")
	if err := os.Rename(filepath.Join(ra, "app.tgz"), artCopy); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{
		dir: dir,
	}, "validate", "artifact-signature",
		"--artifact", "app.tgz",
		"--key", pub,
	)
	if code != 0 {
		t.Errorf("verify exit %d\nstderr: %s", code, stderr)
	}

	// Tamper: rewrite the artefact and re-verify. Must fail.
	if err := os.WriteFile(artCopy, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, code = run(t, runOpts{dir: dir}, "validate", "artifact-signature",
		"--artifact", "app.tgz", "--key", pub)
	if code == 0 {
		t.Errorf("tampered artefact verify must fail (non-zero exit), got 0")
	}
}

// TestReleaseSignMethodFlagValidation pins the per-method invariants
// on --key / --oidc-issuer at the CLI boundary. Wrong combos must
// exit non-zero with a specific message; the binary must not even
// reach the cosign subprocess.
func TestReleaseSignMethodFlagValidation(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name      string
		args      []string
		wantInErr []string
	}{
		{
			name:      "kms-without-key",
			args:      []string{"release", "sign", "--method=kms"},
			wantInErr: []string{"--key is required", "--method=kms"},
		},
		{
			name:      "sigstore-with-key",
			args:      []string{"release", "sign", "--method=sigstore", "--key", "awskms:///alias/X"},
			wantInErr: []string{"--key is forbidden", "--method=sigstore"},
		},
		{
			name:      "kms-with-oidc-issuer",
			args:      []string{"release", "sign", "--method=kms", "--key", "/dev/null", "--oidc-issuer", "https://x"},
			wantInErr: []string{"--oidc-issuer is forbidden", "--method=kms"},
		},
		{
			name:      "gpg-with-key",
			args:      []string{"release", "sign", "--method=gpg", "--key", "./somekey"},
			wantInErr: []string{"--key is forbidden", "--method=gpg"},
		},
		{
			name:      "unknown-method",
			args:      []string{"release", "sign", "--method=openssl"},
			wantInErr: []string{"sign method", "not one of"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, stderr, code := run(t, runOpts{dir: dir}, c.args...)
			if code == 0 {
				t.Fatalf("expected non-zero exit on bad flag combo, got 0\nstderr: %s", stderr)
			}

			for _, want := range c.wantInErr {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr must mention %q for operator guidance; got:\n%s", want, stderr)
				}
			}
		})
	}
}

// TestValidateArtifactSignatureAutoDetect pins the sidecar-based
// auto-detection: `.bundle` → cosign (kms or sigstore per flags);
// `.asc` → GPG; both present requires --method explicit.
func TestValidateArtifactSignatureAutoDetect(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "app.tgz")

	if err := os.WriteFile(art, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No sidecars → ErrMissingInput → exit 66 (sysexits EX_NOINPUT).
	_, stderr, code := run(t, runOpts{dir: dir},
		"validate", "artifact-signature", "--artifact", "app.tgz")
	if code != 66 { //nolint:mnd // EX_NOINPUT
		t.Errorf("no sidecars: expected exit 66, got %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "no signature sidecar") {
		t.Errorf("missing-sidecar error must mention 'no signature sidecar'; got %s", stderr)
	}

	// Dual-sign (.bundle + .asc) → ErrInvalidConfig → exit 78.
	if err := os.WriteFile(art+".bundle", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(art+".asc", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code = run(t, runOpts{dir: dir},
		"validate", "artifact-signature", "--artifact", "app.tgz")
	if code != 78 { //nolint:mnd // EX_CONFIG
		t.Errorf("dual-sign: expected exit 78, got %d\nstderr: %s", code, stderr)
	}

	if !strings.Contains(stderr, "dual-signed state") {
		t.Errorf("dual-sign error must mention 'dual-signed state'; got %s", stderr)
	}
}
