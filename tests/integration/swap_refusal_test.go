// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

// Locks the swap-refusal contract end-to-end: `release sign` MUST
// exit EX_CONFIG (78) when /proc/swaps reports an active swap area,
// unless the operator passes --debug-allow-swap. The swap state is
// injected via REUSABLE_CI_PROC_SWAPS (a test-only knob that
// redirects the reader, NOT a policy override).

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// procSwapsWith returns a path to a synthetic /proc/swaps body.
// header-only → no swap; one extra line → swap on.
func procSwapsWith(t *testing.T, swapOn bool) string {
	t.Helper()

	body := "Filename\tType\tSize\tUsed\tPriority\n"
	if swapOn {
		body += "/dev/sda2\tpartition\t2097148\t0\t-2\n"
	}

	path := filepath.Join(t.TempDir(), "swaps")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestSwapRefusal_ReleaseSignRefusesWith78 verifies that `release
// sign` exits with EX_CONFIG (78) and the actionable error message
// when /proc/swaps reports an active swap area.
func TestSwapRefusal_ReleaseSignRefusesWith78(t *testing.T) {
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	priv, err := os.ReadFile(key.privateASC)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"GNUPGHOME":                 key.gnupgHome,
			"GPG_PRIVATE_KEY":           string(priv),
			"REUSABLE_CI_PROC_SWAPS":    procSwapsWith(t, true),
		},
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")

	if code != 78 { //nolint:mnd // EX_CONFIG (sysexits.h)
		t.Errorf("expected EX_CONFIG=78 with swap on, got %d\nstderr: %s", code, stderr)
	}

	for _, want := range []string{
		"swap is enabled",
		"swapoff",
		"hosted runner",
		"Sigstore",
		"KMS",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("error message must mention %q for operator guidance; got:\n%s", want, stderr)
		}
	}

	// The signature must NOT have been produced.
	if fileExists(filepath.Join(dir, "app.tgz.asc")) {
		t.Errorf("policy was bypassed — signature was created despite swap refusal")
	}
}

// TestSwapRefusal_ReleaseSignPassesWhenSwapOff verifies the inverse:
// the binary signs normally when /proc/swaps shows no active swap.
// Confirms the swap check is precisely scoped — it doesn't break the
// happy path on swap-off runners.
func TestSwapRefusal_ReleaseSignPassesWhenSwapOff(t *testing.T) {
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	priv, err := os.ReadFile(key.privateASC)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"GNUPGHOME":                 key.gnupgHome,
			"GPG_PRIVATE_KEY":           string(priv),
			"REUSABLE_CI_PROC_SWAPS":    procSwapsWith(t, false),
		},
	}, "release", "sign", "--release-artifacts-dir", "release-artifacts")

	if code != 0 {
		t.Fatalf("expected exit 0 with swap off, got %d\nstderr: %s", code, stderr)
	}

	if !fileExists(filepath.Join(dir, "app.tgz.asc")) {
		t.Errorf("signature should have been created on swap-off host")
	}
}

// TestSwapRefusal_DebugFlagAllowsSigning verifies the documented
// debug escape hatch end-to-end: passing --debug-allow-swap
// alongside a swap-on /proc/swaps allows signing to complete and
// the operator gets a Warning annotation in CI logs.
func TestSwapRefusal_DebugFlagAllowsSigning(t *testing.T) {
	requireTool(t, "gpg")
	key := bootstrapGPGKey(t)

	priv, err := os.ReadFile(key.privateASC)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	ra := filepath.Join(dir, "release-artifacts")
	if err := os.MkdirAll(ra, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(ra, "app.tgz"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := run(t, runOpts{
		dir: dir,
		env: map[string]string{
			"GNUPGHOME":              key.gnupgHome,
			"GPG_PRIVATE_KEY":        string(priv),
			"REUSABLE_CI_PROC_SWAPS": procSwapsWith(t, true),
			// Force the GHA output channel so the test can pin the
			// `::warning::` workflow command. Production runs in GHA
			// always have these set; in unit-test environments they
			// don't, and the annotator falls back to "Warning:" text.
			"GITHUB_ACTIONS": "true",
			"CI":             "true",
		},
	}, "release", "sign", "--debug-allow-swap", "--release-artifacts-dir", "release-artifacts")

	if code != 0 {
		t.Fatalf("expected exit 0 with --debug-allow-swap set, got %d\nstderr: %s", code, stderr)
	}

	if !fileExists(filepath.Join(dir, "app.tgz.asc")) {
		t.Errorf("expected signature when debug override active; not produced")
	}

	if !strings.Contains(stderr, "::warning::") {
		t.Errorf("debug override must emit a Warning annotation; stderr:\n%s", stderr)
	}

	for _, want := range []string{"--debug-allow-swap", "swap"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("warning must mention %q; got:\n%s", want, stderr)
		}
	}
}

