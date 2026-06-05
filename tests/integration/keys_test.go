// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gpgKey holds a throwaway GPG key plus its isolated GNUPGHOME.
type gpgKey struct {
	gnupgHome  string
	keyID      string
	fingerprint string
	privateASC string // path to armored private key
	publicASC  string // path to armored public key
}

// bootstrapGPGKey generates a throwaway no-passphrase RSA key in an
// isolated GNUPGHOME with ultimate ownertrust. The key is cleaned up
// when the test ends via t.Cleanup.
func bootstrapGPGKey(t *testing.T) gpgKey {
	t.Helper()
	requireTool(t, "gpg")

	dir := t.TempDir()

	keygen := filepath.Join(dir, "keygen")
	if err := os.WriteFile(keygen, []byte(`%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Integration Test
Name-Email: integration@test.example
Expire-Date: 0
%commit
`), 0o600); err != nil {
		t.Fatalf("write keygen: %v", err)
	}

	runGPG := func(args ...string) (string, error) {
		cmd := exec.Command("gpg", args...)
		cmd.Env = append(os.Environ(), "GNUPGHOME="+dir)

		out, err := cmd.CombinedOutput()

		return string(out), err
	}

	if _, err := runGPG("--batch", "--gen-key", keygen); err != nil {
		t.Fatalf("gen-key: %v", err)
	}

	colons, err := runGPG("--list-secret-keys", "--with-colons")
	if err != nil {
		t.Fatalf("list-secret-keys: %v", err)
	}

	key := gpgKey{gnupgHome: dir}
	for _, line := range strings.Split(colons, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 11 {
			continue
		}

		switch fields[0] {
		case "sec":
			if key.keyID == "" {
				key.keyID = fields[4]
			}
		case "fpr":
			if key.fingerprint == "" {
				key.fingerprint = fields[9]
			}
		}
	}

	if key.keyID == "" || key.fingerprint == "" {
		t.Fatalf("could not parse key id / fingerprint from:\n%s", colons)
	}

	// Ultimate ownertrust so signing works without prompts.
	trustCmd := exec.Command("gpg", "--import-ownertrust")
	trustCmd.Env = append(os.Environ(), "GNUPGHOME="+dir)
	trustCmd.Stdin = strings.NewReader(key.fingerprint + ":6:\n")

	if out, err := trustCmd.CombinedOutput(); err != nil {
		t.Fatalf("import-ownertrust: %v\n%s", err, out)
	}

	key.privateASC = filepath.Join(dir, "priv.asc")
	if err := exportArmored(dir, key.keyID, key.privateASC, "--export-secret-keys"); err != nil {
		t.Fatal(err)
	}

	key.publicASC = filepath.Join(dir, "pub.asc")
	if err := exportArmored(dir, key.keyID, key.publicASC, "--export"); err != nil {
		t.Fatal(err)
	}

	return key
}

func exportArmored(gnupgHome, keyID, dst, kind string) error {
	out, err := os.Create(dst) //nolint:gosec // test fixture path under t.TempDir().
	if err != nil {
		return err
	}

	defer out.Close()

	cmd := exec.Command("gpg", "--armor", kind, keyID)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+gnupgHome)
	cmd.Stdout = out

	return cmd.Run()
}

// sshKey holds a throwaway ed25519 keypair + an allowed_signers file
// suitable for SSH-format tag signing.
type sshKey struct {
	private        string
	public         string
	allowedSigners string
}

// bootstrapSSHKey generates an ed25519 key + allowed_signers file that
// authorises the same identity used by isolated git commits.
func bootstrapSSHKey(t *testing.T) sshKey {
	t.Helper()
	requireTool(t, "ssh-keygen")

	dir := t.TempDir()
	priv := filepath.Join(dir, "id_ed25519")

	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "integration", "-f", priv).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}

	pub, err := os.ReadFile(priv + ".pub")
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}

	allowed := filepath.Join(dir, "allowed_signers")
	body := "integration@test.example " + strings.TrimSpace(string(pub)) + "\n"
	if err := os.WriteFile(allowed, []byte(body), 0o600); err != nil {
		t.Fatalf("write allowed_signers: %v", err)
	}

	return sshKey{private: priv, public: priv + ".pub", allowedSigners: allowed}
}

// initGitRepo creates an empty git repo at a fresh dir under t.TempDir
// and runs the supplied configure func against the repo.
//
// All git invocations from this helper go through an isolated config
// stack (GIT_CONFIG_GLOBAL=/dev/null) so the developer's ~/.gitconfig
// — notably gpg.format=ssh — cannot bleed in.
func initGitRepo(t *testing.T, env map[string]string, configure func(repo string, runGit func(args ...string) error)) string {
	t.Helper()
	requireTool(t, "git")

	repo := t.TempDir()
	base := map[string]string{
		"GIT_CONFIG_GLOBAL":  os.DevNull,
		"GIT_CONFIG_SYSTEM":  os.DevNull,
		"GIT_AUTHOR_NAME":    "Integration Test",
		"GIT_AUTHOR_EMAIL":   "integration@test.example",
		"GIT_COMMITTER_NAME": "Integration Test",
		"GIT_COMMITTER_EMAIL": "integration@test.example",
	}
	for k, v := range env {
		base[k] = v
	}

	runGit := func(args ...string) error {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		// Build env from base + PATH/HOME from os.
		env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		for k, v := range base {
			env = append(env, k+"="+v)
		}

		cmd.Env = env

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}

		return err
	}

	if err := runGit("init", "-q", "-b", "main"); err != nil {
		t.Fatalf("git init: %v", err)
	}

	if configure != nil {
		configure(repo, runGit)
	}

	return repo
}
