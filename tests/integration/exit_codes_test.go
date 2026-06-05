// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
// SPDX-License-Identifier: CC0-1.0

//go:build integration

package integration

import (
	"testing"
)

// TestExitCodeMatrix locks down the public exit-code contract of the
// CLI by black-box probing each documented sysexits.h-style class.
// CI policy YAML / orchestrator workflows branch on these values, so
// a regression that flips usage→validation (or vice versa) silently
// breaks the entire stage.
//
//   1 — EX_VALIDATION  (input present but rejected by a check)
//   2 — EX_USAGE       (missing flag, unknown subcommand/option)
//  66 — EX_NOINPUT     (referenced input file absent)
//  77 — EX_NOPERM      (release-authorisation denied)
//  78 — EX_CONFIG      (declared config inconsistent / unsupported)
//
// The EX_NOPERM cases are exercised by the release_authorization_test.go
// integration test (signer-not-in-allowlist, missing-allowlist-fails-closed);
// they appear there because building the scenario needs a signed tag.
func TestExitCodeMatrix(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "invalid_tag_format_is_EX_VALIDATION",
			args: []string{"validate", "tag", "format", "--tag", "vBOGUS"},
			want: 1,
		},
		{
			name: "missing_required_flag_is_EX_USAGE",
			args: []string{"version", "bump"},
			want: 2,
		},
		{
			name: "unknown_subcommand_is_EX_USAGE",
			args: []string{"this-subcommand-does-not-exist"},
			want: 2,
		},
		{
			name: "unknown_project_type_is_EX_USAGE",
			args: []string{"version", "bump", "--project-type=java", "--version=1.0.0"},
			want: 2,
		},
		{
			name: "valid_tag_format_is_success",
			args: []string{"validate", "tag", "format", "--tag", "v1.2.3"},
			want: 0,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stdout, stderr, code := run(t, runOpts{}, tc.args...)
			if code != tc.want {
				t.Errorf("args=%v want exit %d got %d\nstdout:\n%s\nstderr:\n%s",
					tc.args, tc.want, code, stdout, stderr)
			}
		})
	}
}
