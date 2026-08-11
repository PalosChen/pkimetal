package linter

import "testing"

func TestVersionString(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"draft identifier", "draft-05", "draft-05"},
		{"stable semantic version", "1.2.3", "v1.2.3"},
		{"prefixed stable semantic version", "v1.2.3", "v1.2.3"},
		{"git describe", "v1.2.3-4-gabcdef1", "v1.2.3-4-gabcdef1"},
		{"Go pseudo-version", "v0.0.0-20210101000000-abcdef123456", "v0.0.0-20210101000000-abcdef123456"},
		{"commit hash", "abcdef123456", "gabcdef1"},
		{"short identifier", "dev", "(dev)"},
		{"not installed", NOT_INSTALLED, "[not installed]"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := VersionString(tc.version); got != tc.want {
				t.Errorf("VersionString(%q) = %q, want %q", tc.version, got, tc.want)
			}
		})
	}
}
