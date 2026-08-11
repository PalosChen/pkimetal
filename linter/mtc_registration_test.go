package linter_test

import (
	"slices"
	"testing"

	"github.com/pkimetal/pkimetal/linter"
	_ "github.com/pkimetal/pkimetal/linter/cqrplint"
	_ "github.com/pkimetal/pkimetal/linter/mtclint"
)

func TestMTCPolicyLintersRegisterPublicMetadata(t *testing.T) {
	tests := []struct {
		name             string
		formattedVersion string
		url              string
		supported        []linter.ProfileId
	}{
		{
			name:             "mtclint",
			formattedVersion: "draft-05",
			url:              "https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-05",
			supported:        []linter.ProfileId{linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER},
		},
		{
			name:             "cqrplint",
			formattedVersion: "v0.2.0",
			url:              "https://github.com/pkimetal/pkimetal/blob/main/doc/superpowers/specs/2026-08-11-mtc-pkimetal-design.md#source-baselines",
			supported:        []linter.ProfileId{linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var matches []*linter.Linter
			for _, registered := range linter.Linters {
				if registered.Name == tc.name {
					matches = append(matches, registered)
				}
			}
			if len(matches) != 1 {
				t.Fatalf("registrations = %d, want 1", len(matches))
			}
			registered := matches[0]
			if got := linter.VersionString(registered.Version); got != tc.formattedVersion {
				t.Errorf("formatted version = %q, want %q", got, tc.formattedVersion)
			}
			if registered.Url != tc.url {
				t.Errorf("URL = %q, want %q", registered.Url, tc.url)
			}
			for profile := range linter.AllProfiles {
				wantSupported := slices.Contains(tc.supported, profile)
				gotSupported := !slices.Contains(registered.Unsupported, profile)
				if gotSupported != wantSupported {
					t.Errorf("profile %s supported = %t, want %t", linter.AllProfiles[profile].Name, gotSupported, wantSupported)
				}
			}
		})
	}
}
