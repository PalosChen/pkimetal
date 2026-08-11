package linter

import (
	"slices"
	"testing"
)

var mtcProfiles = []ProfileId{MTC_CA, MTC_SUBSCRIBER, CQRP_MTC_CA, CQRP_MTC_SUBSCRIBER}

func TestIsMTCProfile(t *testing.T) {
	for _, profile := range mtcProfiles {
		if !IsMTCProfile(profile) {
			t.Errorf("IsMTCProfile(%v) = false", profile)
		}
	}
	for _, profile := range []ProfileId{AUTODETECT, RFC5280_ROOT, BIMIGROUP_LEAF_VERIFIEDMARK_PRECERTIFICATE, -1, CQRP_MTC_SUBSCRIBER + 1} {
		if IsMTCProfile(profile) {
			t.Errorf("IsMTCProfile(%v) = true", profile)
		}
	}
}

func TestSupportsRequiresPositiveMTCRegistrationAndPreservesLegacyBehavior(t *testing.T) {
	legacy := &Linter{Unsupported: []ProfileId{RFC5280_ROOT}}
	for _, profile := range mtcProfiles {
		if legacy.Supports(profile) {
			t.Errorf("legacy linter supports MTC profile %s without positive registration", AllProfiles[profile].Name)
		}
	}
	if legacy.Supports(RFC5280_ROOT) {
		t.Fatal("legacy linter supports a legacy profile listed in Unsupported")
	}
	if !legacy.Supports(RFC5280_LEAF) {
		t.Fatal("legacy linter no longer supports an unlisted legacy profile")
	}

	positive := &Linter{
		Supported:   []ProfileId{MTC_CA},
		Unsupported: []ProfileId{MTC_CA, RFC5280_ROOT},
	}
	if !positive.Supports(MTC_CA) {
		t.Fatal("positive MTC registration was overridden by Unsupported")
	}
	if positive.Supports(MTC_SUBSCRIBER) {
		t.Fatal("unregistered MTC profile is supported")
	}
	if positive.Supports(RFC5280_ROOT) {
		t.Fatal("positive MTC registration changed legacy Unsupported behavior")
	}
}

func TestEvaluateApplicabilityChecksSupportBeforeCallback(t *testing.T) {
	callbackCalls := 0
	lin := &Linter{
		Supported: []ProfileId{MTC_CA},
		Applicable: func(*LintingRequest) (bool, string) {
			callbackCalls++
			return false, "callback reason"
		},
	}

	applicable, reason := lin.EvaluateApplicability(&LintingRequest{ProfileId: MTC_SUBSCRIBER})
	if applicable || reason != "MTC profile is not explicitly supported" {
		t.Fatalf("unsupported MTC applicability = %t, %q", applicable, reason)
	}
	if callbackCalls != 0 {
		t.Fatalf("callback calls = %d, want 0", callbackCalls)
	}

	applicable, reason = lin.EvaluateApplicability(&LintingRequest{ProfileId: MTC_CA})
	if applicable || reason != "callback reason" {
		t.Fatalf("supported MTC applicability = %t, %q", applicable, reason)
	}
	if callbackCalls != 1 {
		t.Fatalf("callback calls = %d, want 1", callbackCalls)
	}
}

func TestEvaluateApplicabilityHandlesNilReceiversAndRequests(t *testing.T) {
	var nilLinter *Linter
	if applicable, reason := nilLinter.EvaluateApplicability(&LintingRequest{ProfileId: MTC_CA}); applicable || reason == "" {
		t.Fatalf("nil linter applicability = %t, %q", applicable, reason)
	}

	callbackCalls := 0
	lin := &Linter{Applicable: func(*LintingRequest) (bool, string) {
		callbackCalls++
		return true, ""
	}}
	if applicable, reason := lin.EvaluateApplicability(nil); applicable || reason == "" {
		t.Fatalf("nil request applicability = %t, %q", applicable, reason)
	}
	if callbackCalls != 0 {
		t.Fatalf("callback calls = %d, want 0", callbackCalls)
	}
}

func TestRegisterLinterWithProfilesUsesPositiveMTCSupport(t *testing.T) {
	name := "applicability-metadata-test"
	lin := &Linter{Name: name, Supported: []ProfileId{MTC_CA}, Unsupported: []ProfileId{RFC5280_ROOT}}

	registerLinterWithProfiles(lin)
	t.Cleanup(func() {
		for id, profile := range AllProfiles {
			profile.Linters = slices.DeleteFunc(profile.Linters, func(candidate *string) bool {
				return candidate != nil && *candidate == name
			})
			AllProfiles[id] = profile
		}
	})

	for _, tc := range []struct {
		profile ProfileId
		want    bool
	}{
		{MTC_CA, true},
		{MTC_SUBSCRIBER, false},
		{RFC5280_ROOT, false},
		{RFC5280_LEAF, true},
	} {
		got := slices.ContainsFunc(AllProfiles[tc.profile].Linters, func(candidate *string) bool {
			return candidate != nil && *candidate == name
		})
		if got != tc.want {
			t.Errorf("profile %s metadata contains linter = %t, want %t", AllProfiles[tc.profile].Name, got, tc.want)
		}
	}
}
