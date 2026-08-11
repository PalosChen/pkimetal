package mtclint

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestRegistration(t *testing.T) {
	var registered []*linter.Linter
	for _, candidate := range linter.Linters {
		if candidate.Name == "mtclint" {
			registered = append(registered, candidate)
		}
	}
	if len(registered) != 1 {
		t.Fatalf("mtclint registrations = %d, want 1", len(registered))
	}
	got := registered[0]
	if got.Version != "draft-05" {
		t.Errorf("version = %q, want draft-05", got.Version)
	}
	if got.Url != "https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-05" {
		t.Errorf("URL = %q", got.Url)
	}
	if got.NumInstances != 1 {
		t.Errorf("instances = %d, want 1", got.NumInstances)
	}

	supported := []linter.ProfileId{linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER}
	if !slices.Equal(got.Supported, supported) {
		t.Errorf("supported = %#v, want %#v", got.Supported, supported)
	}
	for id := range linter.AllProfiles {
		if gotSupported := got.Supports(id); gotSupported != slices.Contains(supported, id) {
			t.Errorf("profile %s supported = %t", linter.AllProfiles[id].Name, gotSupported)
		}
	}
}

func TestInstanceLifecycleAndResultProcessing(t *testing.T) {
	handler := &MTCLint{}
	useHandleRequest, directory, cmd, args := handler.StartInstance()
	if !useHandleRequest || directory != "" || cmd != "" || args != nil {
		t.Fatalf("StartInstance() = %t, %q, %q, %#v", useHandleRequest, directory, cmd, args)
	}
	handler.StopInstance(nil)
	want := linter.LintingResult{Finding: "finding", Field: "field", Code: "code", Severity: linter.SEVERITY_WARNING}
	if got := handler.ProcessResult(want); got != want {
		t.Fatalf("ProcessResult() = %#v, want %#v", got, want)
	}
}

func TestDraftProfilesHandleValidArtifactsAndMutations(t *testing.T) {
	tests := []struct {
		name     string
		profile  linter.ProfileId
		template mtctest.Template
		mutate   func(*mtctest.Template)
		wantCode string
	}{
		{"CA", linter.MTC_CA, mtctest.ValidCATemplate(), func(tpl *mtctest.Template) { mtctest.RemoveExtension(tpl, mtctest.OIDBasicConstraints) }, "e_mtc_ca_basic_constraints_missing"},
		{"subscriber", linter.MTC_SUBSCRIBER, mtctest.ValidSubscriberTemplate(), func(tpl *mtctest.Template) { tpl.Serial.SetInt64(9) }, "e_mtc_serial_log_number_zero"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid := parseArtifact(t, tc.template, mtc.InputCertificate)
			if got := handle(t, tc.profile, valid); len(got) != 0 {
				t.Fatalf("valid artifact findings = %#v", got)
			}
			tc.mutate(&tc.template)
			invalid := parseArtifact(t, tc.template, mtc.InputCertificate)
			assertHasCode(t, handle(t, tc.profile, invalid), tc.wantCode)
		})
	}
}

func TestCQRPProfilesAlsoRunDraftRulesButNotCQRPPolicy(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	tpl.Serial.SetInt64(9)
	tpl.NotAfter = tpl.NotBefore.AddDate(0, 0, 48)
	results := handle(t, linter.CQRP_MTC_SUBSCRIBER, parseArtifact(t, tpl, mtc.InputCertificate))
	assertHasCode(t, results, "e_mtc_serial_log_number_zero")
	assertLacksCode(t, results, "e_cqrp_subscriber_validity_too_long")
}

func TestExpectedProfileKindControlsRulesAndReportsMismatch(t *testing.T) {
	tests := []struct {
		name        string
		profile     linter.ProfileId
		template    mtctest.Template
		wantFinding string
		wantCode    string
	}{
		{
			name:        "CA artifact selected as subscriber",
			profile:     linter.MTC_SUBSCRIBER,
			template:    mtctest.ValidCATemplate(),
			wantFinding: "Selected profile \"mtc_subscriber\" expects subscriber artifact; actual artifact kind is ca",
			wantCode:    "e_mtc_signature_algorithm_oid",
		},
		{
			name:        "subscriber artifact selected as CQRP CA",
			profile:     linter.CQRP_MTC_CA,
			template:    mtctest.ValidSubscriberTemplate(),
			wantFinding: "Selected profile \"cqrp_mtc_ca\" expects ca artifact; actual artifact kind is subscriber",
			wantCode:    "e_mtc_ca_extension_missing",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, tc.template, mtc.InputCertificate)
			before := fmt.Sprintf("%#v", artifact)
			results := handle(t, tc.profile, artifact)
			if len(results) == 0 || results[0] != (linter.LintingResult{
				Finding:  tc.wantFinding,
				Field:    "profile",
				Code:     "e_mtc_profile_artifact_mismatch",
				Severity: linter.SEVERITY_ERROR,
			}) {
				t.Fatalf("first mismatch finding = %#v", results)
			}
			assertHasCode(t, results, tc.wantCode)
			if after := fmt.Sprintf("%#v", artifact); after != before {
				t.Fatal("handler mutated caller artifact")
			}
		})
	}
}

func TestNilAndUnknownArtifactsReportMismatchWithoutPanicking(t *testing.T) {
	want := linter.LintingResult{
		Finding:  "Selected profile \"mtc_ca\" expects ca artifact; actual artifact kind is unrecognized",
		Field:    "profile",
		Code:     "e_mtc_profile_artifact_mismatch",
		Severity: linter.SEVERITY_ERROR,
	}
	for _, req := range []*linter.LintingRequest{
		{ProfileId: linter.MTC_CA},
		{ProfileId: linter.MTC_CA, MTCArtifact: &mtc.Artifact{Kind: mtc.ArtifactUnknown, InputKind: mtc.InputCertificate}},
	} {
		got := (&MTCLint{}).HandleRequest(context.Background(), nil, req)
		if len(got) == 0 || got[0] != want {
			t.Fatalf("mismatch = %#v, want first %#v", got, want)
		}
	}
	if got := (&MTCLint{}).HandleRequest(context.Background(), nil, nil); got != nil {
		t.Fatalf("nil request results = %#v", got)
	}
	if got := (&MTCLint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{ProfileId: linter.RFC5280_ROOT}); got != nil {
		t.Fatalf("unsupported profile results = %#v", got)
	}
}

func TestTBSSkipsOuterSignatureAndProofRules(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.OuterSignature.OID = mtctest.OIDSHA256
	tpl.Signature = mtctest.MalformedProofBytes()
	results := handle(t, linter.MTC_SUBSCRIBER, parseArtifact(t, tpl, mtc.InputTBSCertificate))
	for _, code := range []string{
		"e_mtc_cert_signature_algorithm_mismatch",
		"f_mtc_proof_malformed",
		"e_mtc_proof_cosigner_id_empty",
	} {
		assertLacksCode(t, results, code)
	}
}

func TestMismatchResultsAreDeterministic(t *testing.T) {
	artifact := parseArtifact(t, mtctest.ValidCATemplate(), mtc.InputCertificate)
	first := handle(t, linter.MTC_SUBSCRIBER, artifact)
	for i := 0; i < 10; i++ {
		if got := handle(t, linter.MTC_SUBSCRIBER, artifact); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d results differ:\n%#v\n%#v", i, got, first)
		}
	}
}

func parseArtifact(t *testing.T, tpl mtctest.Template, inputKind mtc.InputKind) *mtc.Artifact {
	t.Helper()
	input := mtctest.Certificate(tpl)
	if inputKind == mtc.InputTBSCertificate {
		input = mtctest.TBSCertificate(tpl)
	}
	artifact, err := mtc.Parse(input, inputKind)
	if err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	return artifact
}

func handle(t *testing.T, profile linter.ProfileId, artifact *mtc.Artifact) []linter.LintingResult {
	t.Helper()
	req := &linter.LintingRequest{ProfileId: profile, MTCArtifact: artifact}
	return (&MTCLint{}).HandleRequest(context.Background(), nil, req)
}

func assertHasCode(t *testing.T, results []linter.LintingResult, code string) {
	t.Helper()
	for _, result := range results {
		if result.Code == code {
			return
		}
	}
	t.Errorf("missing finding %s in %#v", code, results)
}

func assertLacksCode(t *testing.T, results []linter.LintingResult, code string) {
	t.Helper()
	for _, result := range results {
		if result.Code == code {
			t.Errorf("unexpected finding %s in %#v", code, results)
			return
		}
	}
}
