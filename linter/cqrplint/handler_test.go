package cqrplint

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestRegistration(t *testing.T) {
	var registered []*linter.Linter
	for _, candidate := range linter.Linters {
		if candidate.Name == "cqrplint" {
			registered = append(registered, candidate)
		}
	}
	if len(registered) != 1 {
		t.Fatalf("cqrplint registrations = %d, want 1", len(registered))
	}
	got := registered[0]
	if got.Version != "v0.2.0" {
		t.Errorf("version = %q, want v0.2.0", got.Version)
	}
	if got.Url != "https://github.com/pkimetal/pkimetal/blob/main/doc/superpowers/specs/2026-08-11-mtc-pkimetal-design.md#source-baselines" {
		t.Errorf("URL = %q", got.Url)
	}
	if got.NumInstances != 1 {
		t.Errorf("instances = %d, want 1", got.NumInstances)
	}

	supported := []linter.ProfileId{linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER}
	for id := range linter.AllProfiles {
		if gotUnsupported := slices.Contains(got.Unsupported, id); gotUnsupported == slices.Contains(supported, id) {
			t.Errorf("profile %s unsupported = %t", linter.AllProfiles[id].Name, gotUnsupported)
		}
	}
}

func TestInstanceLifecycleAndResultProcessing(t *testing.T) {
	handler := &CQRPLint{}
	useHandleRequest, directory, cmd, args := handler.StartInstance()
	if !useHandleRequest || directory != "" || cmd != "" || args != nil {
		t.Fatalf("StartInstance() = %t, %q, %q, %#v", useHandleRequest, directory, cmd, args)
	}
	handler.StopInstance(nil)
	want := linter.LintingResult{Finding: "finding", Field: "field", Code: "code", Severity: linter.SEVERITY_FATAL}
	if got := handler.ProcessResult(want); got != want {
		t.Fatalf("ProcessResult() = %#v, want %#v", got, want)
	}
}

func TestProfilesHandleValidArtifactsAndMutations(t *testing.T) {
	tests := []struct {
		name     string
		profile  linter.ProfileId
		template mtctest.Template
		mutate   func(*mtctest.Template)
		wantCode string
	}{
		{"CA", linter.CQRP_MTC_CA, mtctest.ValidCQRPCATemplate(), func(tpl *mtctest.Template) { tpl.SPKIAlgorithm.OID = mtctest.OIDMLDSA65 }, "e_cqrp_ca_spki_algorithm"},
		{"subscriber", linter.CQRP_MTC_SUBSCRIBER, mtctest.ValidCQRPSubscriberTemplate(), func(tpl *mtctest.Template) { tpl.NotAfter = tpl.NotBefore.Add(48 * 24 * time.Hour) }, "e_cqrp_subscriber_validity_too_long"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := handle(t, tc.profile, parseArtifact(t, tc.template, mtc.InputCertificate)); len(got) != 0 {
				t.Fatalf("valid artifact findings = %#v", got)
			}
			tc.mutate(&tc.template)
			assertHasCode(t, handle(t, tc.profile, parseArtifact(t, tc.template, mtc.InputCertificate)), tc.wantCode)
		})
	}
}

func TestHandlerReturnsOnlyCQRPPolicyFindings(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	tpl.Serial.SetInt64(9)
	tpl.NotAfter = tpl.NotBefore.Add(48 * 24 * time.Hour)
	results := handle(t, linter.CQRP_MTC_SUBSCRIBER, parseArtifact(t, tpl, mtc.InputCertificate))
	assertHasCode(t, results, "e_cqrp_subscriber_validity_too_long")
	assertLacksCode(t, results, "e_mtc_serial_log_number_zero")
	assertLacksCode(t, results, "e_mtc_profile_artifact_mismatch")
}

func TestExpectedProfileKindControlsCQRPPolicyWithoutMutatingArtifact(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	tpl.SPKIAlgorithm.OID = mtctest.OIDMLDSA65
	tpl.SubjectPublicKey = make([]byte, 1952)
	artifact := parseArtifact(t, tpl, mtc.InputCertificate)
	before := fmt.Sprintf("%#v", artifact)
	results := handle(t, linter.CQRP_MTC_CA, artifact)
	assertHasCode(t, results, "e_cqrp_ca_spki_algorithm")
	assertLacksCode(t, results, "e_cqrp_subscriber_validity_too_long")
	assertLacksCode(t, results, "e_mtc_profile_artifact_mismatch")
	if after := fmt.Sprintf("%#v", artifact); after != before {
		t.Fatal("handler mutated caller artifact")
	}
}

func TestUnsupportedNilAndMissingArtifactAreSafe(t *testing.T) {
	handler := &CQRPLint{}
	requests := []*linter.LintingRequest{
		nil,
		{ProfileId: linter.MTC_CA, MTCArtifact: parseArtifact(t, mtctest.ValidCQRPCATemplate(), mtc.InputCertificate)},
		{ProfileId: linter.RFC5280_ROOT, MTCArtifact: parseArtifact(t, mtctest.ValidCQRPCATemplate(), mtc.InputCertificate)},
		{ProfileId: linter.CQRP_MTC_CA},
	}
	for _, req := range requests {
		if got := handler.HandleRequest(context.Background(), nil, req); got != nil {
			t.Errorf("request %#v results = %#v, want nil", req, got)
		}
	}
}

func TestTBSSkipsStandaloneCosignaturePolicy(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	proof := mtctest.ValidProof()
	proof.Signatures = []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: []byte{1}}}
	tpl.Signature = mtctest.ProofBytes(proof)
	results := handle(t, linter.CQRP_MTC_SUBSCRIBER, parseArtifact(t, tpl, mtc.InputTBSCertificate))
	assertLacksCode(t, results, "e_cqrp_subscriber_standalone_cosignatures")
}

func TestResultsAreDeterministic(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	tpl.NotAfter = tpl.NotBefore.Add(48 * 24 * time.Hour)
	mtctest.RemoveExtension(&tpl, mtctest.OIDExtendedKeyUsage)
	artifact := parseArtifact(t, tpl, mtc.InputCertificate)
	first := handle(t, linter.CQRP_MTC_SUBSCRIBER, artifact)
	for i := 0; i < 10; i++ {
		if got := handle(t, linter.CQRP_MTC_SUBSCRIBER, artifact); !reflect.DeepEqual(got, first) {
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
	return (&CQRPLint{}).HandleRequest(context.Background(), nil, req)
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
