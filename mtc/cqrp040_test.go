package mtc

import (
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

func TestCQRP040LogRangeAndHistoricalPolicy(t *testing.T) {
	for _, logNumber := range []uint64{4, 5, 6} {
		tpl := mtctest.ValidCQRPSubscriberTemplate()
		tpl.Serial.SetUint64(logNumber<<48 | 7)
		artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
		current := LintCQRP040ForKind(artifact, ArtifactSubscriber)
		found := false
		for _, finding := range current {
			if finding.Code == "e_cqrp_subscriber_log_number_not_trusted" {
				found = true
				if finding.Source != cqrp040Source || finding.Section != "2.5.1.3" {
					t.Fatalf("log %d finding = %#v", logNumber, finding)
				}
			}
		}
		if found != (logNumber > 5) {
			t.Errorf("v0.4.0 log %d rejected = %t", logNumber, found)
		}
		if logNumber == 5 {
			legacy := LintCQRP030ForKind(artifact, ArtifactSubscriber)
			if !hasFindingCode(legacy, "e_cqrp_subscriber_log_number_not_trusted") {
				t.Fatal("v0.3.0 no longer rejects log 5")
			}
		}
	}
}

func TestCQRP040CARequiresCrlSign(t *testing.T) {
	tpl := mtctest.ValidCQRP040CATemplate()
	for _, kind := range []InputKind{InputCertificate, InputTBSCertificate} {
		input := mtctest.Certificate(tpl)
		if kind == InputTBSCertificate {
			input = mtctest.TBSCertificate(tpl)
		}
		if findings := LintCQRP040ForKind(parseArtifact(t, input, kind), ArtifactCA); len(findings) != 0 {
			t.Fatalf("valid CA kind %d findings = %#v", kind, findings)
		}
	}
	mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)})
	for _, kind := range []InputKind{InputCertificate, InputTBSCertificate} {
		input := mtctest.Certificate(tpl)
		if kind == InputTBSCertificate {
			input = mtctest.TBSCertificate(tpl)
		}
		artifact := parseArtifact(t, input, kind)
		if !hasFindingCode(LintCQRP040ForKind(artifact, ArtifactCA), "e_cqrp_ca_key_usage_missing_crl_sign") {
			t.Fatalf("v0.4.0 accepted CA kind %d without cRLSign", kind)
		}
		if hasFindingCode(LintCQRP030ForKind(artifact, ArtifactCA), "e_cqrp_ca_key_usage_missing_crl_sign") {
			t.Fatal("v0.3.0 behavior changed")
		}
	}
	mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x0200)})
	if !hasFindingCode(LintCQRP040ForKind(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate), ArtifactCA), "e_cqrp_ca_key_usage_missing_key_cert_sign") {
		t.Fatal("v0.4.0 accepted CA without keyCertSign")
	}
	mtctest.RemoveExtension(&tpl, mtctest.OIDKeyUsage)
	if !hasFindingCode(LintCQRP040ForKind(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate), ArtifactCA), "e_cqrp_ca_key_usage_missing_crl_sign") {
		t.Fatal("v0.4.0 accepted CA without keyUsage")
	}
	mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: []byte{0x03, 0x00}})
	if !hasFindingCode(LintCQRP040ForKind(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate), ArtifactCA), "e_cqrp_ca_key_usage_missing_crl_sign") {
		t.Fatal("v0.4.0 accepted malformed CA keyUsage")
	}
	subscriber := parseArtifact(t, mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate()), InputCertificate)
	if hasFindingCode(LintCQRP040ForKind(subscriber, ArtifactSubscriber), "e_cqrp_ca_key_usage_missing_crl_sign") {
		t.Fatal("CA rule applied to subscriber")
	}
}

func hasFindingCode(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
