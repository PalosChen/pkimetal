package mtc

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

type findingExpectation struct {
	Code     string
	Severity Severity
	Field    string
	Source   string
	Section  string
}

var draft05Expectations = map[string]findingExpectation{
	"signature_algorithm_oid_inner":                       {"e_mtc_signature_algorithm_oid", Error, "tbsCertificate.signature", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"signature_algorithm_oid_outer":                       {"e_mtc_signature_algorithm_oid", Error, "signatureAlgorithm", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"signature_algorithm_parameters_present_inner":        {"e_mtc_signature_algorithm_parameters_present", Error, "tbsCertificate.signature.parameters", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"signature_algorithm_parameters_present_outer":        {"e_mtc_signature_algorithm_parameters_present", Error, "signatureAlgorithm.parameters", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_cert_signature_algorithm_mismatch":             {"e_mtc_cert_signature_algorithm_mismatch", Error, "signatureAlgorithm", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_signature_value_unused_bits":                   {"e_mtc_signature_value_unused_bits", Error, "signatureValue", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_ca_subject_not_ca_id":                          {"e_mtc_ca_subject_not_ca_id", Error, "tbsCertificate.subject", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_extension_missing":                          {"e_mtc_ca_extension_missing", Error, "tbsCertificate.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_extension_not_critical":                     {"e_mtc_ca_extension_not_critical", Error, "tbsCertificate.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"f_mtc_ca_extension_malformed":                        {"f_mtc_ca_extension_malformed", Fatal, "tbsCertificate.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_serial_range_invalid":                       {"e_mtc_ca_serial_range_invalid", Error, "tbsCertificate.extensions.mtcCertificationAuthority", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_key_usage_missing":                          {"e_mtc_ca_key_usage_missing", Error, "tbsCertificate.extensions.keyUsage", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_key_cert_sign_missing":                      {"e_mtc_ca_key_cert_sign_missing", Error, "tbsCertificate.extensions.keyUsage", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_basic_constraints_missing":                  {"e_mtc_ca_basic_constraints_missing", Error, "tbsCertificate.extensions.basicConstraints", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_basic_constraints_not_ca":                   {"e_mtc_ca_basic_constraints_not_ca", Error, "tbsCertificate.extensions.basicConstraints", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"w_mtc_ca_ski_not_ca_id":                              {"w_mtc_ca_ski_not_ca_id", Warning, "tbsCertificate.extensions.subjectKeyIdentifier", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"w_mtc_ca_self_issued":                                {"w_mtc_ca_self_issued", Warning, "tbsCertificate.issuer", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_subscriber_issuer_not_ca_id":                   {"e_mtc_subscriber_issuer_not_ca_id", Error, "tbsCertificate.issuer", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_serial_non_positive":                           {"e_mtc_serial_non_positive", Error, "tbsCertificate.serialNumber", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_serial_too_large":                              {"e_mtc_serial_too_large", Error, "tbsCertificate.serialNumber", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_serial_log_number_zero":                        {"e_mtc_serial_log_number_zero", Error, "tbsCertificate.serialNumber", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"f_mtc_proof_malformed":                               {"f_mtc_proof_malformed", Fatal, "signatureValue", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_range_invalid":                           {"e_mtc_proof_range_invalid", Error, "signatureValue.start,end", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_subtree_invalid":                         {"e_mtc_proof_subtree_invalid", Error, "signatureValue.start,end", "draft-ietf-plants-merkle-tree-certs-05", "4.1"},
	"e_mtc_proof_index_outside_range":                     {"e_mtc_proof_index_outside_range", Error, "signatureValue.start,end", "draft-ietf-plants-merkle-tree-certs-05", "4.3.2"},
	"e_mtc_proof_extensions_order":                        {"e_mtc_proof_extensions_order", Error, "signatureValue.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.2.1"},
	"e_mtc_proof_extensions_duplicate":                    {"e_mtc_proof_extensions_duplicate", Error, "signatureValue.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.2.1"},
	"e_mtc_proof_cosigner_id_empty":                       {"e_mtc_proof_cosigner_id_empty", Error, "signatureValue.signatures.cosigner_id", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_cosigner_order":                          {"e_mtc_proof_cosigner_order", Error, "signatureValue.signatures.cosigner_id", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_cosigner_duplicate":                      {"e_mtc_proof_cosigner_duplicate", Error, "signatureValue.signatures.cosigner_id", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_rfc9925_unsigned_algorithm_mismatch":               {"e_rfc9925_unsigned_algorithm_mismatch", Error, "signatureAlgorithm", "RFC 9925", "3.1"},
	"e_rfc9925_unsigned_parameters_present":               {"e_rfc9925_unsigned_parameters_present", Error, "signatureAlgorithm.parameters", "RFC 9925", "3.1"},
	"e_rfc9925_unsigned_signature_not_empty":              {"e_rfc9925_unsigned_signature_not_empty", Error, "signatureValue", "RFC 9925", "3.1"},
	"e_rfc9925_unsigned_issuer_unique_id_present":         {"e_rfc9925_unsigned_issuer_unique_id_present", Error, "tbsCertificate.issuerUniqueID", "RFC 9925", "3.2"},
	"w_rfc9925_unsigned_authority_key_identifier_present": {"w_rfc9925_unsigned_authority_key_identifier_present", Warning, "tbsCertificate.extensions.authorityKeyIdentifier", "RFC 9925", "3.3"},
	"w_rfc9925_unsigned_issuer_alternative_name_present":  {"w_rfc9925_unsigned_issuer_alternative_name_present", Warning, "tbsCertificate.extensions.issuerAlternativeName", "RFC 9925", "3.3"},
}

func TestRuleCoverageDocument(t *testing.T) {
	draftCodes := assertRuleCodeList(t, "draft-05", Draft05RuleCodes)
	cqrpCodes := assertRuleCodeList(t, "CQRP v0.2.0", CQRP020RuleCodes)

	document, err := os.ReadFile("../doc/MTC_RULE_COVERAGE.md")
	if err != nil {
		t.Fatalf("read rule coverage document: %v", err)
	}
	body := string(document)
	codes := append(draftCodes, cqrpCodes...)
	codes = append(codes, "e_mtc_profile_artifact_mismatch", "b_mtc_rule_panic")
	for _, code := range codes {
		if count := strings.Count(body, "`"+code+"`"); count != 1 {
			t.Errorf("coverage document occurrences of %q = %d, want 1", code, count)
		}
	}

	validStatuses := map[string]bool{
		"implemented":           true,
		"delegated":             true,
		"not applicable":        true,
		"not locally decidable": true,
	}
	for lineNumber, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) != 9 {
			t.Errorf("coverage row %d has %d columns, want 7: %s", lineNumber+1, len(columns)-2, line)
			continue
		}
		for _, column := range []int{2, 3, 4, 5, 6} {
			if strings.TrimSpace(columns[column]) == "" {
				t.Errorf("coverage row %d has blank required metadata: %s", lineNumber+1, line)
			}
		}
		status := strings.TrimSpace(columns[7])
		if !validStatuses[status] {
			t.Errorf("coverage row %d has invalid status %q", lineNumber+1, status)
		}
	}
}

func assertRuleCodeList(t *testing.T, name string, list func() []string) []string {
	t.Helper()
	first := list()
	if len(first) == 0 {
		t.Fatalf("%s rule code list is empty", name)
	}
	if !sort.StringsAreSorted(first) {
		t.Errorf("%s rule codes are not sorted: %q", name, first)
	}
	for i, code := range first {
		if code == "" {
			t.Errorf("%s rule code %d is blank", name, i)
		}
		if i > 0 && code == first[i-1] {
			t.Errorf("%s rule code %q is duplicated", name, code)
		}
	}
	want := append([]string(nil), first...)
	first[0] = "caller mutation"
	if got := list(); !reflect.DeepEqual(got, want) {
		t.Errorf("%s rule code list shares caller-mutable storage: got %q, want %q", name, got, want)
	}
	return want
}

func TestDraft05ValidArtifactsHaveNoFindings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		kind  InputKind
	}{
		{"subscriber certificate", mtctest.Certificate(mtctest.ValidSubscriberTemplate()), InputCertificate},
		{"subscriber TBS", mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), InputTBSCertificate},
		{"CA certificate", mtctest.Certificate(mtctest.ValidCATemplate()), InputCertificate},
		{"unsigned CA certificate", mtctest.Certificate(mtctest.ValidUnsignedCATemplate()), InputCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, tc.input, tc.kind)
			assertFindings(t, LintDraft05(artifact))
		})
	}
}

func TestDraft05CARules(t *testing.T) {
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64)
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   string
	}{
		{"subject is not CA ID", func(x *mtctest.Template) {
			x.Subject = mtctest.ValidSubscriberTemplate().Subject
			x.Issuer = mtctest.ValidCAIDNameDER()
		}, "e_mtc_ca_subject_not_ca_id"},
		{"MTC CA extension not critical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDMTC_CA, Value: mtctest.ValidCAExtensionDER()})
		}, "e_mtc_ca_extension_not_critical"},
		{"MTC CA extension malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: []byte{0x30, 0x80, 0, 0}})
		}, "f_mtc_ca_extension_malformed"},
		{"MTC CA extension duplicated", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: mtctest.ValidCAExtensionDER()})
		}, "f_mtc_ca_extension_malformed"},
		{"minimum serial negative", replaceCARange(big.NewInt(-1), big.NewInt(10)), "e_mtc_ca_serial_range_invalid"},
		{"maximum serial negative", replaceCARange(big.NewInt(0), big.NewInt(-1)), "e_mtc_ca_serial_range_invalid"},
		{"maximum serial too large", replaceCARange(big.NewInt(1), tooLarge), "e_mtc_ca_serial_range_invalid"},
		{"serial range reversed", replaceCARange(big.NewInt(10), big.NewInt(9)), "e_mtc_ca_serial_range_invalid"},
		{"key usage missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDKeyUsage) }, "e_mtc_ca_key_usage_missing"},
		{"key cert sign missing", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(false)})
		}, "e_mtc_ca_key_cert_sign_missing"},
		{"key usage malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: []byte{0x03, 0x01, 0x08}})
		}, "e_mtc_ca_key_cert_sign_missing"},
		{"basic constraints missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDBasicConstraints) }, "e_mtc_ca_basic_constraints_missing"},
		{"basic constraints not CA", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(false)})
		}, "e_mtc_ca_basic_constraints_not_ca"},
		{"basic constraints malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: []byte{0x30, 0x01, 0x01}})
		}, "e_mtc_ca_basic_constraints_not_ca"},
		{"SKI is not CA ID", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER([]byte("wrong"))})
		}, "w_mtc_ca_ski_not_ca_id"},
		{"structurally self-issued", func(x *mtctest.Template) { x.Issuer = append([]byte(nil), x.Subject...) }, "w_mtc_ca_self_issued"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact), tc.want)
		})
	}
}

func TestLintDraft05ForKindEvaluatesExplicitCAWithoutMutation(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	mtctest.RemoveExtension(&tpl, mtctest.OIDMTC_CA)
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	if artifact.Kind != ArtifactUnknown {
		t.Fatalf("autodetected kind = %v, want unknown", artifact.Kind)
	}
	assertFindings(t, LintDraft05(artifact))

	originalKind := artifact.Kind
	originalRaw := append([]byte(nil), artifact.Raw...)
	originalTBS := append([]byte(nil), artifact.RawTBS...)
	originalSubject := append([]byte(nil), artifact.SubjectRaw...)
	originalSerial := new(big.Int).Set(artifact.SerialNumber)
	originalExtensions := cloneExtensions(artifact.Extensions)

	findings := LintDraft05ForKind(artifact, ArtifactCA)
	assertFindings(t, findings, "e_mtc_ca_extension_missing")
	if artifact.Kind != originalKind || !bytes.Equal(artifact.Raw, originalRaw) ||
		!bytes.Equal(artifact.RawTBS, originalTBS) || !bytes.Equal(artifact.SubjectRaw, originalSubject) ||
		artifact.SerialNumber.Cmp(originalSerial) != 0 || !reflect.DeepEqual(artifact.Extensions, originalExtensions) {
		t.Fatalf("LintDraft05ForKind mutated caller artifact: %#v", artifact)
	}
}

func TestLintDraft05ForKindHandlesNilAndUnsupportedKind(t *testing.T) {
	if got := LintDraft05ForKind(nil, ArtifactCA); got != nil {
		t.Fatalf("nil artifact findings = %#v", got)
	}
	artifact := parseArtifact(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), InputCertificate)
	if got := LintDraft05ForKind(artifact, ArtifactUnknown); got != nil {
		t.Fatalf("unsupported expected kind findings = %#v", got)
	}
	if artifact.Kind != ArtifactSubscriber {
		t.Fatalf("unsupported expected kind mutated artifact kind to %v", artifact.Kind)
	}
}

func TestLintDraft05ForKindRebuildsSubscriberProofState(t *testing.T) {
	validProof := mtctest.ProofBytes(mtctest.ValidProof())
	tests := []struct {
		name     string
		template mtctest.Template
		want     []string
	}{
		{
			name:     "unknown with valid proof",
			template: explicitUnknownSubscriberTemplate(validProof),
			want:     []string{"signature_algorithm_oid_inner", "e_mtc_subscriber_issuer_not_ca_id"},
		},
		{
			name:     "unknown with malformed proof",
			template: explicitUnknownSubscriberTemplate(mtctest.MalformedProofBytes()),
			want:     []string{"signature_algorithm_oid_inner", "e_mtc_subscriber_issuer_not_ca_id", "f_mtc_proof_malformed"},
		},
		{
			name:     "CA with valid proof",
			template: explicitCASubscriberTemplate(validProof),
			want:     nil,
		},
		{
			name:     "CA with malformed proof",
			template: explicitCASubscriberTemplate(mtctest.MalformedProofBytes()),
			want:     []string{"f_mtc_proof_malformed"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, mtctest.Certificate(tc.template), InputCertificate)
			if artifact.Kind == ArtifactSubscriber || artifact.Proof != nil || artifact.ProofParseError != nil {
				t.Fatalf("precondition kind/proof/error = %v/%#v/%v", artifact.Kind, artifact.Proof, artifact.ProofParseError)
			}
			findings := lintForKindWithoutMutation(t, artifact, ArtifactSubscriber)
			assertFindings(t, findings, tc.want...)
		})
	}
}

func TestLintDraft05ForKindRunsSubscriberProofSemanticRules(t *testing.T) {
	tpl := explicitCASubscriberTemplate(mtctest.ProofBytes(mtctest.Proof{Start: 4, End: 9}))
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	findings := lintForKindWithoutMutation(t, artifact, ArtifactSubscriber)
	assertFindings(t, findings, "e_mtc_proof_subtree_invalid")
}

func TestLintDraft05ForKindDoesNotParseProofForTBS(t *testing.T) {
	tpl := explicitCASubscriberTemplate(mtctest.MalformedProofBytes())
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), InputTBSCertificate)
	findings := lintForKindWithoutMutation(t, artifact, ArtifactSubscriber)
	assertFindings(t, findings)
}

func TestDraft05CASerialRangeBoundaries(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	for _, tc := range []struct {
		name     string
		min, max *big.Int
	}{
		{"zero range", big.NewInt(0), big.NewInt(0)},
		{"zero through maximum", big.NewInt(0), max},
		{"positive singleton", big.NewInt(1), big.NewInt(1)},
		{"maximum singleton", max, max},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			replaceCARange(tc.min, tc.max)(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact))
		})
	}
}

func TestDraft05KeyUsageNamedBitListCanonicality(t *testing.T) {
	for _, tc := range []struct {
		name        string
		value       []byte
		wantFinding bool
	}{
		{"single keyCertSign bit", []byte{0x03, 0x02, 0x02, 0x04}, false},
		{"multiple first-octet bits", []byte{0x03, 0x02, 0x02, 0x84}, false},
		{"multiple octets", []byte{0x03, 0x03, 0x07, 0x04, 0x80}, false},
		{"trailing zero octet", []byte{0x03, 0x03, 0x00, 0x04, 0x00}, true},
		{"nonminimal unused count", []byte{0x03, 0x02, 0x00, 0x04}, true},
		{"nonzero unused bits", []byte{0x03, 0x02, 0x03, 0x04}, true},
		{"invalid unused count", []byte{0x03, 0x01, 0x08}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: tc.value})
			findings := LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate))
			if tc.wantFinding {
				assertFindings(t, findings, "e_mtc_ca_key_cert_sign_missing")
			} else {
				assertFindings(t, findings)
			}
		})
	}
}

func TestDraft05ValidSKIEncodesCAID(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
		ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER(mtctest.ValidCAID()),
	})
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	assertFindings(t, LintDraft05(artifact))
}

func TestDraft05SKIWarningRequiresParsedSubjectCAID(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	tpl.Subject = mtctest.ValidSubscriberTemplate().Subject
	tpl.Issuer = mtctest.ValidCAIDNameDER()
	tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
		ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER([]byte("wrong")),
	})
	findings := LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate))
	assertFindings(t, findings, "e_mtc_ca_subject_not_ca_id")
}

func TestDraft05DuplicateCAExtensionContentChecksAreOrderIndependent(t *testing.T) {
	goodKeyUsage := mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)}
	badKeyUsage := mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(false)}
	goodBasicConstraints := mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(true)}
	badBasicConstraints := mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(false)}
	for _, tc := range []struct {
		name       string
		oid        asn1.ObjectIdentifier
		extensions []mtctest.Extension
	}{
		{"key usage good then bad", mtctest.OIDKeyUsage, []mtctest.Extension{goodKeyUsage, badKeyUsage}},
		{"key usage bad then good", mtctest.OIDKeyUsage, []mtctest.Extension{badKeyUsage, goodKeyUsage}},
		{"basic constraints good then bad", mtctest.OIDBasicConstraints, []mtctest.Extension{goodBasicConstraints, badBasicConstraints}},
		{"basic constraints bad then good", mtctest.OIDBasicConstraints, []mtctest.Extension{badBasicConstraints, goodBasicConstraints}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			mtctest.RemoveExtension(&tpl, tc.oid)
			tpl.Extensions = append(tpl.Extensions, tc.extensions...)
			findings := LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate))
			assertFindings(t, findings)
		})
	}
}

func TestDraft05SubscriberRules(t *testing.T) {
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64)
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"inner signature algorithm OID", func(x *mtctest.Template) { x.TBSSignature.OID = mtctest.OIDSHA256 }, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_oid_inner"}},
		{"outer signature algorithm OID", func(x *mtctest.Template) { x.OuterSignature.OID = mtctest.OIDSHA256 }, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_oid_outer"}},
		{"inner signature parameters", func(x *mtctest.Template) {
			x.TBSSignature.ParametersPresent, x.TBSSignature.Parameters = true, []byte{0x05, 0x00}
		}, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_parameters_present_inner"}},
		{"outer signature parameters", func(x *mtctest.Template) {
			x.OuterSignature.ParametersPresent, x.OuterSignature.Parameters = true, []byte{0x05, 0x00}
		}, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_parameters_present_outer"}},
		{"inner and outer signature mismatch", func(x *mtctest.Template) {
			x.OuterSignature.ParametersPresent, x.OuterSignature.Parameters = true, []byte{0x05, 0x00}
		}, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_parameters_present_outer"}},
		{"signature unused bits", func(x *mtctest.Template) { x.SignatureUnused = 1 }, []string{"e_mtc_signature_value_unused_bits"}},
		{"issuer is not CA ID", func(x *mtctest.Template) { x.Issuer = x.Subject }, []string{"e_mtc_subscriber_issuer_not_ca_id"}},
		{"serial zero", func(x *mtctest.Template) { x.Serial = big.NewInt(0) }, []string{"e_mtc_serial_non_positive"}},
		{"serial negative", func(x *mtctest.Template) { x.Serial = big.NewInt(-1) }, []string{"e_mtc_serial_non_positive"}},
		{"serial too large", func(x *mtctest.Template) { x.Serial = tooLarge }, []string{"e_mtc_serial_too_large"}},
		{"zero log number", func(x *mtctest.Template) { x.Serial = big.NewInt(7) }, []string{"e_mtc_serial_log_number_zero"}},
		{"malformed proof", func(x *mtctest.Template) { x.Signature = mtctest.MalformedProofBytes() }, []string{"f_mtc_proof_malformed"}},
		{"proof range empty", withProof(func(p *mtctest.Proof) { p.Start, p.End = 7, 7 }), []string{"e_mtc_proof_range_invalid"}},
		{"proof range reversed", withProof(func(p *mtctest.Proof) { p.Start, p.End = 8, 7 }), []string{"e_mtc_proof_range_invalid"}},
		{"proof subtree invalid", withProof(func(p *mtctest.Proof) { p.Start, p.End = 4, 9 }), []string{"e_mtc_proof_subtree_invalid"}},
		{"proof index outside range", func(x *mtctest.Template) {
			x.Serial = new(big.Int).SetUint64((1 << 48) | 9)
			withProof(func(p *mtctest.Proof) { p.Start, p.End = 0, 8 })(x)
		}, []string{"e_mtc_proof_index_outside_range"}},
		{"proof extensions out of order", withProof(func(p *mtctest.Proof) {
			p.Extensions = []mtctest.ProofExtension{{Type: 2}, {Type: 1}}
		}), []string{"e_mtc_proof_extensions_order"}},
		{"proof extensions duplicate", withProof(func(p *mtctest.Proof) {
			p.Extensions = []mtctest.ProofExtension{{Type: 1}, {Type: 1}}
		}), []string{"e_mtc_proof_extensions_duplicate"}},
		{"cosigner ID empty", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{Signature: []byte{1}}}
		}), []string{"e_mtc_proof_cosigner_id_empty"}},
		{"cosigners out of length order", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("aa")}, {CosignerID: []byte("b")}}
		}), []string{"e_mtc_proof_cosigner_order"}},
		{"cosigners out of lexical order", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("b")}, {CosignerID: []byte("a")}}
		}), []string{"e_mtc_proof_cosigner_order"}},
		{"cosigner duplicate", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("a")}, {CosignerID: []byte("a")}}
		}), []string{"e_mtc_proof_cosigner_duplicate"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidSubscriberTemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact), tc.want...)
		})
	}
}

func TestDraft05ProofUint48RangeIsCheckedWithoutCascades(t *testing.T) {
	artifact := parseArtifact(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), InputCertificate)
	artifact.Proof.End = 1 << 48
	assertFindings(t, LintDraft05(artifact), "e_mtc_proof_range_invalid")
}

func TestDraft05TBSDoesNotRunOuterOrProofRules(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDSHA256, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
	tpl.Signature = mtctest.MalformedProofBytes()
	tpl.SignatureUnused = 1
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), InputTBSCertificate)
	assertFindings(t, LintDraft05(artifact))
}

func TestDraft05RFC9925UnsignedCARules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   string
	}{
		{"algorithm mismatch", func(x *mtctest.Template) { x.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDMLDSA65} }, "e_rfc9925_unsigned_algorithm_mismatch"},
		{"parameters present", func(x *mtctest.Template) {
			x.TBSSignature.ParametersPresent, x.TBSSignature.Parameters = true, []byte{0x05, 0x00}
		}, "e_rfc9925_unsigned_parameters_present"},
		{"signature not empty", func(x *mtctest.Template) { x.Signature = []byte{1} }, "e_rfc9925_unsigned_signature_not_empty"},
		{"issuer unique ID present", func(x *mtctest.Template) { x.IssuerUniqueID = []byte{0x80}; x.IssuerUniqueIDUnused = 7 }, "e_rfc9925_unsigned_issuer_unique_id_present"},
		{"authority key identifier present", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0}})
		}, "w_rfc9925_unsigned_authority_key_identifier_present"},
		{"issuer alternative name present", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: []byte{0x30, 0}})
		}, "w_rfc9925_unsigned_issuer_alternative_name_present"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidUnsignedCATemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact), tc.want)
		})
	}
}

func TestDraft05UnsignedRulesApplyToTBSWhenDecidable(t *testing.T) {
	tpl := mtctest.ValidUnsignedCATemplate()
	tpl.TBSSignature.ParametersPresent = true
	tpl.TBSSignature.Parameters = []byte{0x05, 0x00}
	tpl.IssuerUniqueID = []byte{0x80}
	tpl.IssuerUniqueIDUnused = 7
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), InputTBSCertificate)
	assertFindings(t, LintDraft05(artifact),
		"e_rfc9925_unsigned_issuer_unique_id_present",
		"e_rfc9925_unsigned_parameters_present",
	)
}

func TestDraft05UnsignedRulesDoNotApplyToSubscribers(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDUnsigned}
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDUnsigned}
	tpl.Signature = nil
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	assertFindings(t, LintDraft05(artifact), "signature_algorithm_oid_inner", "f_mtc_proof_malformed")
}

func replaceCARange(min, max *big.Int) func(*mtctest.Template) {
	return func(tpl *mtctest.Template) {
		mtctest.ReplaceExtension(tpl, mtctest.Extension{
			ID:       mtctest.OIDMTC_CA,
			Critical: true,
			Value: mtctest.CAExtensionDER(
				mtctest.Algorithm{OID: mtctest.OIDSHA256},
				mtctest.Algorithm{OID: mtctest.OIDMLDSA65},
				min, max,
			),
		})
	}
}

func withProof(mutate func(*mtctest.Proof)) func(*mtctest.Template) {
	return func(tpl *mtctest.Template) {
		proof := mtctest.ValidProof()
		mutate(&proof)
		tpl.Signature = mtctest.ProofBytes(proof)
	}
}

func parseArtifact(t *testing.T, input []byte, kind InputKind) *Artifact {
	t.Helper()
	artifact, err := Parse(input, kind)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func cloneExtensions(extensions []Extension) []Extension {
	cloned := make([]Extension, len(extensions))
	for i, extension := range extensions {
		cloned[i] = extension
		cloned[i].Raw = append([]byte(nil), extension.Raw...)
		cloned[i].ID = append(asn1.ObjectIdentifier(nil), extension.ID...)
		cloned[i].Value = append([]byte(nil), extension.Value...)
	}
	return cloned
}

func explicitUnknownSubscriberTemplate(signature []byte) mtctest.Template {
	tpl := mtctest.ValidCATemplate()
	mtctest.RemoveExtension(&tpl, mtctest.OIDMTC_CA)
	tpl.Serial = new(big.Int).SetUint64((1 << 48) | 7)
	tpl.Signature = append([]byte(nil), signature...)
	return tpl
}

func explicitCASubscriberTemplate(signature []byte) mtctest.Template {
	tpl := mtctest.ValidCATemplate()
	tpl.Serial = new(big.Int).SetUint64((1 << 48) | 7)
	tpl.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDMTCProof}
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDMTCProof}
	tpl.Issuer = mtctest.ValidCAIDNameDER()
	tpl.Signature = append([]byte(nil), signature...)
	return tpl
}

func lintForKindWithoutMutation(t *testing.T, artifact *Artifact, expected ArtifactKind) []Finding {
	t.Helper()
	originalKind := artifact.Kind
	originalProof := artifact.Proof
	originalProofError := artifact.ProofParseError
	originalSignature := append([]byte(nil), artifact.SignatureValue...)
	originalExtensions := cloneExtensions(artifact.Extensions)

	findings := LintDraft05ForKind(artifact, expected)
	if artifact.Kind != originalKind || artifact.Proof != originalProof || artifact.ProofParseError != originalProofError ||
		!bytes.Equal(artifact.SignatureValue, originalSignature) || !reflect.DeepEqual(artifact.Extensions, originalExtensions) {
		t.Fatalf("LintDraft05ForKind mutated caller artifact: %#v", artifact)
	}
	return findings
}

func assertFindings(t *testing.T, findings []Finding, expectationIDs ...string) {
	t.Helper()
	want := make([]findingExpectation, len(expectationIDs))
	for i, id := range expectationIDs {
		expectation, ok := draft05Expectations[id]
		if !ok {
			t.Fatalf("unknown finding expectation %q", id)
		}
		want[i] = expectation
	}
	sort.SliceStable(want, func(i, j int) bool { return want[i].Code < want[j].Code })

	got := make([]findingExpectation, len(findings))
	for i, finding := range findings {
		got[i] = findingExpectation{
			Code: finding.Code, Severity: finding.Severity, Field: finding.Field,
			Source: finding.Source, Section: finding.Section,
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding tuples = %#v, want %#v; findings = %#v", got, want, findings)
	}
}
