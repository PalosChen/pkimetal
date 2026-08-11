package mtc_test

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/mtc"
)

const draft05Source = "draft-ietf-plants-merkle-tree-certs-05"

func TestDraft05ValidArtifactsHaveNoFindings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		kind  mtc.InputKind
	}{
		{"subscriber certificate", mtctest.Certificate(mtctest.ValidSubscriberTemplate()), mtc.InputCertificate},
		{"subscriber TBS", mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), mtc.InputTBSCertificate},
		{"CA certificate", mtctest.Certificate(mtctest.ValidCATemplate()), mtc.InputCertificate},
		{"unsigned CA certificate", mtctest.Certificate(mtctest.ValidUnsignedCATemplate()), mtc.InputCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, tc.input, tc.kind)
			if got := mtc.LintDraft05(artifact); len(got) != 0 {
				t.Fatalf("findings = %#v", got)
			}
		})
	}
}

func TestDraft05CARules(t *testing.T) {
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64)
	tests := []struct {
		name     string
		mutate   func(*mtctest.Template)
		code     string
		severity mtc.Severity
	}{
		{"subject is not CA ID", func(x *mtctest.Template) { x.Subject = mtctest.ValidSubscriberTemplate().Subject }, "e_mtc_ca_subject_not_ca_id", mtc.Error},
		{"MTC CA extension not critical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDMTC_CA, Value: mtctest.ValidCAExtensionDER()})
		}, "e_mtc_ca_extension_not_critical", mtc.Error},
		{"MTC CA extension malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: []byte{0x30, 0x80, 0, 0}})
		}, "f_mtc_ca_extension_malformed", mtc.Fatal},
		{"MTC CA extension duplicated", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: mtctest.ValidCAExtensionDER()})
		}, "f_mtc_ca_extension_malformed", mtc.Fatal},
		{"minimum serial negative", replaceCARange(big.NewInt(-1), big.NewInt(10)), "e_mtc_ca_serial_range_invalid", mtc.Error},
		{"maximum serial negative", replaceCARange(big.NewInt(0), big.NewInt(-1)), "e_mtc_ca_serial_range_invalid", mtc.Error},
		{"maximum serial too large", replaceCARange(big.NewInt(1), tooLarge), "e_mtc_ca_serial_range_invalid", mtc.Error},
		{"serial range reversed", replaceCARange(big.NewInt(10), big.NewInt(9)), "e_mtc_ca_serial_range_invalid", mtc.Error},
		{"key usage missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDKeyUsage) }, "e_mtc_ca_key_usage_missing", mtc.Error},
		{"key cert sign missing", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(false)})
		}, "e_mtc_ca_key_cert_sign_missing", mtc.Error},
		{"key usage malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: []byte{0x03, 0x01, 0x08}})
		}, "e_mtc_ca_key_cert_sign_missing", mtc.Error},
		{"basic constraints missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDBasicConstraints) }, "e_mtc_ca_basic_constraints_missing", mtc.Error},
		{"basic constraints not CA", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(false)})
		}, "e_mtc_ca_basic_constraints_not_ca", mtc.Error},
		{"basic constraints malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: []byte{0x30, 0x01, 0x01}})
		}, "e_mtc_ca_basic_constraints_not_ca", mtc.Error},
		{"SKI is not CA ID", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER([]byte("wrong"))})
		}, "w_mtc_ca_ski_not_ca_id", mtc.Warning},
		{"structurally self-issued", func(x *mtctest.Template) { x.Issuer = append([]byte(nil), x.Subject...) }, "w_mtc_ca_self_issued", mtc.Warning},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
			assertDraftFinding(t, mtc.LintDraft05(artifact), tc.code, tc.severity)
		})
	}
}

func TestLintDraft05ForKindEvaluatesExplicitCAWithoutMutation(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	mtctest.RemoveExtension(&tpl, mtctest.OIDMTC_CA)
	artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
	if artifact.Kind != mtc.ArtifactUnknown {
		t.Fatalf("autodetected kind = %v, want unknown", artifact.Kind)
	}
	assertNoCode(t, mtc.LintDraft05(artifact), "e_mtc_ca_extension_missing")

	originalKind := artifact.Kind
	originalRaw := append([]byte(nil), artifact.Raw...)
	originalTBS := append([]byte(nil), artifact.RawTBS...)
	originalSubject := append([]byte(nil), artifact.SubjectRaw...)
	originalSerial := new(big.Int).Set(artifact.SerialNumber)
	originalExtensions := cloneExtensions(artifact.Extensions)

	findings := mtc.LintDraft05ForKind(artifact, mtc.ArtifactCA)
	assertDraftFinding(t, findings, "e_mtc_ca_extension_missing", mtc.Error)
	if artifact.Kind != originalKind || !bytes.Equal(artifact.Raw, originalRaw) ||
		!bytes.Equal(artifact.RawTBS, originalTBS) || !bytes.Equal(artifact.SubjectRaw, originalSubject) ||
		artifact.SerialNumber.Cmp(originalSerial) != 0 || !reflect.DeepEqual(artifact.Extensions, originalExtensions) {
		t.Fatalf("LintDraft05ForKind mutated caller artifact: %#v", artifact)
	}
}

func TestLintDraft05ForKindHandlesNilAndUnsupportedKind(t *testing.T) {
	if got := mtc.LintDraft05ForKind(nil, mtc.ArtifactCA); got != nil {
		t.Fatalf("nil artifact findings = %#v", got)
	}
	artifact := parseArtifact(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), mtc.InputCertificate)
	if got := mtc.LintDraft05ForKind(artifact, mtc.ArtifactUnknown); got != nil {
		t.Fatalf("unsupported expected kind findings = %#v", got)
	}
	if artifact.Kind != mtc.ArtifactSubscriber {
		t.Fatalf("unsupported expected kind mutated artifact kind to %v", artifact.Kind)
	}
}

func TestLintDraft05ForKindRebuildsSubscriberProofState(t *testing.T) {
	validProof := mtctest.ProofBytes(mtctest.ValidProof())
	tests := []struct {
		name      string
		template  mtctest.Template
		wantCodes []string
	}{
		{
			name:      "unknown with valid proof",
			template:  explicitUnknownSubscriberTemplate(validProof),
			wantCodes: []string{"e_mtc_signature_algorithm_oid", "e_mtc_subscriber_issuer_not_ca_id"},
		},
		{
			name:      "unknown with malformed proof",
			template:  explicitUnknownSubscriberTemplate(mtctest.MalformedProofBytes()),
			wantCodes: []string{"e_mtc_signature_algorithm_oid", "e_mtc_subscriber_issuer_not_ca_id", "f_mtc_proof_malformed"},
		},
		{
			name:      "CA with valid proof",
			template:  explicitCASubscriberTemplate(validProof),
			wantCodes: nil,
		},
		{
			name:      "CA with malformed proof",
			template:  explicitCASubscriberTemplate(mtctest.MalformedProofBytes()),
			wantCodes: []string{"f_mtc_proof_malformed"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, mtctest.Certificate(tc.template), mtc.InputCertificate)
			if artifact.Kind == mtc.ArtifactSubscriber || artifact.Proof != nil || artifact.ProofParseError != nil {
				t.Fatalf("precondition kind/proof/error = %v/%#v/%v", artifact.Kind, artifact.Proof, artifact.ProofParseError)
			}
			findings := lintForKindWithoutMutation(t, artifact, mtc.ArtifactSubscriber)
			assertOnlyCodes(t, findings, tc.wantCodes...)
		})
	}
}

func TestLintDraft05ForKindRunsSubscriberProofSemanticRules(t *testing.T) {
	tpl := explicitCASubscriberTemplate(mtctest.ProofBytes(mtctest.Proof{Start: 4, End: 9}))
	artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
	findings := lintForKindWithoutMutation(t, artifact, mtc.ArtifactSubscriber)
	assertOnlyCodes(t, findings, "e_mtc_proof_subtree_invalid")
}

func TestLintDraft05ForKindDoesNotParseProofForTBS(t *testing.T) {
	tpl := explicitCASubscriberTemplate(mtctest.MalformedProofBytes())
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), mtc.InputTBSCertificate)
	findings := lintForKindWithoutMutation(t, artifact, mtc.ArtifactSubscriber)
	assertOnlyCodes(t, findings)
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
			artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
			assertNoCode(t, mtc.LintDraft05(artifact), "e_mtc_ca_serial_range_invalid")
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
			findings := mtc.LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate))
			if tc.wantFinding {
				assertOnlyCodes(t, findings, "e_mtc_ca_key_cert_sign_missing")
			} else {
				assertOnlyCodes(t, findings)
			}
		})
	}
}

func TestDraft05ValidSKIEncodesCAID(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
		ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER(mtctest.ValidCAID()),
	})
	artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
	assertNoCode(t, mtc.LintDraft05(artifact), "w_mtc_ca_ski_not_ca_id")
}

func TestDraft05SKIWarningRequiresParsedSubjectCAID(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	tpl.Subject = mtctest.ValidSubscriberTemplate().Subject
	tpl.Issuer = mtctest.ValidCAIDNameDER()
	tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
		ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER([]byte("wrong")),
	})
	findings := mtc.LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate))
	assertOnlyCodes(t, findings, "e_mtc_ca_subject_not_ca_id")
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
			findings := mtc.LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate))
			assertOnlyCodes(t, findings)
		})
	}
}

func TestDraft05SubscriberRules(t *testing.T) {
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64)
	tests := []struct {
		name     string
		mutate   func(*mtctest.Template)
		code     string
		severity mtc.Severity
	}{
		{"inner signature algorithm OID", func(x *mtctest.Template) { x.TBSSignature.OID = mtctest.OIDSHA256 }, "e_mtc_signature_algorithm_oid", mtc.Error},
		{"outer signature algorithm OID", func(x *mtctest.Template) { x.OuterSignature.OID = mtctest.OIDSHA256 }, "e_mtc_signature_algorithm_oid", mtc.Error},
		{"inner signature parameters", func(x *mtctest.Template) {
			x.TBSSignature.ParametersPresent, x.TBSSignature.Parameters = true, []byte{0x05, 0x00}
		}, "e_mtc_signature_algorithm_parameters_present", mtc.Error},
		{"outer signature parameters", func(x *mtctest.Template) {
			x.OuterSignature.ParametersPresent, x.OuterSignature.Parameters = true, []byte{0x05, 0x00}
		}, "e_mtc_signature_algorithm_parameters_present", mtc.Error},
		{"inner and outer signature mismatch", func(x *mtctest.Template) {
			x.OuterSignature.ParametersPresent, x.OuterSignature.Parameters = true, []byte{0x05, 0x00}
		}, "e_mtc_cert_signature_algorithm_mismatch", mtc.Error},
		{"signature unused bits", func(x *mtctest.Template) { x.SignatureUnused = 1 }, "e_mtc_signature_value_unused_bits", mtc.Error},
		{"issuer is not CA ID", func(x *mtctest.Template) { x.Issuer = x.Subject }, "e_mtc_subscriber_issuer_not_ca_id", mtc.Error},
		{"serial zero", func(x *mtctest.Template) { x.Serial = big.NewInt(0) }, "e_mtc_serial_non_positive", mtc.Error},
		{"serial negative", func(x *mtctest.Template) { x.Serial = big.NewInt(-1) }, "e_mtc_serial_non_positive", mtc.Error},
		{"serial too large", func(x *mtctest.Template) { x.Serial = tooLarge }, "e_mtc_serial_too_large", mtc.Error},
		{"zero log number", func(x *mtctest.Template) { x.Serial = big.NewInt(7) }, "e_mtc_serial_log_number_zero", mtc.Error},
		{"malformed proof", func(x *mtctest.Template) { x.Signature = mtctest.MalformedProofBytes() }, "f_mtc_proof_malformed", mtc.Fatal},
		{"proof range empty", withProof(func(p *mtctest.Proof) { p.Start, p.End = 7, 7 }), "e_mtc_proof_range_invalid", mtc.Error},
		{"proof range reversed", withProof(func(p *mtctest.Proof) { p.Start, p.End = 8, 7 }), "e_mtc_proof_range_invalid", mtc.Error},
		{"proof subtree invalid", withProof(func(p *mtctest.Proof) { p.Start, p.End = 4, 9 }), "e_mtc_proof_subtree_invalid", mtc.Error},
		{"proof index outside range", func(x *mtctest.Template) {
			x.Serial = new(big.Int).SetUint64((1 << 48) | 9)
			withProof(func(p *mtctest.Proof) { p.Start, p.End = 0, 8 })(x)
		}, "e_mtc_proof_index_outside_range", mtc.Error},
		{"proof extensions out of order", withProof(func(p *mtctest.Proof) {
			p.Extensions = []mtctest.ProofExtension{{Type: 2}, {Type: 1}}
		}), "e_mtc_proof_extensions_order", mtc.Error},
		{"proof extensions duplicate", withProof(func(p *mtctest.Proof) {
			p.Extensions = []mtctest.ProofExtension{{Type: 1}, {Type: 1}}
		}), "e_mtc_proof_extensions_duplicate", mtc.Error},
		{"cosigner ID empty", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{Signature: []byte{1}}}
		}), "e_mtc_proof_cosigner_id_empty", mtc.Error},
		{"cosigners out of length order", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("aa")}, {CosignerID: []byte("b")}}
		}), "e_mtc_proof_cosigner_order", mtc.Error},
		{"cosigners out of lexical order", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("b")}, {CosignerID: []byte("a")}}
		}), "e_mtc_proof_cosigner_order", mtc.Error},
		{"cosigner duplicate", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("a")}, {CosignerID: []byte("a")}}
		}), "e_mtc_proof_cosigner_duplicate", mtc.Error},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidSubscriberTemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
			findings := mtc.LintDraft05(artifact)
			assertDraftFinding(t, findings, tc.code, tc.severity)
			if tc.code == "f_mtc_proof_malformed" {
				for _, finding := range findings {
					if strings.HasPrefix(finding.Code, "e_mtc_proof_") {
						t.Fatalf("malformed proof cascaded to %s", finding.Code)
					}
				}
			}
		})
	}
}

func TestDraft05RepresentativeMutationsHaveExactFindingSets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		template  mtctest.Template
		wantCodes []string
	}{
		{
			name: "CA extension not critical",
			template: mutateTemplate(mtctest.ValidCATemplate(), func(x *mtctest.Template) {
				mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDMTC_CA, Value: mtctest.ValidCAExtensionDER()})
			}),
			wantCodes: []string{"e_mtc_ca_extension_not_critical"},
		},
		{
			name: "CA serial range reversed",
			template: mutateTemplate(mtctest.ValidCATemplate(), func(x *mtctest.Template) {
				replaceCARange(big.NewInt(10), big.NewInt(9))(x)
			}),
			wantCodes: []string{"e_mtc_ca_serial_range_invalid"},
		},
		{
			name: "subscriber serial zero",
			template: mutateTemplate(mtctest.ValidSubscriberTemplate(), func(x *mtctest.Template) {
				x.Serial = big.NewInt(0)
			}),
			wantCodes: []string{"e_mtc_serial_non_positive"},
		},
		{
			name: "subscriber proof malformed",
			template: mutateTemplate(mtctest.ValidSubscriberTemplate(), func(x *mtctest.Template) {
				x.Signature = mtctest.MalformedProofBytes()
			}),
			wantCodes: []string{"f_mtc_proof_malformed"},
		},
		{
			name: "subscriber proof extension duplicate",
			template: mutateTemplate(mtctest.ValidSubscriberTemplate(), withProof(func(p *mtctest.Proof) {
				p.Extensions = []mtctest.ProofExtension{{Type: 1}, {Type: 1}}
			})),
			wantCodes: []string{"e_mtc_proof_extensions_duplicate"},
		},
		{
			name: "unsigned CA signature not empty",
			template: mutateTemplate(mtctest.ValidUnsignedCATemplate(), func(x *mtctest.Template) {
				x.Signature = []byte{1}
			}),
			wantCodes: []string{"e_rfc9925_unsigned_signature_not_empty"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, mtctest.Certificate(tc.template), mtc.InputCertificate)
			assertOnlyCodes(t, mtc.LintDraft05(artifact), tc.wantCodes...)
		})
	}
}

func TestDraft05ProofUint48RangeIsCheckedWithoutCascades(t *testing.T) {
	artifact := parseArtifact(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), mtc.InputCertificate)
	artifact.Proof.End = 1 << 48
	findings := mtc.LintDraft05(artifact)
	assertDraftFinding(t, findings, "e_mtc_proof_range_invalid", mtc.Error)
	assertNoCode(t, findings, "e_mtc_proof_subtree_invalid")
	assertNoCode(t, findings, "e_mtc_proof_index_outside_range")
}

func TestDraft05TBSDoesNotRunOuterOrProofRules(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDSHA256, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
	tpl.Signature = mtctest.MalformedProofBytes()
	tpl.SignatureUnused = 1
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), mtc.InputTBSCertificate)
	for _, code := range []string{
		"e_mtc_cert_signature_algorithm_mismatch",
		"e_mtc_signature_value_unused_bits",
		"f_mtc_proof_malformed",
		"e_mtc_proof_range_invalid",
	} {
		assertNoCode(t, mtc.LintDraft05(artifact), code)
	}
}

func TestDraft05RFC9925UnsignedCARules(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*mtctest.Template)
		code     string
		severity mtc.Severity
		section  string
	}{
		{"algorithm mismatch", func(x *mtctest.Template) { x.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDMLDSA65} }, "e_rfc9925_unsigned_algorithm_mismatch", mtc.Error, "3.1"},
		{"parameters present", func(x *mtctest.Template) {
			x.TBSSignature.ParametersPresent, x.TBSSignature.Parameters = true, []byte{0x05, 0x00}
		}, "e_rfc9925_unsigned_parameters_present", mtc.Error, "3.1"},
		{"signature not empty", func(x *mtctest.Template) { x.Signature = []byte{1} }, "e_rfc9925_unsigned_signature_not_empty", mtc.Error, "3.1"},
		{"issuer unique ID present", func(x *mtctest.Template) { x.IssuerUniqueID = []byte{0x80}; x.IssuerUniqueIDUnused = 7 }, "e_rfc9925_unsigned_issuer_unique_id_present", mtc.Error, "3.2"},
		{"authority key identifier present", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0}})
		}, "w_rfc9925_unsigned_authority_key_identifier_present", mtc.Warning, "3.3"},
		{"issuer alternative name present", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: []byte{0x30, 0}})
		}, "w_rfc9925_unsigned_issuer_alternative_name_present", mtc.Warning, "3.3"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidUnsignedCATemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
			finding := requireFinding(t, mtc.LintDraft05(artifact), tc.code, tc.severity)
			if finding.Source != "RFC 9925" || finding.Section != tc.section {
				t.Fatalf("source/section = %q/%q", finding.Source, finding.Section)
			}
		})
	}
}

func TestDraft05UnsignedRulesApplyToTBSWhenDecidable(t *testing.T) {
	tpl := mtctest.ValidUnsignedCATemplate()
	tpl.TBSSignature.ParametersPresent = true
	tpl.TBSSignature.Parameters = []byte{0x05, 0x00}
	tpl.IssuerUniqueID = []byte{0x80}
	tpl.IssuerUniqueIDUnused = 7
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), mtc.InputTBSCertificate)
	findings := mtc.LintDraft05(artifact)
	requireFinding(t, findings, "e_rfc9925_unsigned_parameters_present", mtc.Error)
	requireFinding(t, findings, "e_rfc9925_unsigned_issuer_unique_id_present", mtc.Error)
	assertNoCode(t, findings, "e_rfc9925_unsigned_algorithm_mismatch")
	assertNoCode(t, findings, "e_rfc9925_unsigned_signature_not_empty")
}

func TestDraft05UnsignedRulesDoNotApplyToSubscribers(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDUnsigned}
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDUnsigned}
	tpl.Signature = nil
	artifact := parseArtifact(t, mtctest.Certificate(tpl), mtc.InputCertificate)
	for _, finding := range mtc.LintDraft05(artifact) {
		if strings.Contains(finding.Code, "rfc9925") {
			t.Fatalf("RFC 9925 finding applied to subscriber: %#v", finding)
		}
	}
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

func mutateTemplate(template mtctest.Template, mutate func(*mtctest.Template)) mtctest.Template {
	mutate(&template)
	return template
}

func parseArtifact(t *testing.T, input []byte, kind mtc.InputKind) *mtc.Artifact {
	t.Helper()
	artifact, err := mtc.Parse(input, kind)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func assertDraftFinding(t *testing.T, findings []mtc.Finding, code string, severity mtc.Severity) {
	t.Helper()
	finding := requireFinding(t, findings, code, severity)
	if finding.Source != draft05Source || finding.Section == "" {
		t.Fatalf("%s source/section = %q/%q", code, finding.Source, finding.Section)
	}
}

func requireFinding(t *testing.T, findings []mtc.Finding, code string, severity mtc.Severity) mtc.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			if finding.Severity != severity {
				t.Fatalf("%s severity = %v, want %v", code, finding.Severity, severity)
			}
			return finding
		}
	}
	t.Fatalf("missing %s in %#v", code, findings)
	return mtc.Finding{}
}

func assertNoCode(t *testing.T, findings []mtc.Finding, code string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			t.Fatalf("unexpected %s in %#v", code, findings)
		}
	}
}

func cloneExtensions(extensions []mtc.Extension) []mtc.Extension {
	cloned := make([]mtc.Extension, len(extensions))
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

func lintForKindWithoutMutation(t *testing.T, artifact *mtc.Artifact, expected mtc.ArtifactKind) []mtc.Finding {
	t.Helper()
	originalKind := artifact.Kind
	originalProof := artifact.Proof
	originalProofError := artifact.ProofParseError
	originalSignature := append([]byte(nil), artifact.SignatureValue...)
	originalExtensions := cloneExtensions(artifact.Extensions)

	findings := mtc.LintDraft05ForKind(artifact, expected)
	if artifact.Kind != originalKind || artifact.Proof != originalProof || artifact.ProofParseError != originalProofError ||
		!bytes.Equal(artifact.SignatureValue, originalSignature) || !reflect.DeepEqual(artifact.Extensions, originalExtensions) {
		t.Fatalf("LintDraft05ForKind mutated caller artifact: %#v", artifact)
	}
	return findings
}

func assertOnlyCodes(t *testing.T, findings []mtc.Finding, want ...string) {
	t.Helper()
	got := make([]string, len(findings))
	for i, finding := range findings {
		got[i] = finding.Code
		var wantSeverity mtc.Severity
		switch {
		case strings.HasPrefix(finding.Code, "w_"):
			wantSeverity = mtc.Warning
		case strings.HasPrefix(finding.Code, "e_"):
			wantSeverity = mtc.Error
		case strings.HasPrefix(finding.Code, "b_"):
			wantSeverity = mtc.Bug
		case strings.HasPrefix(finding.Code, "f_"):
			wantSeverity = mtc.Fatal
		default:
			t.Fatalf("finding code has no stable severity prefix: %#v", finding)
		}
		if finding.Severity != wantSeverity {
			t.Fatalf("%s severity = %v, want %v", finding.Code, finding.Severity, wantSeverity)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("finding codes = %v, want %v; findings = %#v", got, want, findings)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("finding codes = %v, want %v; findings = %#v", got, want, findings)
		}
	}
}
