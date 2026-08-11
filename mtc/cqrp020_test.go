package mtc

import (
	"bytes"
	"encoding/asn1"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

var cqrp020Expectations = map[string]findingExpectation{
	"e_cqrp_ca_spki_algorithm":                   {"e_cqrp_ca_spki_algorithm", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_spki_parameters_present":          {"e_cqrp_ca_spki_parameters_present", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_spki_encoding":                    {"e_cqrp_ca_spki_encoding", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_hash_mldsa":                       {"e_cqrp_ca_hash_mldsa", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_key_usage_not_critical":           {"e_cqrp_ca_key_usage_not_critical", Error, "tbsCertificate.extensions.keyUsage", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_subscriber_validity_too_long":        {"e_cqrp_subscriber_validity_too_long", Error, "tbsCertificate.validity", "CQRP v0.2.0", "2.1"},
	"e_cqrp_subscriber_mldsa_parameters_present": {"e_cqrp_subscriber_mldsa_parameters_present", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_mldsa_encoding":           {"e_cqrp_subscriber_mldsa_encoding", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_hash_mldsa":               {"e_cqrp_subscriber_hash_mldsa", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_dv_subject_not_empty":     {"e_cqrp_subscriber_dv_subject_not_empty", Error, "tbsCertificate.subject", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_policies_missing":         {"e_cqrp_subscriber_policies_missing", Error, "tbsCertificate.extensions.certificatePolicies", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_policies_critical":        {"e_cqrp_subscriber_policies_critical", Error, "tbsCertificate.extensions.certificatePolicies", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_policy_identifier":        {"e_cqrp_subscriber_policy_identifier", Error, "tbsCertificate.extensions.certificatePolicies", "CQRP v0.2.0", "4.5.2"},
	"w_cqrp_subscriber_policy_not_dv":            {"w_cqrp_subscriber_policy_not_dv", Warning, "tbsCertificate.extensions.certificatePolicies", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_eku_missing":              {"e_cqrp_subscriber_eku_missing", Error, "tbsCertificate.extensions.extKeyUsage", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_eku_critical":             {"e_cqrp_subscriber_eku_critical", Error, "tbsCertificate.extensions.extKeyUsage", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_eku_only_server_auth":     {"e_cqrp_subscriber_eku_only_server_auth", Error, "tbsCertificate.extensions.extKeyUsage", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_ian_critical":             {"e_cqrp_subscriber_ian_critical", Error, "tbsCertificate.extensions.issuerAlternativeName", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_ian_form":                 {"e_cqrp_subscriber_ian_form", Error, "tbsCertificate.extensions.issuerAlternativeName", "CQRP v0.2.0", "4.5.2"},
	"w_cqrp_subscriber_ian_name_attributes":      {"w_cqrp_subscriber_ian_name_attributes", Warning, "tbsCertificate.extensions.issuerAlternativeName", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_sct_present":              {"e_cqrp_subscriber_sct_present", Error, "tbsCertificate.extensions.signedCertificateTimestampList", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_standalone_cosignatures":  {"e_cqrp_subscriber_standalone_cosignatures", Error, "signatureValue.signatures", "CQRP v0.2.0", "4.7"},
}

func TestCQRP020ValidArtifactsHaveNoFindings(t *testing.T) {
	tests := []struct {
		name string
		tpl  mtctest.Template
		kind InputKind
	}{
		{"CA certificate", mtctest.ValidCQRPCATemplate(), InputCertificate},
		{"CA TBS", mtctest.ValidCQRPCATemplate(), InputTBSCertificate},
		{"subscriber certificate", mtctest.ValidCQRPSubscriberTemplate(), InputCertificate},
		{"subscriber TBS", mtctest.ValidCQRPSubscriberTemplate(), InputTBSCertificate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var input []byte
			if tc.kind == InputCertificate {
				input = mtctest.Certificate(tc.tpl)
			} else {
				input = mtctest.TBSCertificate(tc.tpl)
			}
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, input, tc.kind)))
		})
	}
}

func TestCQRP020CARules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"wrong algorithm", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA65} }, []string{"e_cqrp_ca_spki_algorithm"}},
		{"parameters and encoding", func(x *mtctest.Template) {
			x.SPKIAlgorithm.ParametersPresent = true
			x.SPKIAlgorithm.Parameters = []byte{0x05, 0x00}
		}, []string{"e_cqrp_ca_spki_encoding", "e_cqrp_ca_spki_parameters_present"}},
		{"HashML-DSA 44", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA44, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
		}, []string{"e_cqrp_ca_hash_mldsa"}},
		{"HashML-DSA 65", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA65} }, []string{"e_cqrp_ca_hash_mldsa"}},
		{"HashML-DSA 87", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA87} }, []string{"e_cqrp_ca_hash_mldsa"}},
		{"key usage noncritical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Value: mtctest.KeyUsageDER(true)})
		}, []string{"e_cqrp_ca_key_usage_not_critical"}},
		{"key usage absent delegated to draft", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDKeyUsage) }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPCATemplate()
			tc.mutate(&tpl)
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)), tc.want...)
		})
	}
}

func TestCQRP020SubscriberSPKIAndValidity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"47 days allowed", func(x *mtctest.Template) { x.NotAfter = x.NotBefore.Add(47 * 24 * time.Hour) }, nil},
		{"48 days rejected", func(x *mtctest.Template) { x.NotAfter = x.NotBefore.Add(48 * 24 * time.Hour) }, []string{"e_cqrp_subscriber_validity_too_long"}},
		{"traditional RSA delegated", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDRSAEncryption, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
		}, nil},
		{"unknown traditional delegated", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: asn1.ObjectIdentifier{1, 2, 3, 4}} }, nil},
		{"ML-DSA-44 exact", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA44} }, nil},
		{"ML-DSA-65 exact", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA65} }, nil},
		{"ML-DSA-87 exact", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA87} }, nil},
		{"ML-DSA parameters and encoding", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA65, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
		}, []string{"e_cqrp_subscriber_mldsa_encoding", "e_cqrp_subscriber_mldsa_parameters_present"}},
		{"HashML-DSA 44 dedicated", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA44, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
		}, []string{"e_cqrp_subscriber_hash_mldsa"}},
		{"HashML-DSA 65 dedicated", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA65} }, []string{"e_cqrp_subscriber_hash_mldsa"}},
		{"HashML-DSA 87 dedicated", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA87} }, []string{"e_cqrp_subscriber_hash_mldsa"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)), tc.want...)
		})
	}
}

func TestCQRP020SubscriberPolicies(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDCertificatePolicies) }, []string{"e_cqrp_subscriber_policies_missing"}},
		{"critical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Critical: true, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV)})
		}, []string{"e_cqrp_subscriber_policies_critical"}},
		{"empty", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: []byte{0x30, 0x00}})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"malformed policy information", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: []byte{0x30, 0x02, 0x30, 0x00}})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"malformed policy qualifier", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: []byte{0x30, 0x0f, 0x30, 0x0d, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01, 0x30, 0x03, 0x02, 0x01, 0x01}})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"unreserved identifier", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(asn1.ObjectIdentifier{1, 2, 3, 4})})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"DV subject nonempty", func(x *mtctest.Template) {
			x.Subject = mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "example"})
		}, []string{"e_cqrp_subscriber_dv_subject_not_empty"}},
		{"OV warning and nonempty subject allowed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyOV)})
			x.Subject = mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, Value: "Example"})
		}, []string{"w_cqrp_subscriber_policy_not_dv"}},
		{"IV warning", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
		}, []string{"w_cqrp_subscriber_policy_not_dv"}},
		{"multiple allowed with non-DV warning", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV, mtctest.OIDPolicyOV)})
		}, []string{"w_cqrp_subscriber_policy_not_dv"}},
		{"multiple including invalid", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV, asn1.ObjectIdentifier{1, 2, 3})})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)), tc.want...)
		})
	}
}

func TestCQRP020SubscriberEKU(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDExtendedKeyUsage) }, []string{"e_cqrp_subscriber_eku_missing"}},
		{"critical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Critical: true, Value: mtctest.ExtendedKeyUsageDER(mtctest.OIDServerAuth)})
		}, []string{"e_cqrp_subscriber_eku_critical"}},
		{"empty", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: mtctest.ExtendedKeyUsageDER()})
		}, []string{"e_cqrp_subscriber_eku_only_server_auth"}},
		{"extra", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: mtctest.ExtendedKeyUsageDER(mtctest.OIDServerAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2})})
		}, []string{"e_cqrp_subscriber_eku_only_server_auth"}},
		{"duplicate ID", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: mtctest.ExtendedKeyUsageDER(mtctest.OIDServerAuth, mtctest.OIDServerAuth)})
		}, []string{"e_cqrp_subscriber_eku_only_server_auth"}},
		{"malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: []byte{0x30, 0x01, 0x00}})
		}, []string{"e_cqrp_subscriber_eku_only_server_auth"}},
		{"duplicate extension deferred", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: mtctest.ExtendedKeyUsageDER(asn1.ObjectIdentifier{1, 2, 3})})
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)), tc.want...)
		})
	}
}

func TestCQRP020SubscriberIANAndSCT(t *testing.T) {
	validName := mtctest.NameDER(
		mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, Value: "Example"},
		mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "Example Issuer"},
	)
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"valid O and CN", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(validName))})
		}, nil},
		{"critical", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Critical: true, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(validName))})
		}, []string{"e_cqrp_subscriber_ian_critical"}},
		{"empty GeneralNames", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: []byte{0x30, 0x00}})
		}, []string{"e_cqrp_subscriber_ian_form"}},
		{"DNS form", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: []byte{0x30, 0x0d, 0x82, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}})
		}, []string{"e_cqrp_subscriber_ian_form"}},
		{"malformed directoryName", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER([]byte{0xa4, 0x02, 0x30, 0x00})})
		}, []string{"e_cqrp_subscriber_ian_form"}},
		{"other attribute warning", func(x *mtctest.Template) {
			name := mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "US"})
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(name))})
		}, []string{"w_cqrp_subscriber_ian_name_attributes"}},
		{"malformed form suppresses name warning", func(x *mtctest.Template) {
			name := mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "US"})
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(name), []byte{0x82, 0x01, 'x'})})
		}, []string{"e_cqrp_subscriber_ian_form"}},
		{"duplicate IAN deferred", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Critical: true, Value: []byte{0x30, 0x00}}, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(validName))})
		}, nil},
		{"SCT present", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSCTList, Value: []byte{0x00}})
		}, []string{"e_cqrp_subscriber_sct_present"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)), tc.want...)
		})
	}
}

func TestCQRP020StandaloneCosignatures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		signatures []mtctest.ProofSignature
		kind       InputKind
		want       []string
	}{
		{"landmark zero valid", nil, InputCertificate, nil},
		{"standalone one rejected", []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: []byte{1}}}, InputCertificate, []string{"e_cqrp_subscriber_standalone_cosignatures"}},
		{"standalone two valid", []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: []byte{1}}, {CosignerID: []byte{2}, Signature: []byte{2}}}, InputCertificate, nil},
		{"TBS skips proof", []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: []byte{1}}}, InputTBSCertificate, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			proof := mtctest.ValidProof()
			proof.Signatures = tc.signatures
			tpl.Signature = mtctest.ProofBytes(proof)
			var input []byte
			if tc.kind == InputCertificate {
				input = mtctest.Certificate(tpl)
			} else {
				input = mtctest.TBSCertificate(tpl)
			}
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, input, tc.kind)), tc.want...)
		})
	}
}

func TestCQRP020ApplicabilityAndIndependence(t *testing.T) {
	ca := parseArtifact(t, mtctest.Certificate(mtctest.ValidCQRPCATemplate()), InputCertificate)
	ca.Kind = ArtifactSubscriber
	assertCQRPFindings(t, LintCQRP020ForKind(ca, ArtifactCA))
	if ca.Kind != ArtifactSubscriber {
		t.Fatal("LintCQRP020ForKind mutated caller kind")
	}

	subscriber := parseArtifact(t, mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate()), InputCertificate)
	originalProof := subscriber.Proof
	originalProofErr := subscriber.ProofParseError
	originalSignature := bytes.Clone(subscriber.SignatureValue)
	assertCQRPFindings(t, LintCQRP020ForKind(subscriber, ArtifactSubscriber))
	if subscriber.Proof != originalProof || subscriber.ProofParseError != originalProofErr || !bytes.Equal(subscriber.SignatureValue, originalSignature) {
		t.Fatal("LintCQRP020ForKind mutated caller proof state")
	}
	if got := LintCQRP020ForKind(subscriber, ArtifactUnknown); got != nil {
		t.Fatalf("unsupported kind = %#v", got)
	}
	if got := LintCQRP020ForKind(nil, ArtifactSubscriber); got != nil {
		t.Fatalf("nil artifact = %#v", got)
	}

	tpl := mtctest.ValidCQRPSubscriberTemplate()
	tpl.TBSSignature = mtctest.Algorithm{OID: asn1.ObjectIdentifier{1, 2, 3}}
	tpl.OuterSignature = tpl.TBSSignature
	assertCQRPFindings(t, LintCQRP020ForKind(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate), ArtifactSubscriber))
}

func TestCQRP020RegistersExactlyRequiredRules(t *testing.T) {
	seen := make(map[string]bool, len(cqrp020Expectations))
	for _, rule := range cqrp020Rules {
		expectation, ok := cqrp020Expectations[rule.Code]
		if !ok {
			t.Errorf("unexpected CQRP rule %q", rule.Code)
			continue
		}
		if seen[rule.Code] {
			t.Errorf("duplicate CQRP rule %q", rule.Code)
		}
		seen[rule.Code] = true
		if rule.Source != expectation.Source || rule.Section != expectation.Section || len(rule.Kinds) == 0 || len(rule.InputKinds) == 0 || rule.Evaluate == nil {
			t.Errorf("rule %q metadata/applicability = %#v", rule.Code, rule)
		}
	}
	if len(seen) != len(cqrp020Expectations) {
		t.Errorf("registered %d rules, want %d", len(seen), len(cqrp020Expectations))
	}
	for code := range cqrp020Expectations {
		if !seen[code] {
			t.Errorf("missing CQRP rule %q", code)
		}
	}
	all := make(map[string]bool)
	for _, rules := range [][]Rule{draft05Rules, cqrp020Rules} {
		for _, rule := range rules {
			if all[rule.Code] {
				t.Errorf("duplicate registry code %q", rule.Code)
			}
			all[rule.Code] = true
		}
	}
}

func assertCQRPFindings(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	want := make([]findingExpectation, len(ids))
	for i, id := range ids {
		var ok bool
		want[i], ok = cqrp020Expectations[id]
		if !ok {
			t.Fatalf("unknown CQRP expectation %q", id)
		}
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Code < want[j].Code })
	got := make([]findingExpectation, len(findings))
	for i, finding := range findings {
		got[i] = findingExpectation{finding.Code, finding.Severity, finding.Field, finding.Source, finding.Section}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CQRP finding tuples = %#v, want %#v; findings = %#v", got, want, findings)
	}
}
