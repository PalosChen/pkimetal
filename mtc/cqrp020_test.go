package mtc

import (
	"bytes"
	"encoding/asn1"
	"math/big"
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
	"e_cqrp_ca_spki_key_encoding":                {"e_cqrp_ca_spki_encoding", Error, "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_hash_mldsa":                       {"e_cqrp_ca_hash_mldsa", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_key_usage_not_critical":           {"e_cqrp_ca_key_usage_not_critical", Error, "tbsCertificate.extensions.keyUsage", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_signature_algorithm":              {"e_cqrp_ca_signature_algorithm", Error, "tbsCertificate.extensions.mtcCertificationAuthority.sigAlg", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_signature_algorithm_encoding":     {"e_cqrp_ca_signature_algorithm_encoding", Error, "tbsCertificate.extensions.mtcCertificationAuthority.sigAlg", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_ca_signature_parameters_present":     {"e_cqrp_ca_signature_parameters_present", Error, "tbsCertificate.extensions.mtcCertificationAuthority.sigAlg.parameters", "CQRP v0.2.0", "4.5.1"},
	"e_cqrp_subscriber_validity_too_long":        {"e_cqrp_subscriber_validity_too_long", Error, "tbsCertificate.validity", "CQRP v0.2.0", "2.1"},
	"e_cqrp_subscriber_mldsa_parameters_present": {"e_cqrp_subscriber_mldsa_parameters_present", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_mldsa_encoding":           {"e_cqrp_subscriber_mldsa_encoding", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm", "CQRP v0.2.0", "4.5.2"},
	"e_cqrp_subscriber_mldsa_key_encoding":       {"e_cqrp_subscriber_mldsa_encoding", Error, "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey", "CQRP v0.2.0", "4.5.2"},
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
			artifact := parseArtifact(t, input, tc.kind)
			assertCQRPFindings(t, LintCQRP020(artifact))
			if got := len(artifact.SubjectPublicKey.SubjectPublicKey); got != 1312 {
				t.Fatalf("baseline ML-DSA-44 public key length = %d, want 1312", got)
			}
		})
	}
}

func TestCQRP020CARules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"wrong algorithm", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA65}
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 1952)
		}, []string{"e_cqrp_ca_spki_algorithm", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"wrong public key length", func(x *mtctest.Template) {
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 32)
		}, []string{"e_cqrp_ca_spki_key_encoding", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"public key not byte aligned", func(x *mtctest.Template) {
			x.SubjectPublicKeyUnused = 1
		}, []string{"e_cqrp_ca_spki_key_encoding", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"parameters and encoding", func(x *mtctest.Template) {
			x.SPKIAlgorithm.ParametersPresent = true
			x.SPKIAlgorithm.Parameters = []byte{0x05, 0x00}
		}, []string{"e_cqrp_ca_spki_encoding", "e_cqrp_ca_spki_parameters_present", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"HashML-DSA 44", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA44, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
		}, []string{"e_cqrp_ca_hash_mldsa", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"HashML-DSA 65", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA65} }, []string{"e_cqrp_ca_hash_mldsa", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"HashML-DSA 87", func(x *mtctest.Template) { x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDHashMLDSA87} }, []string{"e_cqrp_ca_hash_mldsa", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"key usage noncritical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Value: mtctest.KeyUsageDER(true)})
		}, []string{"e_cqrp_ca_key_usage_not_critical"}},
		{"key usage absent delegated to draft", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDKeyUsage) }, nil},
		{"duplicate key usage critical then noncritical", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDKeyUsage)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)},
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Value: mtctest.KeyUsageDER(true)},
			)
		}, []string{"e_cqrp_ca_key_usage_not_critical"}},
		{"duplicate key usage noncritical then critical", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDKeyUsage)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Value: mtctest.KeyUsageDER(true)},
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)},
			)
		}, []string{"e_cqrp_ca_key_usage_not_critical"}},
		{"duplicate critical key usage keyCertSign then missing", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDKeyUsage)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)},
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(false)},
			)
		}, []string{"e_cqrp_ca_key_usage_not_critical"}},
		{"duplicate critical key usage missing then keyCertSign", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDKeyUsage)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(false)},
				mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)},
			)
		}, []string{"e_cqrp_ca_key_usage_not_critical"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPCATemplate()
			tc.mutate(&tpl)
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)), tc.want...)
		})
	}
}

func TestCQRP020CAExtensionSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		sig  mtctest.Algorithm
		want []string
	}{
		{"ML-DSA-44", mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, nil},
		{"ML-DSA-65", mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, []string{"e_cqrp_ca_signature_algorithm", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"parameters", mtctest.Algorithm{OID: mtctest.OIDMLDSA44, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}, []string{"e_cqrp_ca_signature_algorithm_encoding", "e_cqrp_ca_signature_parameters_present", "e_mtc_tlog_ca_cosigner_not_mldsa44"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPCATemplate()
			mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: mtctest.CAExtensionDER(
				mtctest.Algorithm{OID: mtctest.OIDSHA256}, tc.sig, big.NewInt(100), big.NewInt(999),
			)})
			assertCQRPFindings(t, LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)), tc.want...)
		})
	}
}

func TestCQRP020DuplicateCAKeyUsageMessage(t *testing.T) {
	tpl := mtctest.ValidCQRPCATemplate()
	tpl.Extensions = append(tpl.Extensions, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)})
	findings := LintCQRP020(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate))
	assertCQRPFindings(t, findings, "e_cqrp_ca_key_usage_not_critical")
	if got, want := findings[0].Message, "CA key usage extension is duplicated, which violates the certificate profile and RFC 5280"; got != want {
		t.Fatalf("duplicate keyUsage message = %q, want %q", got, want)
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
		{"ML-DSA-44 exact", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA44}
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 1312)
		}, nil},
		{"ML-DSA-65 exact", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA65}
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 1952)
		}, nil},
		{"ML-DSA-87 exact", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA87}
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 2592)
		}, nil},
		{"ML-DSA-65 wrong public key length", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA65}
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 1312)
		}, []string{"e_cqrp_subscriber_mldsa_key_encoding"}},
		{"ML-DSA-87 wrong public key length", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA87}
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 1952)
		}, []string{"e_cqrp_subscriber_mldsa_key_encoding"}},
		{"ML-DSA public key not byte aligned", func(x *mtctest.Template) {
			x.SubjectPublicKeyUnused = 1
		}, []string{"e_cqrp_subscriber_mldsa_key_encoding"}},
		{"ML-DSA parameters and encoding", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA65, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
			x.SubjectPublicKey = bytes.Repeat([]byte{0x5a}, 1952)
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
		{"duplicate DV policy identifier", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV, mtctest.OIDPolicyDV)})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"duplicate DV around OV suppresses warning", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV, mtctest.OIDPolicyOV, mtctest.OIDPolicyDV)})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"duplicate DV before OV suppresses warning", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV, mtctest.OIDPolicyDV, mtctest.OIDPolicyOV)})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"OV before duplicate DV suppresses warning", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyOV, mtctest.OIDPolicyDV, mtctest.OIDPolicyDV)})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"multiple including invalid", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV, asn1.ObjectIdentifier{1, 2, 3})})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"OV then invalid suppresses warning", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyOV, asn1.ObjectIdentifier{1, 2, 3})})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"invalid then OV suppresses warning", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(asn1.ObjectIdentifier{1, 2, 3}, mtctest.OIDPolicyOV)})
		}, []string{"e_cqrp_subscriber_policy_identifier"}},
		{"DV then invalid still enforces empty subject", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV, asn1.ObjectIdentifier{1, 2, 3})})
			x.Subject = mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "example"})
		}, []string{"e_cqrp_subscriber_dv_subject_not_empty", "e_cqrp_subscriber_policy_identifier"}},
		{"invalid then DV still enforces empty subject", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(asn1.ObjectIdentifier{1, 2, 3}, mtctest.OIDPolicyDV)})
			x.Subject = mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "example"})
		}, []string{"e_cqrp_subscriber_dv_subject_not_empty", "e_cqrp_subscriber_policy_identifier"}},
		{"duplicate policies valid then critical invalid", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDCertificatePolicies)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV)},
				mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Critical: true, Value: mtctest.CertificatePoliciesDER(asn1.ObjectIdentifier{1, 2, 3})},
			)
		}, []string{"e_cqrp_subscriber_policies_critical", "e_cqrp_subscriber_policy_identifier"}},
		{"duplicate policies critical invalid then valid", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDCertificatePolicies)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Critical: true, Value: mtctest.CertificatePoliciesDER(asn1.ObjectIdentifier{1, 2, 3})},
				mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyDV)},
			)
		}, []string{"e_cqrp_subscriber_policies_critical", "e_cqrp_subscriber_policy_identifier"}},
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
		{"duplicate EKU valid then critical invalid", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDExtendedKeyUsage)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: mtctest.ExtendedKeyUsageDER(mtctest.OIDServerAuth)},
				mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Critical: true, Value: mtctest.ExtendedKeyUsageDER(asn1.ObjectIdentifier{1, 2, 3})},
			)
		}, []string{"e_cqrp_subscriber_eku_critical", "e_cqrp_subscriber_eku_only_server_auth"}},
		{"duplicate EKU critical invalid then valid", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDExtendedKeyUsage)
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Critical: true, Value: mtctest.ExtendedKeyUsageDER(asn1.ObjectIdentifier{1, 2, 3})},
				mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: mtctest.ExtendedKeyUsageDER(mtctest.OIDServerAuth)},
			)
		}, []string{"e_cqrp_subscriber_eku_critical", "e_cqrp_subscriber_eku_only_server_auth"}},
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
	longUTF8 := append([]byte{0x0c, 0x41}, bytes.Repeat([]byte{'a'}, 65)...)
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"valid O and CN", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(validName))})
		}, nil},
		{"valid PrintableString", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: []byte{0x13, 0x01, 'A'}})), nil},
		{"valid TeletexString", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: []byte{0x14, 0x01, 'A'}})), nil},
		{"valid UTF8String", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: []byte{0x0c, 0x02, 0xc3, 0xa9}})), nil},
		{"valid UniversalString", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: []byte{0x1c, 0x04, 0x00, 0x00, 0x00, 'A'}})), nil},
		{"valid BMPString", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: []byte{0x1e, 0x02, 0x00, 'A'}})), nil},
		{"O INTEGER rejected", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: []byte{0x02, 0x01, 0x01}})), []string{"e_cqrp_subscriber_ian_form"}},
		{"CN NULL rejected", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: []byte{0x05, 0x00}})), []string{"e_cqrp_subscriber_ian_form"}},
		{"empty O rejected", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: []byte{0x0c, 0x00}})), []string{"e_cqrp_subscriber_ian_form"}},
		{"O over 64 characters rejected", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: longUTF8})), []string{"e_cqrp_subscriber_ian_form"}},
		{"malformed CN unicode rejected", addIANName(mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: []byte{0x0c, 0x01, 0xff}})), []string{"e_cqrp_subscriber_ian_form"}},
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
		{"duplicate IAN valid then critical malformed", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(validName))},
				mtctest.Extension{ID: mtctest.OIDIssuerAltName, Critical: true, Value: []byte{0x30, 0x00}},
			)
		}, []string{"e_cqrp_subscriber_ian_critical", "e_cqrp_subscriber_ian_form"}},
		{"duplicate IAN critical malformed then valid", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions,
				mtctest.Extension{ID: mtctest.OIDIssuerAltName, Critical: true, Value: []byte{0x30, 0x00}},
				mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(validName))},
			)
		}, []string{"e_cqrp_subscriber_ian_critical", "e_cqrp_subscriber_ian_form"}},
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

func addIANName(name []byte) func(*mtctest.Template) {
	return func(tpl *mtctest.Template) {
		tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
			ID:    mtctest.OIDIssuerAltName,
			Value: mtctest.GeneralNamesDER(mtctest.DirectoryNameGeneralNameDER(name)),
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

func TestCQRP020CARequiresMTCTlog(t *testing.T) {
	tpl := mtctest.ValidCQRPCATemplate()
	mtctest.RemoveExtension(&tpl, mtctest.OIDMTCTlogPrefixURL)
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	for _, finding := range LintCQRP020(artifact) {
		if finding.Code == "e_cqrp_ca_mtc_tlog_extension_missing" {
			return
		}
	}
	t.Fatal("LintCQRP020 did not require the mtc-tlog extension for a CA")
}

func TestCQRP020RegistersExactlyRequiredRules(t *testing.T) {
	wantCodes := make(map[string]bool, len(cqrp020Expectations))
	for _, expectation := range cqrp020Expectations {
		wantCodes[expectation.Code] = true
	}
	seen := make(map[string]bool, len(wantCodes))
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
	if len(seen) != len(wantCodes) {
		t.Errorf("registered %d rules, want %d", len(seen), len(wantCodes))
	}
	for code := range wantCodes {
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
			want[i], ok = mtcTlogExpectations[id]
		}
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
