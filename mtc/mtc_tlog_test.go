package mtc

import (
	"math/big"
	"reflect"
	"sort"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

var mtcTlogExpectations = map[string]findingExpectation{
	"e_cqrp_ca_mtc_tlog_extension_missing": {"e_cqrp_ca_mtc_tlog_extension_missing", Error, "tbsCertificate.extensions.mtcTlogPrefixURL", "CQRP v0.2.0", "4.6.1"},
	"e_mtc_tlog_ca_cosigner_not_mldsa44":   {"e_mtc_tlog_ca_cosigner_not_mldsa44", Error, "tbsCertificate.subjectPublicKeyInfo.algorithm,tbsCertificate.extensions.mtcCertificationAuthority.sigAlg", "C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105", "Cosigners"},
	"e_mtc_tlog_extension_critical":        {"e_mtc_tlog_extension_critical", Error, "tbsCertificate.extensions.mtcTlogPrefixURL", "C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105", "Parameters"},
	"e_mtc_tlog_extension_duplicate":       {"e_mtc_tlog_extension_duplicate", Error, "tbsCertificate.extensions.mtcTlogPrefixURL", "C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105", "Parameters"},
	"e_mtc_tlog_extension_malformed":       {"e_mtc_tlog_extension_malformed", Error, "tbsCertificate.extensions.mtcTlogPrefixURL", "C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105", "Parameters"},
	"e_mtc_tlog_log_hash_not_sha256":       {"e_mtc_tlog_log_hash_not_sha256", Error, "tbsCertificate.extensions.mtcCertificationAuthority.logHash", "C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105", "Parameters"},
	"e_mtc_tlog_prefix_url_invalid":        {"e_mtc_tlog_prefix_url_invalid", Error, "tbsCertificate.extensions.mtcTlogPrefixURL", "C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105", "Parameters"},
}

func TestMTCTlogRuleCodesAreStable(t *testing.T) {
	first := MTCTlogRuleCodes()
	if !sort.StringsAreSorted(first) {
		t.Fatalf("rule codes are not sorted: %q", first)
	}
	if len(first) != len(mtcTlogExpectations) {
		t.Fatalf("rule code count = %d, expectations = %d", len(first), len(mtcTlogExpectations))
	}
	for i, code := range first {
		if _, ok := mtcTlogExpectations[code]; !ok {
			t.Errorf("rule code %q lacks metadata expectation", code)
		}
		if i > 0 && code == first[i-1] {
			t.Errorf("rule code %q is duplicated", code)
		}
	}
	want := append([]string(nil), first...)
	first[0] = "caller mutation"
	if got := MTCTlogRuleCodes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rule code list shares caller storage: got %q, want %q", got, want)
	}
}

func TestMTCTlogRules(t *testing.T) {
	valid := mtctest.Extension{ID: mtctest.OIDMTCTlogPrefixURL, Value: mtctest.MTCTlogPrefixURLDER("https://ca.example/mtc")}
	tests := []struct {
		name       string
		extensions []mtctest.Extension
		logHash    mtctest.Algorithm
		required   bool
		want       []string
	}{
		{"generic missing accepted", nil, mtctest.Algorithm{OID: mtctest.OIDSHA256}, false, nil},
		{"CQRP missing rejected", nil, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_cqrp_ca_mtc_tlog_extension_missing"}},
		{"valid HTTPS", []mtctest.Extension{valid}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, nil},
		{"valid HTTP", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Value: mtctest.MTCTlogPrefixURLDER("http://ca.example/mtc")}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, nil},
		{"critical", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Critical: true, Value: valid.Value}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_extension_critical"}},
		{"duplicate", []mtctest.Extension{valid, valid}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_extension_duplicate"}},
		{"wrong DER tag", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Value: []byte{0x0c, 0x01, 'x'}}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_extension_malformed"}},
		{"non ASCII", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Value: []byte{0x16, 0x01, 0xff}}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_extension_malformed"}},
		{"relative URL", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Value: mtctest.MTCTlogPrefixURLDER("/mtc")}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
		{"userinfo", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Value: mtctest.MTCTlogPrefixURLDER("https://user@ca.example/mtc")}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
		{"query", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Value: mtctest.MTCTlogPrefixURLDER("https://ca.example/mtc?q=1")}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
		{"fragment", []mtctest.Extension{{ID: mtctest.OIDMTCTlogPrefixURL, Value: mtctest.MTCTlogPrefixURLDER("https://ca.example/mtc#x")}}, mtctest.Algorithm{OID: mtctest.OIDSHA256}, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
		{"non SHA-256", []mtctest.Extension{valid}, mtctest.Algorithm{OID: mtctest.OIDRSAEncryption}, false, []string{"e_mtc_tlog_log_hash_not_sha256"}},
		{"required missing and non SHA-256", nil, mtctest.Algorithm{OID: mtctest.OIDRSAEncryption}, true, []string{"e_cqrp_ca_mtc_tlog_extension_missing", "e_mtc_tlog_log_hash_not_sha256"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			tpl.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDMLDSA44}
			tpl.SubjectPublicKey = make([]byte, 1312)
			mtctest.RemoveExtension(&tpl, mtctest.OIDMTCTlogPrefixURL)
			tpl.Extensions = append(tpl.Extensions, tc.extensions...)
			mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: mtctest.CAExtensionDER(tc.logHash, mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, big.NewInt(100), big.NewInt(999))})
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			var findings []Finding
			if tc.required {
				findings = LintMTCTlogRequiredForKind(artifact, ArtifactCA)
			} else {
				findings = LintMTCTlogConditionalForKind(artifact, ArtifactCA)
			}
			assertMTCTlogFindings(t, findings, tc.want...)
		})
	}
}

func TestMTCTlogCACosignerMustUseMLDSA44(t *testing.T) {
	for _, tc := range []struct {
		name string
		spki mtctest.Algorithm
		sig  mtctest.Algorithm
		kind InputKind
		key  []byte
		want []string
	}{
		{"ML-DSA-44 certificate", mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, InputCertificate, make([]byte, 1312), nil},
		{"ML-DSA-65 certificate", mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, InputCertificate, make([]byte, 1952), []string{"e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"ML-DSA-65 TBS", mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, InputTBSCertificate, make([]byte, 1952), []string{"e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"wrong key algorithm", mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, InputCertificate, make([]byte, 1952), []string{"e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"wrong signature algorithm", mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, InputCertificate, make([]byte, 1312), []string{"e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"SPKI parameters", mtctest.Algorithm{OID: mtctest.OIDMLDSA44, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}, mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, InputCertificate, make([]byte, 1312), []string{"e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"signature parameters", mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, mtctest.Algorithm{OID: mtctest.OIDMLDSA44, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}, InputCertificate, make([]byte, 1312), []string{"e_mtc_tlog_ca_cosigner_not_mldsa44"}},
		{"invalid public key size", mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, mtctest.Algorithm{OID: mtctest.OIDMLDSA44}, InputCertificate, make([]byte, 1311), []string{"e_mtc_tlog_ca_cosigner_not_mldsa44"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			tpl.SPKIAlgorithm = tc.spki
			tpl.SubjectPublicKey = tc.key
			mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: mtctest.CAExtensionDER(mtctest.Algorithm{OID: mtctest.OIDSHA256}, tc.sig, big.NewInt(100), big.NewInt(999))})
			tpl.Extensions = append(tpl.Extensions, mtctest.Extension{ID: mtctest.OIDMTCTlogPrefixURL, Value: mtctest.MTCTlogPrefixURLDER("https://ca.example/mtc")})
			var input []byte
			if tc.kind == InputCertificate {
				input = mtctest.Certificate(tpl)
			} else {
				input = mtctest.TBSCertificate(tpl)
			}
			artifact := parseArtifact(t, input, tc.kind)
			assertMTCTlogFindings(t, LintMTCTlogConditionalForKind(artifact, ArtifactCA), tc.want...)
		})
	}
}

func TestMTCTlogRulesAreCAOnlyAndDoNotMutate(t *testing.T) {
	artifact := parseArtifact(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), InputCertificate)
	before := artifact.Kind
	if got := LintMTCTlogRequiredForKind(artifact, ArtifactSubscriber); got != nil {
		t.Fatalf("subscriber findings = %#v", got)
	}
	if artifact.Kind != before {
		t.Fatal("lint mutated artifact kind")
	}
}

func assertMTCTlogFindings(t *testing.T, findings []Finding, ids ...string) {
	t.Helper()
	want := make([]findingExpectation, len(ids))
	for i, id := range ids {
		want[i] = mtcTlogExpectations[id]
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Code < want[j].Code })
	got := make([]findingExpectation, len(findings))
	for i, finding := range findings {
		got[i] = findingExpectation{finding.Code, finding.Severity, finding.Field, finding.Source, finding.Section}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding tuples = %#v, want %#v; findings = %#v", got, want, findings)
	}
}
