package mtc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

func TestRFC5280SubscriberSANFallback(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"valid critical DNS SAN", func(*mtctest.Template) {}, nil},
		{"missing with empty subject", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDSubjectAltName)
		}, []string{"e_rfc5280_mtc_subscriber_san_missing"}},
		{"missing with nonempty subject allowed", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDSubjectAltName)
			x.Subject = mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "subscriber.example"})
		}, nil},
		{"noncritical with empty subject", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDSubjectAltName, Value: mtctest.GeneralNamesDER(mtctest.DNSNameGeneralNameDER("subscriber.example"))})
		}, []string{"e_rfc5280_mtc_subscriber_san_not_critical"}},
		{"duplicate", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSubjectAltName, Critical: true, Value: mtctest.GeneralNamesDER(mtctest.DNSNameGeneralNameDER("second.example"))})
		}, []string{"e_rfc5280_mtc_subscriber_san_duplicate"}},
		{"empty GeneralNames", replaceSAN([]byte{0x30, 0x00}), []string{"e_rfc5280_mtc_subscriber_san_malformed"}},
		{"not a sequence", replaceSAN([]byte{0x82, 0x01, 'x'}), []string{"e_rfc5280_mtc_subscriber_san_malformed"}},
		{"constructed DNS name", replaceSAN([]byte{0x30, 0x03, 0xa2, 0x01, 'x'}), []string{"e_rfc5280_mtc_subscriber_san_malformed"}},
		{"malformed registered ID", replaceSAN([]byte{0x30, 0x03, 0x88, 0x01, 0x80}), []string{"e_rfc5280_mtc_subscriber_san_malformed"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindingCodes(t, LintRFC5280SubscriberForKind(artifact, ArtifactSubscriber), tc.want...)
		})
	}
}

func TestRFC5280SubscriberCoreFallback(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"valid", func(*mtctest.Template) {}, nil},
		{"validity order", func(x *mtctest.Template) { x.NotAfter = x.NotBefore }, []string{"e_rfc5280_mtc_subscriber_validity_order"}},
		{"duplicate extension", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDExtendedKeyUsage, Value: mtctest.ExtendedKeyUsageDER(mtctest.OIDServerAuth)})
		}, []string{"e_rfc5280_mtc_subscriber_duplicate_extension"}},
		{"unknown noncritical extension allowed", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{0x05, 0x00}})
		}, nil},
		{"unknown critical extension", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}})
		}, []string{"e_rfc5280_mtc_subscriber_unknown_critical_extension"}},
		{"subscriber basic constraints CA", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(true)})
		}, []string{"e_rfc5280_mtc_subscriber_basic_constraints"}},
		{"malformed key usage", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: []byte{0x03, 0x00}})
		}, []string{"e_rfc5280_mtc_subscriber_key_usage_malformed"}},
		{"critical SKI", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Critical: true, Value: mtctest.SubjectKeyIdentifierDER([]byte{1})})
		}, []string{"e_rfc5280_mtc_subscriber_ski"}},
		{"malformed SKI", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Value: []byte{0x04, 0x00}})
		}, []string{"e_rfc5280_mtc_subscriber_ski"}},
		{"valid AKI", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0x03, 0x80, 0x01, 0x01}})
		}, nil},
		{"critical AKI", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Critical: true, Value: []byte{0x30, 0x03, 0x80, 0x01, 0x01}})
		}, []string{"e_rfc5280_mtc_subscriber_aki"}},
		{"empty AKI", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0x00}})
		}, []string{"e_rfc5280_mtc_subscriber_aki"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindingCodes(t, LintRFC5280SubscriberForKind(artifact, ArtifactSubscriber), tc.want...)
		})
	}
}

func TestCABFTLSSubscriberSANFallback(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"valid DNS", func(*mtctest.Template) {}, nil},
		{"valid wildcard", replaceSANNamelist(mtctest.DNSNameGeneralNameDER("*.example.com")), nil},
		{"valid A-label", replaceSANNamelist(mtctest.DNSNameGeneralNameDER("xn--bcher-kva.example.com")), nil},
		{"valid IPv4", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("8.8.8.8").To4())), nil},
		{"valid IPv6", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("2606:4700:4700::1111").To16())), nil},
		{"reserved IPv4", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("192.0.2.1").To4())), []string{"e_cabf_mtc_subscriber_reserved_ip"}},
		{"reserved IPv6", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("2001:db8::1").To16())), []string{"e_cabf_mtc_subscriber_reserved_ip"}},
		{"reserved DNS label", replaceSANNamelist(mtctest.DNSNameGeneralNameDER("ab--cd.example.com")), []string{"e_cabf_mtc_subscriber_reserved_dns_label"}},
		{"missing", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDSubjectAltName)
		}, []string{"e_cabf_mtc_subscriber_san_missing"}},
		{"URI name type", replaceSANNamelist(mtctest.URINameGeneralNameDER("https://subscriber.example")), []string{"e_cabf_mtc_subscriber_san_name_type"}},
		{"invalid IP length", replaceSANNamelist(mtctest.IPAddressGeneralNameDER([]byte{192, 0, 2})), []string{"e_cabf_mtc_subscriber_ip_address_invalid"}},
	}
	invalidDNS := []string{
		"", ".example.com", "example.com.", "example..com", "exa_mple.com",
		"-example.com", "example-.com", "example.*.com", "foo*.example.com",
		"*.*.example.com", "example", "xn--.example", "\u00e9xample.com",
		"subscriber.example", "*.com", "example.arpa", "192.0.2.1",
		stringsOfLength(64) + ".example", stringsOfLength(250) + ".com",
	}
	for _, dnsName := range invalidDNS {
		dnsName := dnsName
		tests = append(tests, struct {
			name   string
			mutate func(*mtctest.Template)
			want   []string
		}{"invalid DNS " + dnsName, replaceSANNamelist(mtctest.DNSNameGeneralNameDER(dnsName)), []string{"e_cabf_mtc_subscriber_dns_name_invalid"}})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindingCodes(t, LintCABFTLSSubscriberForKind(artifact, ArtifactSubscriber), tc.want...)
		})
	}
}

func TestCABFTLSSubscriberCoreFallback(t *testing.T) {
	validRSA := mustSPKI(t, &rsa.PublicKey{N: rsaModulus(2048), E: 65537})
	weakRSA := mustSPKI(t, &rsa.PublicKey{N: rsaModulus(1024), E: 65537})
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	validECDSA := mustSPKI(t, &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})

	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"valid ML-DSA", func(*mtctest.Template) {}, nil},
		{"valid RSA", func(x *mtctest.Template) { setSPKI(x, validRSA) }, nil},
		{"valid ECDSA", func(x *mtctest.Template) { setSPKI(x, validECDSA) }, nil},
		{"weak RSA", func(x *mtctest.Template) { setSPKI(x, weakRSA) }, []string{"e_cabf_mtc_subscriber_spki_invalid"}},
		{"malformed RSA", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDRSAEncryption, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
			x.SubjectPublicKey = []byte{1, 2, 3}
		}, []string{"e_cabf_mtc_subscriber_spki_invalid"}},
		{"key usage CA bit", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)})
		}, []string{"e_cabf_mtc_subscriber_key_usage_ca_bits"}},
		{"basic constraints not critical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Value: mtctest.BasicConstraintsDER(false)})
		}, []string{"e_cabf_mtc_subscriber_basic_constraints_not_critical"}},
		{"matching DNS common name", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "subscriber.example.com"})
		}, []string{"w_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"mismatched DNS common name", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "other.example.com"})
		}, []string{"e_cabf_mtc_subscriber_common_name_not_in_san", "w_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"matching IP common name", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "8.8.8.8"})
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDSubjectAltName, Critical: true, Value: mtctest.GeneralNamesDER(mtctest.IPAddressGeneralNameDER(net.ParseIP("8.8.8.8").To4()))})
		}, []string{"w_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"OV missing subject identity", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyOV)})
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV malformed organization", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: []byte{0x02, 0x01, 0x01}},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "US"},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, Value: "Example City"},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject", "w_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"valid OV subject", func(x *mtctest.Template) { setOVSubjectAndPolicy(x) }, []string{"w_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"IV missing subject identity", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
		}, []string{"e_cabf_mtc_subscriber_iv_subject"}},
		{"valid IV subject", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDGivenName, Value: "Alice"},
				mtctest.NameAttribute{ID: mtctest.OIDSurname, Value: "Example"},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "US"},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, Value: "Example City"},
			)
		}, []string{"w_cabf_mtc_subscriber_san_critical_with_subject"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindingCodes(t, LintCABFTLSSubscriberForKind(artifact, ArtifactSubscriber), tc.want...)
		})
	}
}

func TestSubscriberFallbackApplicabilityAndIndependence(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	mtctest.RemoveExtension(&tpl, mtctest.OIDSubjectAltName)
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	original := append([]Extension(nil), artifact.Extensions...)

	assertFindingCodes(t, LintRFC5280SubscriberForKind(artifact, ArtifactSubscriber), "e_rfc5280_mtc_subscriber_san_missing")
	assertFindingCodes(t, LintCABFTLSSubscriberForKind(artifact, ArtifactSubscriber), "e_cabf_mtc_subscriber_san_missing")
	if !reflect.DeepEqual(artifact.Extensions, original) {
		t.Fatal("subscriber fallback lint mutated artifact extensions")
	}
	if got := LintRFC5280SubscriberForKind(artifact, ArtifactCA); got != nil {
		t.Fatalf("RFC fallback CA findings = %#v", got)
	}
	if got := LintCABFTLSSubscriberForKind(nil, ArtifactSubscriber); got != nil {
		t.Fatalf("CABF fallback nil findings = %#v", got)
	}
}

func TestSubscriberFallbackRuleCodesAreStableCopies(t *testing.T) {
	wantRFC := []string{
		"e_rfc5280_mtc_subscriber_aki",
		"e_rfc5280_mtc_subscriber_basic_constraints",
		"e_rfc5280_mtc_subscriber_duplicate_extension",
		"e_rfc5280_mtc_subscriber_key_usage_malformed",
		"e_rfc5280_mtc_subscriber_san_duplicate",
		"e_rfc5280_mtc_subscriber_san_malformed",
		"e_rfc5280_mtc_subscriber_san_missing",
		"e_rfc5280_mtc_subscriber_san_not_critical",
		"e_rfc5280_mtc_subscriber_ski",
		"e_rfc5280_mtc_subscriber_unknown_critical_extension",
		"e_rfc5280_mtc_subscriber_validity_order",
	}
	wantCABF := []string{
		"e_cabf_mtc_subscriber_basic_constraints_not_critical",
		"e_cabf_mtc_subscriber_common_name_not_in_san",
		"e_cabf_mtc_subscriber_dns_name_invalid",
		"e_cabf_mtc_subscriber_ip_address_invalid",
		"e_cabf_mtc_subscriber_iv_subject",
		"e_cabf_mtc_subscriber_key_usage_ca_bits",
		"e_cabf_mtc_subscriber_ov_subject",
		"e_cabf_mtc_subscriber_reserved_dns_label",
		"e_cabf_mtc_subscriber_reserved_ip",
		"e_cabf_mtc_subscriber_san_missing",
		"e_cabf_mtc_subscriber_san_name_type",
		"e_cabf_mtc_subscriber_spki_invalid",
		"w_cabf_mtc_subscriber_san_critical_with_subject",
	}
	if got := RFC5280SubscriberRuleCodes(); !reflect.DeepEqual(got, wantRFC) {
		t.Fatalf("RFC rule codes = %#v, want %#v", got, wantRFC)
	}
	if got := CABFTLSSubscriberRuleCodes(); !reflect.DeepEqual(got, wantCABF) {
		t.Fatalf("CABF rule codes = %#v, want %#v", got, wantCABF)
	}

	rfc := RFC5280SubscriberRuleCodes()
	cabf := CABFTLSSubscriberRuleCodes()
	rfc[0] = "mutated"
	cabf[0] = "mutated"
	if reflect.DeepEqual(RFC5280SubscriberRuleCodes(), rfc) || reflect.DeepEqual(CABFTLSSubscriberRuleCodes(), cabf) {
		t.Fatal("subscriber fallback rule code accessor returned mutable registry state")
	}
}

func mustSPKI(t *testing.T, key any) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return encoded
}

func setSPKI(tpl *mtctest.Template, encoded []byte) {
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(encoded, &spki); err != nil || len(rest) != 0 {
		panic("invalid test SPKI")
	}
	tpl.SPKIAlgorithm = mtctest.Algorithm{OID: spki.Algorithm.Algorithm}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		tpl.SPKIAlgorithm.ParametersPresent = true
		tpl.SPKIAlgorithm.Parameters = append([]byte(nil), spki.Algorithm.Parameters.FullBytes...)
	}
	tpl.SubjectPublicKey = append([]byte(nil), spki.PublicKey.Bytes...)
	tpl.SubjectPublicKeyUnused = len(spki.PublicKey.Bytes)*8 - spki.PublicKey.BitLength
}

func rsaModulus(bits int) *big.Int {
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return modulus.Or(modulus, big.NewInt(3))
}

func setOVSubjectAndPolicy(tpl *mtctest.Template, extra ...mtctest.NameAttribute) {
	mtctest.ReplaceExtension(tpl, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyOV)})
	attributes := []mtctest.NameAttribute{
		{ID: mtctest.OIDOrganizationName, Value: "Example Organization"},
		{ID: mtctest.OIDCountryName, Value: "US"},
		{ID: mtctest.OIDLocalityName, Value: "Example City"},
	}
	tpl.Subject = mtctest.NameDER(append(attributes, extra...)...)
}

func TestCABFTLSSubscriberCriticalSANWarningSeverity(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	setOVSubjectAndPolicy(&tpl)
	findings := LintCABFTLSSubscriberForKind(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate), ArtifactSubscriber)
	if len(findings) != 1 || findings[0].Code != "w_cabf_mtc_subscriber_san_critical_with_subject" || findings[0].Severity != Warning {
		t.Fatalf("critical SAN findings = %#v", findings)
	}
}

func replaceSAN(value []byte) func(*mtctest.Template) {
	return func(tpl *mtctest.Template) {
		mtctest.ReplaceExtension(tpl, mtctest.Extension{ID: mtctest.OIDSubjectAltName, Critical: true, Value: value})
	}
}

func replaceSANNamelist(names ...[]byte) func(*mtctest.Template) {
	return replaceSAN(mtctest.GeneralNamesDER(names...))
}

func stringsOfLength(length int) string {
	return string(bytes.Repeat([]byte{'a'}, length))
}

func assertFindingCodes(t *testing.T, findings []Finding, want ...string) {
	t.Helper()
	var got []string
	for _, finding := range findings {
		got = append(got, finding.Code)
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding codes = %#v, want %#v; findings = %#v", got, want, findings)
	}
}
