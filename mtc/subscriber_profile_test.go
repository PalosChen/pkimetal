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
	"time"

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
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: []byte{0x03, 0x00}})
		}, []string{"e_rfc5280_mtc_subscriber_key_usage_malformed"}},
		{"critical SKI", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Critical: true, Value: mtctest.SubjectKeyIdentifierDER([]byte{1})})
		}, []string{"e_rfc5280_mtc_subscriber_ski"}},
		{"malformed SKI", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Value: []byte{0x04, 0x00}})
		}, []string{"e_rfc5280_mtc_subscriber_ski"}},
		{"missing AKI", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDAuthorityKeyID)
		}, []string{"e_rfc5280_mtc_subscriber_aki"}},
		{"valid AKI", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: mtctest.AuthorityKeyIdentifierDER([]byte{1})})
		}, nil},
		{"critical AKI", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Critical: true, Value: mtctest.AuthorityKeyIdentifierDER([]byte{1})})
		}, []string{"e_rfc5280_mtc_subscriber_aki"}},
		{"empty AKI", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0x00}})
		}, []string{"e_rfc5280_mtc_subscriber_aki"}},
		{"AKI issuer and serial without key identifier", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0x08, 0xa1, 0x03, 0x82, 0x01, 'x', 0x82, 0x01, 0x01}})
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

func TestRFC5280SubscriberRejectsNonV3Certificate(t *testing.T) {
	encoded := mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate())
	v3 := []byte{0xa0, 0x03, 0x02, 0x01, 0x02}
	v2 := []byte{0xa0, 0x03, 0x02, 0x01, 0x01}
	if bytes.Count(encoded, v3) != 1 {
		t.Fatal("fixture does not contain exactly one explicit v3 version")
	}
	encoded = bytes.Replace(encoded, v3, v2, 1)
	artifact := parseArtifact(t, encoded, InputCertificate)
	assertFindingCodes(t, LintRFC5280SubscriberForKind(artifact, ArtifactSubscriber), "e_rfc5280_mtc_subscriber_not_v3")
}

func TestCABFTLSSubscriberRejectsNonV3Certificate(t *testing.T) {
	encoded := mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate())
	v3 := []byte{0xa0, 0x03, 0x02, 0x01, 0x02}
	v2 := []byte{0xa0, 0x03, 0x02, 0x01, 0x01}
	if bytes.Count(encoded, v3) != 1 {
		t.Fatal("fixture does not contain exactly one explicit v3 version")
	}
	encoded = bytes.Replace(encoded, v3, v2, 1)
	artifact := parseArtifact(t, encoded, InputCertificate)
	assertFindingCodes(t, LintCABFTLSSubscriberForKind(artifact, ArtifactSubscriber), "e_cabf_mtc_subscriber_not_v3")
}

func TestCABFTLSSubscriberCommonProfileRuleSections(t *testing.T) {
	want := map[string]string{
		"e_cabf_mtc_subscriber_not_v3":            "7.1.2.7",
		"e_cabf_mtc_subscriber_unique_id_present": "7.1.2.7",
	}
	for _, rule := range cabfTLSSubscriberRules {
		section, ok := want[rule.Code]
		if !ok {
			continue
		}
		if rule.Section != section {
			t.Errorf("%s section = %q, want %q", rule.Code, rule.Section, section)
		}
		delete(want, rule.Code)
	}
	for code := range want {
		t.Errorf("rule %s not found", code)
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
		{"valid private suffix github.io", replaceSANNamelist(mtctest.DNSNameGeneralNameDER("site.github.io")), nil},
		{"valid private suffix blogspot.com", replaceSANNamelist(mtctest.DNSNameGeneralNameDER("tenant.blogspot.com")), nil},
		{"valid ARPA infrastructure name", replaceSANNamelist(mtctest.DNSNameGeneralNameDER("service.e164.arpa")), nil},
		{"valid IPv4", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("8.8.8.8").To4())), nil},
		{"valid IPv6", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("2606:4700:4700::1111").To16())), nil},
		{"reserved IPv4", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("192.0.2.1").To4())), []string{"e_cabf_mtc_subscriber_reserved_ip"}},
		{"reserved IPv6", replaceSANNamelist(mtctest.IPAddressGeneralNameDER(net.ParseIP("2001:db8::1").To16())), []string{"e_cabf_mtc_subscriber_reserved_ip"}},
		{"reserved DNS label", replaceSANNamelist(mtctest.DNSNameGeneralNameDER("ab--cd.example.com")), []string{"e_cabf_mtc_subscriber_reserved_dns_label"}},
		{"missing", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDSubjectAltName)
		}, []string{"e_cabf_mtc_subscriber_san_missing"}},
		{"duplicate SAN extension", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSubjectAltName, Critical: true, Value: mtctest.GeneralNamesDER(mtctest.DNSNameGeneralNameDER("second.example"))})
		}, []string{"e_cabf_mtc_subscriber_san_duplicate"}},
		{"empty GeneralNames", replaceSAN([]byte{0x30, 0x00}), []string{"e_cabf_mtc_subscriber_san_malformed"}},
		{"SAN not a sequence", replaceSAN([]byte{0x82, 0x01, 'x'}), []string{"e_cabf_mtc_subscriber_san_malformed"}},
		{"URI name type", replaceSANNamelist(mtctest.URINameGeneralNameDER("https://subscriber.example")), []string{"e_cabf_mtc_subscriber_san_name_type"}},
		{"invalid IP length", replaceSANNamelist(mtctest.IPAddressGeneralNameDER([]byte{192, 0, 2})), []string{"e_cabf_mtc_subscriber_ip_address_invalid"}},
	}
	invalidDNS := []string{
		"", ".example.com", "example.com.", "example..com", "exa_mple.com",
		"-example.com", "example-.com", "example.*.com", "foo*.example.com",
		"*.*.example.com", "example", "xn--.example", "\u00e9xample.com",
		"subscriber.example", "*.com", "1.0.0.127.in-addr.arpa", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.ip6.arpa", "192.0.2.1",
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
			setDefaultSubscriberKeyUsage(&tpl)
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindingCodes(t, LintCABFTLSSubscriberForKind(artifact, ArtifactSubscriber), tc.want...)
		})
	}
}

func TestCABFTLSSubscriberCoreFallback(t *testing.T) {
	validRSA := mustSPKI(t, &rsa.PublicKey{N: rsaModulus(2048), E: 65537})
	nonOctetRSA := mustSPKI(t, &rsa.PublicKey{N: rsaModulus(2049), E: 65537})
	lowExponentRSA := mustSPKI(t, &rsa.PublicKey{N: rsaModulus(2048), E: 3})
	invalidExponentRSA := mustSPKI(t, &rsa.PublicKey{N: rsaModulus(2048), E: 4})
	weakRSA := mustSPKI(t, &rsa.PublicKey{N: rsaModulus(1024), E: 65537})
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	validECDSA := mustSPKI(t, &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})

	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"valid ML-DSA", func(*mtctest.Template) {}, nil},
		{"unknown critical extension", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}})
		}, []string{"e_cabf_mtc_subscriber_unknown_critical_extension"}},
		{"valid RSA", func(x *mtctest.Template) { setSPKI(x, validRSA) }, nil},
		{"RSA exponent 3 is allowed but not recommended", func(x *mtctest.Template) { setSPKI(x, lowExponentRSA) }, []string{"w_cabf_mtc_subscriber_rsa_public_exponent_not_recommended"}},
		{"even RSA exponent", func(x *mtctest.Template) { setSPKI(x, invalidExponentRSA) }, []string{"e_cabf_mtc_subscriber_spki_invalid"}},
		{"valid ECDSA", func(x *mtctest.Template) { setSPKI(x, validECDSA) }, nil},
		{"weak RSA", func(x *mtctest.Template) { setSPKI(x, weakRSA) }, []string{"e_cabf_mtc_subscriber_spki_invalid"}},
		{"non-octet-aligned RSA modulus", func(x *mtctest.Template) { setSPKI(x, nonOctetRSA) }, []string{"e_cabf_mtc_subscriber_spki_invalid"}},
		{"malformed RSA", func(x *mtctest.Template) {
			x.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDRSAEncryption, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
			x.SubjectPublicKey = []byte{1, 2, 3}
		}, []string{"e_cabf_mtc_subscriber_spki_invalid"}},
		{"key usage CA bit", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)})
		}, []string{"e_cabf_mtc_subscriber_key_usage_ca_bits"}},
		{"missing key usage", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDKeyUsage)
		}, []string{"w_cabf_mtc_subscriber_key_usage_missing"}},
		{"valid RSA key usage", func(x *mtctest.Template) {
			setSPKI(x, validRSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x8000 | 0x2000)})
		}, nil},
		{"noncritical RSA key usage", func(x *mtctest.Template) {
			setSPKI(x, validRSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Value: mtctest.KeyUsageBitsDER(0x8000)})
		}, []string{"e_cabf_mtc_subscriber_key_usage_not_critical"}},
		{"RSA key usage without digital signature", func(x *mtctest.Template) {
			setSPKI(x, validRSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x2000)})
		}, []string{"w_cabf_mtc_subscriber_rsa_digital_signature_missing"}},
		{"RSA data encipherment is discouraged", func(x *mtctest.Template) {
			setSPKI(x, validRSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x8000 | 0x1000)})
		}, []string{"w_cabf_mtc_subscriber_rsa_data_encipherment"}},
		{"RSA key usage without permitted bit", func(x *mtctest.Template) {
			setSPKI(x, validRSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x4000)})
		}, []string{"e_cabf_mtc_subscriber_key_usage_invalid"}},
		{"valid ECDSA key usage", func(x *mtctest.Template) {
			setSPKI(x, validECDSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x8000)})
		}, nil},
		{"ECDSA key agreement is discouraged", func(x *mtctest.Template) {
			setSPKI(x, validECDSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x8000 | 0x0800)})
		}, []string{"w_cabf_mtc_subscriber_ec_key_agreement"}},
		{"ECDSA key usage without digital signature", func(x *mtctest.Template) {
			setSPKI(x, validECDSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x0800)})
		}, []string{"e_cabf_mtc_subscriber_key_usage_invalid"}},
		{"ECDSA key usage with prohibited bit", func(x *mtctest.Template) {
			setSPKI(x, validECDSA)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x8000 | 0x2000)})
		}, []string{"e_cabf_mtc_subscriber_key_usage_invalid"}},
		{"basic constraints not critical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Value: mtctest.BasicConstraintsDER(false)})
		}, []string{"e_cabf_mtc_subscriber_basic_constraints_not_critical"}},
		{"AIA with only OCSP", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodOCSP, "http://ocsp.example.com"))})
		}, []string{"w_cabf_mtc_subscriber_aia_missing_ca_issuers"}},
		{"AIA with only caIssuers", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodIssuers, "http://ca.example.com/issuer.der"))})
		}, nil},
		{"long-lived certificate without OCSP or CRLDP", func(x *mtctest.Template) {
			x.NotAfter = x.NotBefore.Add(8 * 24 * time.Hour)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodIssuers, "http://ca.example.com/issuer.der"))})
		}, []string{"e_cabf_mtc_subscriber_crldp_missing"}},
		{"long-lived certificate with CRLDP", func(x *mtctest.Template) {
			x.NotAfter = x.NotBefore.Add(8 * 24 * time.Hour)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodIssuers, "http://ca.example.com/issuer.der"))})
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDCRLDistributionPoints, Value: mtctest.CRLDistributionPointsDER("http://crl.example.com/issuer.crl")})
		}, nil},
		{"SC63 ten-day short-lived certificate", func(x *mtctest.Template) {
			x.NotBefore = time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC)
			x.NotAfter = x.NotBefore.Add(10 * 24 * time.Hour)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodIssuers, "http://ca.example.com/issuer.der"))})
		}, nil},
		{"pre-SC63 certificate does not require CRLDP", func(x *mtctest.Template) {
			x.NotBefore = time.Date(2024, 3, 14, 23, 59, 59, 0, time.UTC)
			x.NotAfter = x.NotBefore.Add(30 * 24 * time.Hour)
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodIssuers, "http://ca.example.com/issuer.der"))})
		}, nil},
		{"critical CRLDP", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDCRLDistributionPoints, Critical: true, Value: mtctest.CRLDistributionPointsDER("http://crl.example.com/issuer.crl")})
		}, []string{"e_cabf_mtc_subscriber_crldp_not_critical"}},
		{"invalid CRLDP location", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDCRLDistributionPoints, Value: mtctest.CRLDistributionPointsDER("https://crl.example.com/issuer.crl")})
		}, []string{"e_cabf_mtc_subscriber_crldp_invalid"}},
		{"multiple CRL distribution points are discouraged", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDCRLDistributionPoints, Value: mtctest.CRLDistributionPointsDER(
				"http://crl.example.com/issuer.crl",
				"http://backup.example.com/issuer.crl",
			)})
		}, []string{"w_cabf_mtc_subscriber_crldp_multiple"}},
		{"subscriber name constraints", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDNameConstraints, Critical: true, Value: []byte{0x30, 0x00}})
		}, []string{"e_cabf_mtc_subscriber_name_constraints_present"}},
		{"missing AIA", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDAuthorityInfoAccess)
		}, []string{"e_cabf_mtc_subscriber_aia_missing"}},
		{"critical AIA", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Critical: true, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodOCSP, "http://ocsp.example.com"))})
		}, []string{"e_cabf_mtc_subscriber_aia_not_critical", "w_cabf_mtc_subscriber_aia_missing_ca_issuers"}},
		{"empty AIA", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: []byte{0x30, 0x00}})
		}, []string{"e_cabf_mtc_subscriber_aia_invalid"}},
		{"unsupported AIA method", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(asn1.ObjectIdentifier{1, 2, 3, 4}, "http://example.com"))})
		}, []string{"e_cabf_mtc_subscriber_aia_invalid"}},
		{"HTTPS AIA location", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodOCSP, "https://ocsp.example.com"))})
		}, []string{"e_cabf_mtc_subscriber_aia_invalid"}},
		{"non-URI AIA location", func(x *mtctest.Template) {
			description := mtctest.AccessDescriptionWithLocationDER(mtctest.OIDAccessMethodOCSP, mtctest.DNSNameGeneralNameDER("ocsp.example.com"))
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(description)})
		}, []string{"e_cabf_mtc_subscriber_aia_invalid"}},
		{"duplicate AIA location", func(x *mtctest.Template) {
			description := mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodOCSP, "http://ocsp.example.com")
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(description, description)})
		}, []string{"e_cabf_mtc_subscriber_aia_invalid"}},
		{"AIA location without hostname", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodOCSP, "http://:80"))})
		}, []string{"e_cabf_mtc_subscriber_aia_invalid"}},
		{"case-equivalent duplicate AIA location", func(x *mtctest.Template) {
			first := mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodOCSP, "http://OCSP.example.com/status")
			second := mtctest.AccessDescriptionDER(mtctest.OIDAccessMethodOCSP, "HTTP://ocsp.example.com/status")
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityInfoAccess, Value: mtctest.AuthorityInformationAccessDER(first, second)})
		}, []string{"e_cabf_mtc_subscriber_aia_invalid"}},
		{"missing AKI", func(x *mtctest.Template) {
			mtctest.RemoveExtension(x, mtctest.OIDAuthorityKeyID)
		}, []string{"e_cabf_mtc_subscriber_aki_missing"}},
		{"critical AKI", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Critical: true, Value: mtctest.AuthorityKeyIdentifierDER([]byte{1})})
		}, []string{"e_cabf_mtc_subscriber_aki_not_critical"}},
		{"empty AKI key identifier", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: mtctest.AuthorityKeyIdentifierDER(nil)})
		}, []string{"e_cabf_mtc_subscriber_aki_invalid"}},
		{"subject key identifier is not recommended", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER([]byte{0x42})})
		}, []string{"w_cabf_mtc_subscriber_ski_present"}},
		{"issuer unique ID", func(x *mtctest.Template) {
			x.IssuerUniqueID = []byte{0x80}
			x.IssuerUniqueIDUnused = 7
		}, []string{"e_cabf_mtc_subscriber_unique_id_present"}},
		{"subject unique ID", func(x *mtctest.Template) {
			x.SubjectUniqueID = []byte{0x40}
			x.SubjectUniqueIDUnused = 6
		}, []string{"e_cabf_mtc_subscriber_unique_id_present"}},
		{"unknown noncritical extension is not recommended", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{0x05, 0x00}})
		}, []string{"w_cabf_mtc_subscriber_extension_not_recommended"}},
		{"AKI issuer and serial", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0x08, 0xa1, 0x03, 0x82, 0x01, 'x', 0x82, 0x01, 0x01}})
		}, []string{"e_cabf_mtc_subscriber_aki_invalid"}},
		{"matching DNS common name", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "subscriber.example.com"})
		}, []string{"e_cabf_mtc_subscriber_san_critical_with_subject", "w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended"}},
		{"mismatched DNS common name", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "other.example.com"})
		}, []string{"e_cabf_mtc_subscriber_common_name_not_in_san", "e_cabf_mtc_subscriber_san_critical_with_subject", "w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended"}},
		{"matching IP common name", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "8.8.8.8"})
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDSubjectAltName, Critical: true, Value: mtctest.GeneralNamesDER(mtctest.IPAddressGeneralNameDER(net.ParseIP("8.8.8.8").To4()))})
		}, []string{"e_cabf_mtc_subscriber_san_critical_with_subject", "w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended"}},
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
		}, []string{"e_cabf_mtc_subscriber_ov_subject", "e_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"valid OV subject", func(x *mtctest.Template) { setOVSubjectAndPolicy(x) }, []string{"e_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"valid long OV locality", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER(stringsOfLength(100))},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
			)
		}, nil},
		{"OV business category uses T61String", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDBusinessCategory, RawValue: mtctest.T61StringDER("Private Organization")})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV business category is discouraged", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDBusinessCategory, RawValue: mtctest.UTF8StringDER("Private Organization")})
			setNonCriticalDefaultSAN(x)
		}, []string{"w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended"}},
		{"OV jurisdiction country uses UTF8String", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDJurisdictionCountry, RawValue: mtctest.UTF8StringDER("US")})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV metadata-only organization identifier", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDOrganizationIdentifier, RawValue: mtctest.UTF8StringDER("-")})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV metadata-only unknown attribute", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, RawValue: mtctest.UTF8StringDER("-")})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV long metadata-only unknown attribute", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, RawValue: mtctest.UTF8StringDER(string(bytes.Repeat([]byte{'-'}, 100)))})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV long organization identifier is discouraged", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDOrganizationIdentifier, RawValue: mtctest.UTF8StringDER(stringsOfLength(100))})
			setNonCriticalDefaultSAN(x)
		}, []string{"w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended"}},
		{"valid OV repeated domain and street attributes", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDDomainComponent, RawValue: mtctest.IA5StringDER("com")},
				mtctest.NameAttribute{ID: mtctest.OIDDomainComponent, RawValue: mtctest.IA5StringDER("example")},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
				mtctest.NameAttribute{ID: mtctest.OIDStreetAddress, RawValue: mtctest.UTF8StringDER("First Street")},
				mtctest.NameAttribute{ID: mtctest.OIDStreetAddress, RawValue: mtctest.UTF8StringDER("Second Street")},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
			)
		}, []string{"w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended"}},
		{"OV domain components use DNS order instead of reverse order", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDDomainComponent, RawValue: mtctest.IA5StringDER("example")},
				mtctest.NameAttribute{ID: mtctest.OIDDomainComponent, RawValue: mtctest.IA5StringDER("com")},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV locality exceeds 128 characters", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER(stringsOfLength(129))},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV organization uses T61String", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.T61StringDER("Example Organization")},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV country uses UTF8String", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.UTF8StringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV subject attributes out of order", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV multi-valued RDN", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameWithMultiValuedRDN(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV metadata-only postal code", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDPostalCode, RawValue: mtctest.UTF8StringDER("-")})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV invalid domain component", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDDomainComponent, RawValue: mtctest.IA5StringDER("-")})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV invalid country", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, Value: "Example Organization"},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "ZZ"},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, Value: "Example City"},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV prohibited surname", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDSurname, Value: "Example"})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV duplicate country", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x, mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "US"})
			setNonCriticalDefaultSAN(x)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"OV metadata-only organization", func(x *mtctest.Template) {
			setOVSubjectAndPolicy(x)
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, Value: " - - "},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "US"},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, Value: "Example City"},
			)
		}, []string{"e_cabf_mtc_subscriber_ov_subject"}},
		{"IV missing subject identity", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
		}, []string{"e_cabf_mtc_subscriber_iv_subject"}},
		{"valid IV subject", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, Value: "Example City"},
				mtctest.NameAttribute{ID: mtctest.OIDSurname, Value: "Example"},
				mtctest.NameAttribute{ID: mtctest.OIDGivenName, Value: "Alice"},
			)
		}, []string{"e_cabf_mtc_subscriber_san_critical_with_subject"}},
		{"IV prohibited organizational unit", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDGivenName, Value: "Alice"},
				mtctest.NameAttribute{ID: mtctest.OIDSurname, Value: "Example"},
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, Value: "US"},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, Value: "Example City"},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationalUnitName, Value: "Validation"},
			)
		}, []string{"e_cabf_mtc_subscriber_iv_subject"}},
		{"IV organization name is discouraged", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
				mtctest.NameAttribute{ID: mtctest.OIDOrganizationName, RawValue: mtctest.UTF8StringDER("Example Organization")},
				mtctest.NameAttribute{ID: mtctest.OIDSurname, RawValue: mtctest.UTF8StringDER("Example")},
				mtctest.NameAttribute{ID: mtctest.OIDGivenName, RawValue: mtctest.UTF8StringDER("Alice")},
			)
		}, []string{"w_cabf_mtc_subscriber_iv_subject_attributes_not_recommended"}},
		{"IV address attributes are discouraged", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
				mtctest.NameAttribute{ID: mtctest.OIDPostalCode, RawValue: mtctest.UTF8StringDER("10001")},
				mtctest.NameAttribute{ID: mtctest.OIDStreetAddress, RawValue: mtctest.UTF8StringDER("First Street")},
				mtctest.NameAttribute{ID: mtctest.OIDSurname, RawValue: mtctest.UTF8StringDER("Example")},
				mtctest.NameAttribute{ID: mtctest.OIDGivenName, RawValue: mtctest.UTF8StringDER("Alice")},
			)
		}, []string{"w_cabf_mtc_subscriber_iv_subject_attributes_not_recommended"}},
		{"IV common name is discouraged", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDCertificatePolicies, Value: mtctest.CertificatePoliciesDER(mtctest.OIDPolicyIV)})
			setNonCriticalDefaultSAN(x)
			x.Subject = mtctest.NameDER(
				mtctest.NameAttribute{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
				mtctest.NameAttribute{ID: mtctest.OIDLocalityName, RawValue: mtctest.UTF8StringDER("Example City")},
				mtctest.NameAttribute{ID: mtctest.OIDSurname, RawValue: mtctest.UTF8StringDER("Example")},
				mtctest.NameAttribute{ID: mtctest.OIDGivenName, RawValue: mtctest.UTF8StringDER("Alice")},
				mtctest.NameAttribute{ID: mtctest.OIDCommonName, RawValue: mtctest.UTF8StringDER("subscriber.example.com")},
			)
		}, []string{"w_cabf_mtc_subscriber_iv_subject_attributes_not_recommended"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate()
			setDefaultSubscriberKeyUsage(&tpl)
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindingCodes(t, LintCABFTLSSubscriberForKind(artifact, ArtifactSubscriber), tc.want...)
		})
	}
}

func TestSubscriberFallbackApplicabilityAndIndependence(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	setDefaultSubscriberKeyUsage(&tpl)
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
		"e_rfc5280_mtc_subscriber_not_v3",
		"e_rfc5280_mtc_subscriber_san_duplicate",
		"e_rfc5280_mtc_subscriber_san_malformed",
		"e_rfc5280_mtc_subscriber_san_missing",
		"e_rfc5280_mtc_subscriber_san_not_critical",
		"e_rfc5280_mtc_subscriber_ski",
		"e_rfc5280_mtc_subscriber_unknown_critical_extension",
		"e_rfc5280_mtc_subscriber_validity_order",
	}
	wantCABF := []string{
		"e_cabf_mtc_subscriber_aia_invalid",
		"e_cabf_mtc_subscriber_aia_missing",
		"e_cabf_mtc_subscriber_aia_not_critical",
		"e_cabf_mtc_subscriber_aki_invalid",
		"e_cabf_mtc_subscriber_aki_missing",
		"e_cabf_mtc_subscriber_aki_not_critical",
		"e_cabf_mtc_subscriber_basic_constraints_not_critical",
		"e_cabf_mtc_subscriber_common_name_not_in_san",
		"e_cabf_mtc_subscriber_crldp_invalid",
		"e_cabf_mtc_subscriber_crldp_missing",
		"e_cabf_mtc_subscriber_crldp_not_critical",
		"e_cabf_mtc_subscriber_dns_name_invalid",
		"e_cabf_mtc_subscriber_ip_address_invalid",
		"e_cabf_mtc_subscriber_iv_subject",
		"e_cabf_mtc_subscriber_key_usage_ca_bits",
		"e_cabf_mtc_subscriber_key_usage_invalid",
		"e_cabf_mtc_subscriber_key_usage_not_critical",
		"e_cabf_mtc_subscriber_name_constraints_present",
		"e_cabf_mtc_subscriber_not_v3",
		"e_cabf_mtc_subscriber_ov_subject",
		"e_cabf_mtc_subscriber_reserved_dns_label",
		"e_cabf_mtc_subscriber_reserved_ip",
		"e_cabf_mtc_subscriber_san_critical_with_subject",
		"e_cabf_mtc_subscriber_san_duplicate",
		"e_cabf_mtc_subscriber_san_malformed",
		"e_cabf_mtc_subscriber_san_missing",
		"e_cabf_mtc_subscriber_san_name_type",
		"e_cabf_mtc_subscriber_spki_invalid",
		"e_cabf_mtc_subscriber_unique_id_present",
		"e_cabf_mtc_subscriber_unknown_critical_extension",
		"w_cabf_mtc_subscriber_aia_missing_ca_issuers",
		"w_cabf_mtc_subscriber_crldp_multiple",
		"w_cabf_mtc_subscriber_ec_key_agreement",
		"w_cabf_mtc_subscriber_extension_not_recommended",
		"w_cabf_mtc_subscriber_iv_subject_attributes_not_recommended",
		"w_cabf_mtc_subscriber_key_usage_missing",
		"w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended",
		"w_cabf_mtc_subscriber_rsa_data_encipherment",
		"w_cabf_mtc_subscriber_rsa_digital_signature_missing",
		"w_cabf_mtc_subscriber_rsa_public_exponent_not_recommended",
		"w_cabf_mtc_subscriber_ski_present",
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
		{ID: mtctest.OIDCountryName, RawValue: mtctest.PrintableStringDER("US")},
		{ID: mtctest.OIDLocalityName, Value: "Example City"},
		{ID: mtctest.OIDOrganizationName, Value: "Example Organization"},
	}
	tpl.Subject = mtctest.NameDER(append(attributes, extra...)...)
}

func setNonCriticalDefaultSAN(tpl *mtctest.Template) {
	mtctest.ReplaceExtension(tpl, mtctest.Extension{ID: mtctest.OIDSubjectAltName, Value: mtctest.GeneralNamesDER(mtctest.DNSNameGeneralNameDER("subscriber.example.com"))})
}

func setDefaultSubscriberKeyUsage(tpl *mtctest.Template) {
	mtctest.ReplaceExtension(tpl, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageBitsDER(0x8000)})
}

func TestCABFTLSSubscriberCriticalSANErrorSeverity(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	setDefaultSubscriberKeyUsage(&tpl)
	setOVSubjectAndPolicy(&tpl)
	findings := LintCABFTLSSubscriberForKind(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate), ArtifactSubscriber)
	if len(findings) != 1 || findings[0].Code != "e_cabf_mtc_subscriber_san_critical_with_subject" || findings[0].Severity != Error {
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
