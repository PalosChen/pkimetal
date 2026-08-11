package zlint

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	cryptox509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/linter"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
)

func registeredZlint(t *testing.T) *linter.Linter {
	t.Helper()
	for _, registered := range linter.Linters {
		if registered.Name == "zlint" {
			return registered
		}
	}
	t.Fatal("zlint is not registered")
	return nil
}

func TestRegistrationDeclaresMTCApplicability(t *testing.T) {
	registered := registeredZlint(t)
	want := []linter.ProfileId{linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER}
	if !slices.Equal(registered.Supported, want) {
		t.Fatalf("supported profiles = %#v, want %#v", registered.Supported, want)
	}
	if registered.Applicable == nil {
		t.Fatal("zlint applicability callback is nil")
	}
	if applicable, reason := registered.Applicable(nil); applicable || reason != "" {
		t.Fatalf("nil request applicability = %t, %q", applicable, reason)
	}
	if applicable, reason := registered.Applicable(&linter.LintingRequest{ProfileId: linter.MTC_CA}); applicable || reason != "zcrypto could not safely parse this MTC artifact" {
		t.Fatalf("nil MTC certificate applicability = %t, %q", applicable, reason)
	}
	if applicable, reason := registered.Applicable(&linter.LintingRequest{ProfileId: linter.MTC_CA, Cert: &x509.Certificate{}}); !applicable || reason != "" {
		t.Fatalf("usable MTC certificate applicability = %t, %q", applicable, reason)
	}
	if applicable, reason := registered.Applicable(&linter.LintingRequest{ProfileId: linter.RFC5280_ROOT}); !applicable || reason != "" {
		t.Fatalf("legacy applicability = %t, %q", applicable, reason)
	}
}

func TestCQRPMTCLeafRegistryExcludesOnlyKnownMTCConflicts(t *testing.T) {
	for _, name := range []string{
		"e_signature_algorithm_not_supported",
		"e_public_key_type_not_allowed",
		"e_algorithm_identifier_improper_encoding",
		"w_ct_sct_policy_count_unsatisfied",
	} {
		if cqrpMTCLeafRegistry.CertificateLints().ByName(name) != nil {
			t.Errorf("%s was not excluded", name)
		}
	}
	for _, name := range []string{
		"e_serial_number_longer_than_20_octets",
		"e_dnsname_bad_character_in_label",
	} {
		if cqrpMTCLeafRegistry.CertificateLints().ByName(name) == nil {
			t.Errorf("compatible lint %s was excluded", name)
		}
	}
}

func TestMTCRegistrySelection(t *testing.T) {
	for _, profile := range []linter.ProfileId{linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA} {
		registry := registryForProfile(profile)
		for _, source := range []lint.LintSource{
			lint.CABFBaselineRequirements,
			lint.CABFEVGuidelines,
			lint.CABFSMIMEBaselineRequirements,
			lint.CABFCSBaselineRequirements,
		} {
			if slices.Contains(registry.Sources(), source) {
				t.Errorf("profile %s registry contains CABF source %s", linter.AllProfiles[profile].Name, source)
			}
		}
	}
	if got := registryForProfile(linter.CQRP_MTC_SUBSCRIBER); got != cqrpMTCLeafRegistry {
		t.Fatal("CQRP MTC subscriber did not select the compatible CABF leaf registry")
	}
	if registryForProfile(linter.RFC5280_ROOT) != notCabforumRegistry {
		t.Fatal("legacy non-CABF registry selection changed")
	}
}

func TestMTCProfilesRunCompatibleSerialLint(t *testing.T) {
	cert := syntheticZcryptoCertificate(t)
	cert.SerialNumber = new(big.Int).Lsh(big.NewInt(1), 160)

	for _, profile := range []linter.ProfileId{linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER} {
		results := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
			Cert:      cert,
			ProfileId: profile,
		})
		if !hasFinding(results, "e_serial_number_longer_than_20_octets") {
			t.Errorf("profile %s did not run the compatible serial-number lint", linter.AllProfiles[profile].Name)
		}
	}
}

func TestHandleRequestMTCNilCertificateDoesNotPanic(t *testing.T) {
	for _, profile := range []linter.ProfileId{linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER} {
		if results := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{ProfileId: profile}); results != nil {
			t.Errorf("profile %s results = %#v, want nil", linter.AllProfiles[profile].Name, results)
		}
	}
	if results := (&Zlint{}).HandleRequest(context.Background(), nil, nil); results != nil {
		t.Errorf("nil request results = %#v, want nil", results)
	}
}

func syntheticZcryptoCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	now := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	template := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "subscriber.example"},
		DNSNames:              []string{"subscriber.example"},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              cryptox509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []cryptox509.ExtKeyUsage{cryptox509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := cryptox509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("zcrypto failed to parse test certificate: %v", err)
	}
	return cert
}

func testCRLDER(t *testing.T, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	issuer := &cryptox509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             thisUpdate.Add(-time.Hour),
		NotAfter:              nextUpdate.Add(time.Hour),
		KeyUsage:              cryptox509.KeyUsageCertSign | cryptox509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	crl := &cryptox509.RevocationList{
		SignatureAlgorithm: cryptox509.SHA256WithRSA,
		Number:             big.NewInt(1),
		ThisUpdate:         thisUpdate,
		NextUpdate:         nextUpdate,
	}
	der, err := cryptox509.CreateRevocationList(rand.Reader, crl, issuer, key)
	if err != nil {
		t.Fatalf("failed to generate test CRL: %v", err)
	}
	return der
}

func hasFinding(results []linter.LintingResult, code string) bool {
	for _, result := range results {
		if result.Code == code {
			return true
		}
	}
	return false
}

func TestTBRCRLUsesSubscriberCRLNextUpdateLimit(t *testing.T) {
	thisUpdate := time.Date(2026, time.June, 24, 13, 0, 0, 0, time.UTC)

	validCRLResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: testCRLDER(t, thisUpdate, thisUpdate.AddDate(0, 0, 9)),
		ProfileId:    linter.TBR_CRL,
	})
	if hasFinding(validCRLResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR CRL reported nextUpdate limit violation for a 9-day subscriber CRL")
	}

	invalidCRLResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: testCRLDER(t, thisUpdate, thisUpdate.AddDate(0, 0, 11)),
		ProfileId:    linter.TBR_CRL,
	})
	if !hasFinding(invalidCRLResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR CRL did not report nextUpdate limit violation for an 11-day subscriber CRL")
	}
}

func TestTBRARLUsesCACRLNextUpdateLimit(t *testing.T) {
	thisUpdate := time.Date(2026, time.June, 24, 13, 0, 0, 0, time.UTC)
	crlDER := testCRLDER(t, thisUpdate, thisUpdate.AddDate(0, 11, 0))

	crlResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: crlDER,
		ProfileId:    linter.TBR_CRL,
	})
	if !hasFinding(crlResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR CRL did not report subscriber nextUpdate limit violation")
	}

	arlResults := (&Zlint{}).HandleRequest(context.Background(), nil, &linter.LintingRequest{
		DecodedInput: crlDER,
		ProfileId:    linter.TBR_ARL,
	})
	if hasFinding(arlResults, "e_crl_next_update_invalid") {
		t.Fatal("TBR ARL reported subscriber nextUpdate limit violation")
	}
}
