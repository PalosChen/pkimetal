package mtc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	zlintutil "github.com/zmap/zlint/v3/util"
	"golang.org/x/net/idna"
)

const (
	rfc5280Source   = "RFC 5280"
	cabfTLSBRSource = "CA/B Forum TLS Baseline Requirements"

	keyUsageDigitalSignature = uint16(0x8000)
	keyUsageKeyEncipherment  = uint16(0x2000)
	keyUsageDataEncipherment = uint16(0x1000)
	keyUsageKeyAgreement     = uint16(0x0800)
	keyUsageCABits           = uint16(0x0600)
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidNameConstraints        = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidAuthorityInfoAccess    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidAccessMethodOCSP       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAccessMethodCAIssuers  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	oidRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey            = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidCountryName            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidLocalityName           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidStateOrProvinceName    = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress          = asn1.ObjectIdentifier{2, 5, 4, 9}
	oidBusinessCategory       = asn1.ObjectIdentifier{2, 5, 4, 15}
	oidSerialNumber           = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidPostalCode             = asn1.ObjectIdentifier{2, 5, 4, 17}
	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	oidSurname                = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidGivenName              = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidOrganizationalUnitName = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidDomainComponent        = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidJurisdictionLocality   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}
	oidJurisdictionState      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}
	oidJurisdictionCountry    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}
)

type generalName struct {
	tag      int
	contents []byte
}

var rfc5280SubscriberRules = []Rule{
	subscriberProfileRule("e_rfc5280_mtc_subscriber_not_v3", rfc5280Source, "4.1", func(a *Artifact) *Finding {
		if len(a.Extensions) != 0 && a.Version != 3 {
			return errorFinding("tbsCertificate.version", "subscriber certificate contains extensions but is not version 3")
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_validity_order", rfc5280Source, "4.1.2.5", func(a *Artifact) *Finding {
		if !a.NotAfter.After(a.NotBefore) {
			return errorFinding("tbsCertificate.validity", "subscriber certificate notAfter is not later than notBefore")
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_duplicate_extension", rfc5280Source, "4.2", func(a *Artifact) *Finding {
		seen := make(map[string]struct{}, len(a.Extensions))
		for _, extension := range a.Extensions {
			key := extension.ID.String()
			if _, ok := seen[key]; ok && !extension.ID.Equal(oidSubjectAlternativeName) {
				return errorFinding("tbsCertificate.extensions", "subscriber certificate contains a duplicate extension")
			}
			seen[key] = struct{}{}
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_unknown_critical_extension", rfc5280Source, "4.2", func(a *Artifact) *Finding {
		for _, extension := range a.Extensions {
			if extension.Critical && !knownSubscriberExtension(extension.ID) {
				return errorFinding("tbsCertificate.extensions", "subscriber certificate contains an unrecognized critical extension")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_basic_constraints", rfc5280Source, "4.2.1.9", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidBasicConstraints)
		if len(extensions) == 1 && !bytes.Equal(extensions[0].Value, []byte{0x30, 0x00}) {
			return errorFinding("tbsCertificate.extensions.basicConstraints", "subscriber basic constraints is malformed or asserts CA capabilities")
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_key_usage_malformed", rfc5280Source, "4.2.1.3", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidKeyUsage)
		if len(extensions) == 1 {
			if _, ok := parseKeyUsage(extensions[0].Value); !ok {
				return errorFinding("tbsCertificate.extensions.keyUsage", "subscriber key usage extension is malformed")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_ski", rfc5280Source, "4.2.1.2", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidSubjectKeyIdentifier)
		if len(extensions) == 1 && (extensions[0].Critical || !validSubjectKeyIdentifier(extensions[0].Value)) {
			return errorFinding("tbsCertificate.extensions.subjectKeyIdentifier", "subscriber subject key identifier is critical or malformed")
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_aki", rfc5280Source, "4.2.1.1", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidAuthorityKeyIdentifier)
		if len(extensions) == 0 || (len(extensions) == 1 && (extensions[0].Critical || !validAuthorityKeyIdentifier(extensions[0].Value))) {
			return errorFinding("tbsCertificate.extensions.authorityKeyIdentifier", "subscriber authority key identifier is missing, critical, or malformed")
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_san_missing", rfc5280Source, "4.1.2.6 and 4.2.1.6", func(a *Artifact) *Finding {
		if subjectIsEmpty(a) && countExtensions(a, oidSubjectAlternativeName) == 0 {
			return errorFinding("tbsCertificate.extensions.subjectAltName", "subject alternative name extension is required when the subject is empty")
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_san_not_critical", rfc5280Source, "4.1.2.6 and 4.2.1.6", func(a *Artifact) *Finding {
		if !subjectIsEmpty(a) {
			return nil
		}
		for _, extension := range matchingExtensions(a, oidSubjectAlternativeName) {
			if !extension.Critical {
				return errorFinding("tbsCertificate.extensions.subjectAltName", "subject alternative name extension is not critical when the subject is empty")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_san_duplicate", rfc5280Source, "4.2", func(a *Artifact) *Finding {
		if countExtensions(a, oidSubjectAlternativeName) > 1 {
			return errorFinding("tbsCertificate.extensions.subjectAltName", "subject alternative name extension is duplicated")
		}
		return nil
	}),
	subscriberProfileRule("e_rfc5280_mtc_subscriber_san_malformed", rfc5280Source, "4.2.1.6", func(a *Artifact) *Finding {
		for _, extension := range matchingExtensions(a, oidSubjectAlternativeName) {
			names, ok := parseSubjectAlternativeNames(extension.Value)
			if !ok || !validRFC5280GeneralNames(names) {
				return errorFinding("tbsCertificate.extensions.subjectAltName", "subject alternative name extension is malformed")
			}
		}
		return nil
	}),
}

var cabfTLSSubscriberRules = []Rule{
	subscriberProfileRule("e_cabf_mtc_subscriber_not_v3", cabfTLSBRSource, "7.1.2.7", func(a *Artifact) *Finding {
		if a.Version != 3 {
			return errorFinding("tbsCertificate.version", "TLS subscriber certificate is not version 3")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_aia_missing", cabfTLSBRSource, "7.1.2.7.6 and 7.1.2.7.7", func(a *Artifact) *Finding {
		if countExtensions(a, oidAuthorityInfoAccess) == 0 {
			return errorFinding("tbsCertificate.extensions.authorityInformationAccess", "TLS subscriber certificate has no authority information access extension")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_aia_not_critical", cabfTLSBRSource, "7.1.2.7.6", func(a *Artifact) *Finding {
		for _, extension := range matchingExtensions(a, oidAuthorityInfoAccess) {
			if extension.Critical {
				return errorFinding("tbsCertificate.extensions.authorityInformationAccess", "TLS subscriber authority information access extension is critical")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_aia_invalid", cabfTLSBRSource, "7.1.2.7.7", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidAuthorityInfoAccess)
		if len(extensions) > 0 && (len(extensions) != 1 || !validCABFAuthorityInformationAccess(extensions[0].Value)) {
			return errorFinding("tbsCertificate.extensions.authorityInformationAccess", "TLS subscriber authority information access extension is malformed or contains a prohibited access method or location")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_aia_missing_ca_issuers", cabfTLSBRSource, "7.1.2.7.7", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidAuthorityInfoAccess)
		if len(extensions) != 1 {
			return nil
		}
		info, valid := parseCABFAuthorityInformationAccess(extensions[0].Value)
		if valid && !info.hasCAIssuers {
			return warningFinding("tbsCertificate.extensions.authorityInformationAccess", "TLS subscriber authority information access extension does not contain a caIssuers access method")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_crldp_missing", cabfTLSBRSource, "7.1.2.11.2", func(a *Artifact) *Finding {
		sc63EffectiveDate := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
		sevenDayEffectiveDate := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
		if a.NotBefore.Before(sc63EffectiveDate) {
			return nil
		}
		shortLivedLimit := 10 * 24 * time.Hour
		if !a.NotBefore.Before(sevenDayEffectiveDate) {
			shortLivedLimit = 7 * 24 * time.Hour
		}
		if a.NotAfter.Sub(a.NotBefore) <= shortLivedLimit {
			return nil
		}
		for _, extension := range matchingExtensions(a, oidAuthorityInfoAccess) {
			if info, valid := parseCABFAuthorityInformationAccess(extension.Value); valid && info.hasOCSP {
				return nil
			}
		}
		if countExtensions(a, oidCRLDistributionPoints) == 0 {
			return errorFinding("tbsCertificate.extensions.cRLDistributionPoints", "TLS subscriber certificate without OCSP is not short-lived and has no CRL distribution points extension")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_crldp_not_critical", cabfTLSBRSource, "7.1.2.11.2", func(a *Artifact) *Finding {
		for _, extension := range matchingExtensions(a, oidCRLDistributionPoints) {
			if extension.Critical {
				return errorFinding("tbsCertificate.extensions.cRLDistributionPoints", "TLS subscriber CRL distribution points extension is critical")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_crldp_invalid", cabfTLSBRSource, "7.1.2.11.2", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidCRLDistributionPoints)
		if len(extensions) > 0 && (len(extensions) != 1 || !validCABFCRLDistributionPoints(extensions[0].Value)) {
			return errorFinding("tbsCertificate.extensions.cRLDistributionPoints", "TLS subscriber CRL distribution points extension is malformed or contains a non-HTTP location")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_crldp_multiple", cabfTLSBRSource, "7.1.2.11.2", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidCRLDistributionPoints)
		if len(extensions) != 1 {
			return nil
		}
		count, valid := parseCABFCRLDistributionPoints(extensions[0].Value)
		if valid && count > 1 {
			return warningFinding("tbsCertificate.extensions.cRLDistributionPoints", "TLS subscriber certificate contains more than one CRL distribution point")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_aki_missing", cabfTLSBRSource, "7.1.2.7.6 and 7.1.2.11.1", func(a *Artifact) *Finding {
		if countExtensions(a, oidAuthorityKeyIdentifier) == 0 {
			return errorFinding("tbsCertificate.extensions.authorityKeyIdentifier", "TLS subscriber certificate has no authority key identifier extension")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_aki_not_critical", cabfTLSBRSource, "7.1.2.7.6", func(a *Artifact) *Finding {
		for _, extension := range matchingExtensions(a, oidAuthorityKeyIdentifier) {
			if extension.Critical {
				return errorFinding("tbsCertificate.extensions.authorityKeyIdentifier", "TLS subscriber authority key identifier extension is critical")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_aki_invalid", cabfTLSBRSource, "7.1.2.11.1", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidAuthorityKeyIdentifier)
		if len(extensions) > 0 && (len(extensions) != 1 || !validCABFAuthorityKeyIdentifier(extensions[0].Value)) {
			return errorFinding("tbsCertificate.extensions.authorityKeyIdentifier", "TLS subscriber authority key identifier must contain only a non-empty keyIdentifier")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_ski_present", cabfTLSBRSource, "7.1.2.7.6", func(a *Artifact) *Finding {
		if countExtensions(a, oidSubjectKeyIdentifier) != 0 {
			return warningFinding("tbsCertificate.extensions.subjectKeyIdentifier", "TLS subscriber certificate contains a not-recommended subject key identifier extension")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_unique_id_present", cabfTLSBRSource, "7.1.2.7", func(a *Artifact) *Finding {
		if a.IssuerUniqueIDPresent || a.SubjectUniqueIDPresent {
			return errorFinding("tbsCertificate.issuerUniqueID,tbsCertificate.subjectUniqueID", "TLS subscriber certificate contains a prohibited unique identifier field")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_extension_not_recommended", cabfTLSBRSource, "7.1.2.7.6", func(a *Artifact) *Finding {
		for _, extension := range a.Extensions {
			if !extension.Critical && !knownSubscriberExtension(extension.ID) {
				return warningFinding("tbsCertificate.extensions", "TLS subscriber certificate contains an extension that is not recommended by its certificate profile")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_unknown_critical_extension", rfc5280Source, "4.2", func(a *Artifact) *Finding {
		for _, extension := range a.Extensions {
			if extension.Critical && !knownSubscriberExtension(extension.ID) {
				return errorFinding("tbsCertificate.extensions", "TLS subscriber certificate contains an unrecognized critical extension")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_spki_invalid", cabfTLSBRSource, "6.1.5 and 7.1.3.1", func(a *Artifact) *Finding {
		algorithm := a.SubjectPublicKey.Algorithm.Algorithm
		if !algorithm.Equal(oidRSAEncryption) && !algorithm.Equal(oidECPublicKey) {
			return nil
		}
		key, err := x509.ParsePKIXPublicKey(a.SubjectPublicKey.Raw)
		if err != nil || !validTraditionalSubscriberPublicKey(key) {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo", "TLS subscriber certificate contains an invalid or insufficiently strong traditional public key")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_rsa_public_exponent_not_recommended", cabfTLSBRSource, "6.1.6", func(a *Artifact) *Finding {
		if !a.SubjectPublicKey.Algorithm.Algorithm.Equal(oidRSAEncryption) {
			return nil
		}
		key, err := x509.ParsePKIXPublicKey(a.SubjectPublicKey.Raw)
		publicKey, ok := key.(*rsa.PublicKey)
		if err == nil && ok && publicKey.E >= 3 && publicKey.E < 65537 && publicKey.E%2 == 1 {
			return warningFinding("tbsCertificate.subjectPublicKeyInfo", "TLS subscriber RSA public exponent is valid but lower than the recommended value 65537")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_name_constraints_present", cabfTLSBRSource, "7.1.2.7.6", func(a *Artifact) *Finding {
		if countExtensions(a, oidNameConstraints) != 0 {
			return errorFinding("tbsCertificate.extensions.nameConstraints", "TLS subscriber certificate contains a prohibited name constraints extension")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_basic_constraints_not_critical", cabfTLSBRSource, "7.1.2.7.6", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidBasicConstraints)
		if len(extensions) == 1 && !extensions[0].Critical {
			return errorFinding("tbsCertificate.extensions.basicConstraints", "TLS subscriber basic constraints extension is not critical")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_key_usage_ca_bits", cabfTLSBRSource, "7.1.2.7.11", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidKeyUsage)
		if len(extensions) == 1 {
			usage, ok := parseKeyUsage(extensions[0].Value)
			if ok && usage&0x0600 != 0 {
				return errorFinding("tbsCertificate.extensions.keyUsage", "TLS subscriber key usage asserts keyCertSign or cRLSign")
			}
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_key_usage_missing", cabfTLSBRSource, "7.1.2.7.11", func(a *Artifact) *Finding {
		if countExtensions(a, oidKeyUsage) == 0 {
			return warningFinding("tbsCertificate.extensions.keyUsage", "TLS subscriber key usage extension is absent but recommended")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_key_usage_not_critical", cabfTLSBRSource, "7.1.2.7.11", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidKeyUsage)
		if len(extensions) == 1 && !extensions[0].Critical {
			return errorFinding("tbsCertificate.extensions.keyUsage", "TLS subscriber key usage extension is not critical")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_key_usage_invalid", cabfTLSBRSource, "7.1.2.7.11", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidKeyUsage)
		if len(extensions) != 1 {
			return nil
		}
		usage, ok := parseKeyUsage(extensions[0].Value)
		if !ok {
			return nil
		}
		usageWithoutCABits := usage &^ keyUsageCABits
		if usageWithoutCABits == 0 && usage&keyUsageCABits != 0 {
			return nil
		}
		switch {
		case a.SubjectPublicKey.Algorithm.Algorithm.Equal(oidRSAEncryption):
			allowed := keyUsageDigitalSignature | keyUsageKeyEncipherment | keyUsageDataEncipherment
			if usageWithoutCABits&allowed == 0 || usageWithoutCABits & ^allowed != 0 {
				return errorFinding("tbsCertificate.extensions.keyUsage", "RSA TLS subscriber key usage has no permitted purpose or asserts a prohibited purpose")
			}
		case a.SubjectPublicKey.Algorithm.Algorithm.Equal(oidECPublicKey):
			allowed := keyUsageDigitalSignature | keyUsageKeyAgreement
			if usageWithoutCABits&keyUsageDigitalSignature == 0 || usageWithoutCABits & ^allowed != 0 {
				return errorFinding("tbsCertificate.extensions.keyUsage", "ECDSA TLS subscriber key usage omits digitalSignature or asserts a prohibited purpose")
			}
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_rsa_digital_signature_missing", cabfTLSBRSource, "7.1.2.7.11", func(a *Artifact) *Finding {
		usage, ok := singlePermittedSubscriberKeyUsage(a)
		if ok && a.SubjectPublicKey.Algorithm.Algorithm.Equal(oidRSAEncryption) && usage&keyUsageDigitalSignature == 0 {
			return warningFinding("tbsCertificate.extensions.keyUsage", "RSA TLS subscriber key usage omits the recommended digitalSignature purpose")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_rsa_data_encipherment", cabfTLSBRSource, "7.1.2.7.11", func(a *Artifact) *Finding {
		usage, ok := singlePermittedSubscriberKeyUsage(a)
		if ok && a.SubjectPublicKey.Algorithm.Algorithm.Equal(oidRSAEncryption) && usage&keyUsageDataEncipherment != 0 {
			return warningFinding("tbsCertificate.extensions.keyUsage", "RSA TLS subscriber key usage asserts the not-recommended dataEncipherment purpose")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_ec_key_agreement", cabfTLSBRSource, "7.1.2.7.11", func(a *Artifact) *Finding {
		usage, ok := singlePermittedSubscriberKeyUsage(a)
		if ok && a.SubjectPublicKey.Algorithm.Algorithm.Equal(oidECPublicKey) && usage&keyUsageKeyAgreement != 0 {
			return warningFinding("tbsCertificate.extensions.keyUsage", "ECDSA TLS subscriber key usage asserts the not-recommended keyAgreement purpose")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_san_missing", cabfTLSBRSource, "7.1.4.2.1", func(a *Artifact) *Finding {
		if countExtensions(a, oidSubjectAlternativeName) == 0 {
			return errorFinding("tbsCertificate.extensions.subjectAltName", "TLS subscriber certificate has no subject alternative name extension")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_san_duplicate", rfc5280Source, "4.2", func(a *Artifact) *Finding {
		if countExtensions(a, oidSubjectAlternativeName) > 1 {
			return errorFinding("tbsCertificate.extensions.subjectAltName", "TLS subscriber subject alternative name extension is duplicated")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_san_malformed", rfc5280Source, "4.2.1.6", func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidSubjectAlternativeName)
		if len(extensions) == 1 {
			if _, ok := parseSubjectAlternativeNames(extensions[0].Value); !ok {
				return errorFinding("tbsCertificate.extensions.subjectAltName", "TLS subscriber subject alternative name extension is malformed")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_san_name_type", cabfTLSBRSource, "7.1.4.2.1", func(a *Artifact) *Finding {
		for _, name := range parsedSubjectAlternativeNames(a) {
			if name.tag != 2 && name.tag != 7 {
				return errorFinding("tbsCertificate.extensions.subjectAltName", "TLS subscriber subject alternative name contains a name other than dNSName or iPAddress")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_dns_name_invalid", cabfTLSBRSource, "3.2.2.4 and 7.1.4.2.1", func(a *Artifact) *Finding {
		for _, name := range parsedSubjectAlternativeNames(a) {
			if name.tag == 2 && !validCABFDNSName(name.contents, a.NotBefore) {
				return errorFinding("tbsCertificate.extensions.subjectAltName.dNSName", "TLS subscriber subject alternative name contains an invalid dNSName")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_ip_address_invalid", cabfTLSBRSource, "7.1.4.2.1", func(a *Artifact) *Finding {
		for _, name := range parsedSubjectAlternativeNames(a) {
			if name.tag == 7 && len(name.contents) != 4 && len(name.contents) != 16 {
				return errorFinding("tbsCertificate.extensions.subjectAltName.iPAddress", "TLS subscriber subject alternative name contains an invalid iPAddress")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_reserved_ip", cabfTLSBRSource, "7.1.4.2.1", func(a *Artifact) *Finding {
		for _, name := range parsedSubjectAlternativeNames(a) {
			if name.tag == 7 && (len(name.contents) == net.IPv4len || len(name.contents) == net.IPv6len) && zlintutil.IsIANAReserved(net.IP(name.contents)) {
				return errorFinding("tbsCertificate.extensions.subjectAltName.iPAddress", "TLS subscriber subject alternative name contains a reserved IP address")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_reserved_dns_label", cabfTLSBRSource, "7.1.4.2.1", func(a *Artifact) *Finding {
		for _, name := range parsedSubjectAlternativeNames(a) {
			if name.tag == 2 && containsReservedLDHLabel(string(name.contents)) {
				return errorFinding("tbsCertificate.extensions.subjectAltName.dNSName", "TLS subscriber subject alternative name contains a reserved LDH label")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_common_name_not_in_san", cabfTLSBRSource, "7.1.4.2.2", func(a *Artifact) *Finding {
		attributes, ok := parseSubjectAttributes(a.SubjectRaw)
		if !ok {
			return nil
		}
		var commonNames []string
		for _, attribute := range attributes {
			if attribute.id.Equal(oidCommonName) {
				commonNames = append(commonNames, attribute.value)
			}
		}
		if len(commonNames) == 0 {
			return nil
		}
		if len(commonNames) != 1 || !commonNameInSAN(commonNames[0], parsedSubjectAlternativeNames(a)) {
			return errorFinding("tbsCertificate.subject.commonName", "TLS subscriber common name is not an exact copy of a subject alternative name")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_ov_subject", cabfTLSBRSource, "7.1.2.7.4", func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if !ok || !containsOID(policies, oidPolicyOV) {
			return nil
		}
		attributes, ok := parseSubjectAttributes(a.SubjectRaw)
		if !ok || !validOVSubjectAttributes(attributes) || !validDomainComponentSequence(attributes, a.NotBefore) {
			return errorFinding("tbsCertificate.subject", "OV TLS subscriber subject does not satisfy the required identity attribute profile")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_iv_subject", cabfTLSBRSource, "7.1.2.7.3", func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if !ok || !containsOID(policies, oidPolicyIV) {
			return nil
		}
		attributes, ok := parseSubjectAttributes(a.SubjectRaw)
		if !ok || !validIVSubjectAttributes(attributes) || !validDomainComponentSequence(attributes, a.NotBefore) {
			return errorFinding("tbsCertificate.subject", "IV TLS subscriber subject does not satisfy the required identity attribute profile")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_iv_subject_attributes_not_recommended", cabfTLSBRSource, "7.1.2.7.3", func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if !ok || len(policies) != 1 || !policies[0].Equal(oidPolicyIV) {
			return nil
		}
		attributes, ok := parseSubjectAttributes(a.SubjectRaw)
		if !ok || !validIVSubjectAttributes(attributes) || !validDomainComponentSequence(attributes, a.NotBefore) {
			return nil
		}
		for _, attribute := range attributes {
			if !recommendedIVSubjectAttribute(attribute.id) {
				return warningFinding("tbsCertificate.subject", "IV TLS subscriber subject contains an attribute that is not recommended")
			}
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_ov_subject_attributes_not_recommended", cabfTLSBRSource, "7.1.2.7.4", func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if !ok || len(policies) != 1 || !policies[0].Equal(oidPolicyOV) {
			return nil
		}
		attributes, ok := parseSubjectAttributes(a.SubjectRaw)
		if !ok || !validOVSubjectAttributes(attributes) || !validDomainComponentSequence(attributes, a.NotBefore) {
			return nil
		}
		for _, attribute := range attributes {
			if !recommendedOVSubjectAttribute(attribute.id) {
				return warningFinding("tbsCertificate.subject", "OV TLS subscriber subject contains an attribute that is not recommended")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_san_critical_with_subject", cabfTLSBRSource, "7.1.2.7.12", func(a *Artifact) *Finding {
		if subjectIsEmpty(a) {
			return nil
		}
		for _, extension := range matchingExtensions(a, oidSubjectAlternativeName) {
			if extension.Critical {
				return errorFinding("tbsCertificate.extensions.subjectAltName", "TLS subscriber subject alternative name is critical although the subject is not empty")
			}
		}
		return nil
	}),
}

// LintRFC5280SubscriberForKind evaluates RFC 5280 subscriber rules in an
// explicit profile context without changing the parsed artifact.
func LintRFC5280SubscriberForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	return lintSubscriberProfileForKind(artifact, expected, rfc5280SubscriberRules)
}

// LintCABFTLSSubscriberForKind evaluates CABF TLS subscriber rules in an
// explicit profile context without changing the parsed artifact.
func LintCABFTLSSubscriberForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	return lintSubscriberProfileForKind(artifact, expected, cabfTLSSubscriberRules)
}

func RFC5280SubscriberRuleCodes() []string {
	return subscriberProfileRuleCodes(rfc5280SubscriberRules)
}

func CABFTLSSubscriberRuleCodes() []string {
	return subscriberProfileRuleCodes(cabfTLSSubscriberRules)
}

func lintSubscriberProfileForKind(artifact *Artifact, expected ArtifactKind, rules []Rule) []Finding {
	if artifact == nil || expected != ArtifactSubscriber {
		return nil
	}
	local := *artifact
	local.Kind = ArtifactSubscriber
	return runRules(&local, rules)
}

func subscriberProfileRule(code, source, section string, evaluate func(*Artifact) *Finding) Rule {
	return Rule{Code: code, Source: source, Section: section, Kinds: subscriberKinds, InputKinds: bothInputKinds, Evaluate: evaluate}
}

func subscriberProfileRuleCodes(rules []Rule) []string {
	codes := make([]string, len(rules))
	for i, rule := range rules {
		codes[i] = rule.Code
	}
	sort.Strings(codes)
	return codes
}

func subjectIsEmpty(artifact *Artifact) bool {
	return bytes.Equal(artifact.SubjectRaw, []byte{0x30, 0x00})
}

func parsedSubjectAlternativeNames(artifact *Artifact) []generalName {
	extensions := matchingExtensions(artifact, oidSubjectAlternativeName)
	if len(extensions) != 1 {
		return nil
	}
	names, ok := parseSubjectAlternativeNames(extensions[0].Value)
	if !ok {
		return nil
	}
	return names
}

func parseSubjectAlternativeNames(input []byte) ([]generalName, bool) {
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "subjectAltName") != nil || len(sequence.contents) == 0 {
		return nil, false
	}

	remaining := sequence.contents
	names := make([]generalName, 0, 1)
	for len(remaining) != 0 {
		value, rest, err := parseDER(remaining)
		if err != nil || !validGeneralNameStructure(value) {
			return nil, false
		}
		names = append(names, generalName{tag: value.tag, contents: value.contents})
		remaining = rest
	}
	return names, true
}

func validGeneralNameStructure(value derValue) bool {
	if value.class != classContext || value.tag < 0 || value.tag > 8 {
		return false
	}
	switch value.tag {
	case 0, 3, 5:
		return value.constructed && len(value.contents) != 0
	case 1, 2, 6:
		return !value.constructed
	case 4:
		if !value.constructed || len(value.contents) == 0 {
			return false
		}
		name, rest, err := parseDER(value.contents)
		return err == nil && len(rest) == 0 && expectDER(name, classUniversal, asn1.TagSequence, true, "directoryName") == nil
	case 7:
		return !value.constructed
	case 8:
		return !value.constructed && isMinimalBase128(value.contents)
	default:
		return false
	}
}

func validRFC5280GeneralNames(names []generalName) bool {
	for _, name := range names {
		if len(name.contents) == 0 {
			return false
		}
		if (name.tag == 1 || name.tag == 2 || name.tag == 6) && !allBytes(name.contents, func(b byte) bool { return b <= 0x7f }) {
			return false
		}
	}
	return true
}

func validCABFDNSName(input []byte, when time.Time) bool {
	if len(input) == 0 || len(input) > 253 || input[0] == '.' || input[len(input)-1] == '.' {
		return false
	}
	name := string(input)
	if net.ParseIP(name) != nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for i, label := range labels {
		if label == "*" {
			if i != 0 {
				return false
			}
			continue
		}
		if !validCABFDNSLabel(label) {
			return false
		}
	}
	registrableName := name
	if labels[0] == "*" {
		registrableName = strings.TrimPrefix(name, "*.")
	}
	registrableLabels := strings.Split(registrableName, ".")
	if len(registrableLabels) < 2 || (!when.Before(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)) && hasIPReverseZoneSuffix(registrableLabels)) {
		return false
	}
	return zlintutil.HasValidTLD(registrableName, when)
}

func hasIPReverseZoneSuffix(labels []string) bool {
	if len(labels) < 2 || !strings.EqualFold(labels[len(labels)-1], "arpa") {
		return false
	}
	penultimate := labels[len(labels)-2]
	return strings.EqualFold(penultimate, "in-addr") || strings.EqualFold(penultimate, "ip6")
}

func validCABFDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		b := label[i]
		if b > 0x7f || b != '-' && (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return false
		}
	}
	if strings.HasPrefix(strings.ToLower(label), "xn--") {
		ascii, err := idna.Lookup.ToASCII(label)
		return err == nil && strings.EqualFold(ascii, label)
	}
	return true
}

type subjectAttribute struct {
	id      asn1.ObjectIdentifier
	value   string
	textual bool
}

func knownSubscriberExtension(oid asn1.ObjectIdentifier) bool {
	known := []asn1.ObjectIdentifier{
		oidSubjectKeyIdentifier,
		oidKeyUsage,
		oidSubjectAlternativeName,
		oidIssuerAlternativeName,
		oidBasicConstraints,
		oidNameConstraints,
		oidCRLDistributionPoints,
		oidAuthorityKeyIdentifier,
		oidAuthorityInfoAccess,
		oidCertificatePolicies,
		oidExtendedKeyUsage,
		oidSCTList,
		OIDMTCCertificationAuthority,
		OIDMTCTlogPrefixURL,
	}
	for _, candidate := range known {
		if oid.Equal(candidate) {
			return true
		}
	}
	return false
}

func parseKeyUsage(input []byte) (uint16, bool) {
	value, err := parseExactDER(input)
	if err != nil {
		return 0, false
	}
	bits, _, err := parseBitString(value, "keyUsage")
	if err != nil || len(bits) == 0 || len(bits) > 2 {
		return 0, false
	}
	usage := uint16(bits[0]) << 8
	if len(bits) == 2 {
		usage |= uint16(bits[1])
	}
	return usage, true
}

func singlePermittedSubscriberKeyUsage(artifact *Artifact) (uint16, bool) {
	extensions := matchingExtensions(artifact, oidKeyUsage)
	if len(extensions) != 1 {
		return 0, false
	}
	usage, ok := parseKeyUsage(extensions[0].Value)
	if !ok || usage&keyUsageCABits != 0 {
		return 0, false
	}
	switch {
	case artifact.SubjectPublicKey.Algorithm.Algorithm.Equal(oidRSAEncryption):
		allowed := keyUsageDigitalSignature | keyUsageKeyEncipherment | keyUsageDataEncipherment
		return usage, usage&allowed != 0 && usage&^allowed == 0
	case artifact.SubjectPublicKey.Algorithm.Algorithm.Equal(oidECPublicKey):
		allowed := keyUsageDigitalSignature | keyUsageKeyAgreement
		return usage, usage&keyUsageDigitalSignature != 0 && usage&^allowed == 0
	default:
		return usage, true
	}
}

func validSubjectKeyIdentifier(input []byte) bool {
	value, err := parseExactDER(input)
	return err == nil && expectDER(value, classUniversal, asn1.TagOctetString, false, "subjectKeyIdentifier") == nil && len(value.contents) != 0
}

func validAuthorityKeyIdentifier(input []byte) bool {
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "authorityKeyIdentifier") != nil || len(sequence.contents) == 0 {
		return false
	}
	remaining := sequence.contents
	lastTag := -1
	hasKeyIdentifier, hasIssuer, hasSerial := false, false, false
	for len(remaining) != 0 {
		value, rest, err := parseDER(remaining)
		if err != nil || value.class != classContext || value.tag <= lastTag {
			return false
		}
		switch value.tag {
		case 0:
			if value.constructed || len(value.contents) == 0 {
				return false
			}
			hasKeyIdentifier = true
		case 1:
			if !value.constructed || !validImplicitGeneralNames(value.contents) {
				return false
			}
			hasIssuer = true
		case 2:
			if value.constructed || !validPositiveImplicitInteger(value.contents) {
				return false
			}
			hasSerial = true
		default:
			return false
		}
		lastTag = value.tag
		remaining = rest
	}
	return hasKeyIdentifier && hasIssuer == hasSerial
}

func validCABFAuthorityKeyIdentifier(input []byte) bool {
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "authorityKeyIdentifier") != nil {
		return false
	}
	keyIdentifier, rest, err := parseDER(sequence.contents)
	return err == nil && len(rest) == 0 && keyIdentifier.class == classContext && keyIdentifier.tag == 0 && !keyIdentifier.constructed && len(keyIdentifier.contents) != 0
}

func validCABFAuthorityInformationAccess(input []byte) bool {
	_, valid := parseCABFAuthorityInformationAccess(input)
	return valid
}

type cabfAuthorityInformationAccess struct {
	hasCAIssuers bool
	hasOCSP      bool
}

func parseCABFAuthorityInformationAccess(input []byte) (cabfAuthorityInformationAccess, bool) {
	var info cabfAuthorityInformationAccess
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "authorityInformationAccess") != nil || len(sequence.contents) == 0 {
		return info, false
	}
	seen := make(map[string]struct{})
	remaining := sequence.contents
	for len(remaining) != 0 {
		description, rest, err := parseDER(remaining)
		if err != nil || expectDER(description, classUniversal, asn1.TagSequence, true, "accessDescription") != nil {
			return info, false
		}
		methodDER, fields, err := parseDER(description.contents)
		if err != nil {
			return info, false
		}
		method, err := parseOID(methodDER, "accessMethod")
		if err != nil || (!method.Equal(oidAccessMethodOCSP) && !method.Equal(oidAccessMethodCAIssuers)) {
			return info, false
		}
		location, trailing, err := parseDER(fields)
		if err != nil || len(trailing) != 0 || location.class != classContext || location.tag != 6 || location.constructed {
			return info, false
		}
		canonicalLocation, valid := canonicalHTTPURL(location.contents)
		if !valid {
			return info, false
		}
		key := method.String() + "\x00" + canonicalLocation
		if _, duplicate := seen[key]; duplicate {
			return info, false
		}
		seen[key] = struct{}{}
		if method.Equal(oidAccessMethodCAIssuers) {
			info.hasCAIssuers = true
		} else {
			info.hasOCSP = true
		}
		remaining = rest
	}
	return info, true
}

func validCABFCRLDistributionPoints(input []byte) bool {
	_, valid := parseCABFCRLDistributionPoints(input)
	return valid
}

func parseCABFCRLDistributionPoints(input []byte) (int, bool) {
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "cRLDistributionPoints") != nil || len(sequence.contents) == 0 {
		return 0, false
	}
	count := 0
	remaining := sequence.contents
	for len(remaining) != 0 {
		distributionPoint, rest, err := parseDER(remaining)
		if err != nil || expectDER(distributionPoint, classUniversal, asn1.TagSequence, true, "DistributionPoint") != nil || len(distributionPoint.contents) == 0 {
			return 0, false
		}
		distributionPointName, trailing, err := parseDER(distributionPoint.contents)
		if err != nil || len(trailing) != 0 || distributionPointName.class != classContext || distributionPointName.tag != 0 || !distributionPointName.constructed {
			return 0, false
		}
		fullName, nameTrailing, err := parseDER(distributionPointName.contents)
		if err != nil || len(nameTrailing) != 0 || fullName.class != classContext || fullName.tag != 0 || !fullName.constructed || len(fullName.contents) == 0 {
			return 0, false
		}
		names := fullName.contents
		for len(names) != 0 {
			name, nameRest, err := parseDER(names)
			if err != nil || name.class != classContext || name.tag != 6 || name.constructed || !validHTTPURL(name.contents) {
				return 0, false
			}
			names = nameRest
		}
		count++
		remaining = rest
	}
	return count, true
}

func validHTTPURL(input []byte) bool {
	_, valid := canonicalHTTPURL(input)
	return valid
}

func canonicalHTTPURL(input []byte) (string, bool) {
	if len(input) == 0 {
		return "", false
	}
	for _, b := range input {
		if b > 0x7f {
			return "", false
		}
	}
	parsed, err := url.Parse(string(input))
	if err != nil || !strings.EqualFold(parsed.Scheme, "http") || parsed.Hostname() == "" {
		return "", false
	}
	parsed.Scheme = "http"
	hostname := strings.ToLower(parsed.Hostname())
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}
	return parsed.String(), true
}

func validImplicitGeneralNames(input []byte) bool {
	if len(input) == 0 {
		return false
	}
	for len(input) != 0 {
		value, rest, err := parseDER(input)
		if err != nil || !validGeneralNameStructure(value) {
			return false
		}
		input = rest
	}
	return true
}

func validPositiveImplicitInteger(input []byte) bool {
	if len(input) == 0 || input[0]&0x80 != 0 {
		return false
	}
	return len(input) == 1 || input[0] != 0 || input[1]&0x80 != 0
}

func validTraditionalSubscriberPublicKey(key any) bool {
	switch publicKey := key.(type) {
	case *rsa.PublicKey:
		return publicKey.N != nil && publicKey.N.BitLen() >= 2048 && publicKey.N.BitLen()%8 == 0 && publicKey.E >= 3 && publicKey.E%2 == 1
	case *ecdsa.PublicKey:
		if publicKey.Curve == nil || publicKey.X == nil || publicKey.Y == nil || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
			return false
		}
		switch publicKey.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func containsReservedLDHLabel(name string) bool {
	name = strings.TrimPrefix(name, "*.")
	for _, label := range strings.Split(name, ".") {
		lower := strings.ToLower(label)
		if len(lower) >= 4 && lower[2:4] == "--" && !strings.HasPrefix(lower, "xn--") {
			return true
		}
	}
	return false
}

func parseSubjectAttributes(input []byte) ([]subjectAttribute, bool) {
	name, err := parseExactDER(input)
	if err != nil || expectDER(name, classUniversal, asn1.TagSequence, true, "Name") != nil {
		return nil, false
	}
	remainingRDNs := name.contents
	var attributes []subjectAttribute
	previousRank := -1
	for len(remainingRDNs) != 0 {
		rdn, rest, err := parseDER(remainingRDNs)
		if err != nil || expectDER(rdn, classUniversal, asn1.TagSet, true, "RelativeDistinguishedName") != nil || len(rdn.contents) == 0 {
			return nil, false
		}
		attribute, attributeRest, err := parseDER(rdn.contents)
		if err != nil || len(attributeRest) != 0 || expectDER(attribute, classUniversal, asn1.TagSequence, true, "AttributeTypeAndValue") != nil {
			return nil, false
		}
		contents := attribute.contents
		typeDER, err := takeDER(&contents, "attribute type")
		if err != nil {
			return nil, false
		}
		id, err := parseOID(typeDER, "attribute type")
		if err != nil {
			return nil, false
		}
		value, err := takeDER(&contents, "attribute value")
		if err != nil || len(contents) != 0 {
			return nil, false
		}
		decoded := ""
		textual := false
		if isSubscriberIdentityAttribute(id) {
			decoded, err = decodeCABFSubjectAttribute(id, value)
			if err != nil || decoded == "" {
				return nil, false
			}
			textual = true
		} else if decoded, err = decodeSubjectAttributeText(value); err == nil {
			textual = true
		}
		if rank, tracked := cabfSubjectAttributeRank(id); tracked {
			if rank < previousRank {
				return nil, false
			}
			previousRank = rank
		}
		attributes = append(attributes, subjectAttribute{id: id, value: decoded, textual: textual})
		remainingRDNs = rest
	}
	return attributes, true
}

func isSubscriberIdentityAttribute(id asn1.ObjectIdentifier) bool {
	return id.Equal(oidCommonName) ||
		id.Equal(oidOrganizationName) ||
		id.Equal(oidCountryName) ||
		id.Equal(oidLocalityName) ||
		id.Equal(oidStateOrProvinceName) ||
		id.Equal(oidStreetAddress) ||
		id.Equal(oidBusinessCategory) ||
		id.Equal(oidPostalCode) ||
		id.Equal(oidOrganizationIdentifier) ||
		id.Equal(oidSerialNumber) ||
		id.Equal(oidSurname) ||
		id.Equal(oidGivenName) ||
		id.Equal(oidOrganizationalUnitName) ||
		id.Equal(oidDomainComponent) ||
		id.Equal(oidJurisdictionLocality) ||
		id.Equal(oidJurisdictionState) ||
		id.Equal(oidJurisdictionCountry)
}

func cabfSubjectAttributeRank(id asn1.ObjectIdentifier) (int, bool) {
	ordered := []asn1.ObjectIdentifier{
		oidDomainComponent,
		oidCountryName,
		oidStateOrProvinceName,
		oidLocalityName,
		oidPostalCode,
		oidStreetAddress,
		oidOrganizationName,
		oidSurname,
		oidGivenName,
		oidOrganizationalUnitName,
		oidCommonName,
	}
	for rank, candidate := range ordered {
		if id.Equal(candidate) {
			return rank, true
		}
	}
	return 0, false
}

func decodeCABFSubjectAttribute(id asn1.ObjectIdentifier, value derValue) (string, error) {
	switch {
	case id.Equal(oidDomainComponent):
		decoded, err := decodeSubjectString(value, asn1.TagIA5String, asn1.TagIA5String, 63)
		if err != nil || !validCABFDNSLabel(decoded) {
			return "", asn1.StructuralError{Msg: "invalid domainComponent"}
		}
		return decoded, nil
	case id.Equal(oidCountryName):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagPrintableString, 2)
	case id.Equal(oidLocalityName), id.Equal(oidStateOrProvinceName), id.Equal(oidStreetAddress):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagUTF8String, 128)
	case id.Equal(oidBusinessCategory), id.Equal(oidJurisdictionLocality), id.Equal(oidJurisdictionState):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagUTF8String, 128)
	case id.Equal(oidJurisdictionCountry):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagPrintableString, 2)
	case id.Equal(oidPostalCode):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagUTF8String, 40)
	case id.Equal(oidCommonName), id.Equal(oidOrganizationName), id.Equal(oidOrganizationalUnitName), id.Equal(oidSurname), id.Equal(oidGivenName):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagUTF8String, 64)
	case id.Equal(oidSerialNumber):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagPrintableString, 64)
	case id.Equal(oidOrganizationIdentifier):
		return decodeSubjectString(value, asn1.TagPrintableString, asn1.TagUTF8String, 0)
	default:
		return "", asn1.StructuralError{Msg: "unsupported subject attribute"}
	}
}

func decodeSubjectString(value derValue, firstTag, secondTag, maxCharacters int) (string, error) {
	if value.class != classUniversal || value.constructed || (value.tag != firstTag && value.tag != secondTag) {
		return "", asn1.StructuralError{Msg: "invalid subject string encoding"}
	}
	decoded := string(value.contents)
	characters := len(value.contents)
	switch value.tag {
	case asn1.TagUTF8String:
		if !utf8.Valid(value.contents) {
			return "", asn1.StructuralError{Msg: "invalid UTF8String"}
		}
		characters = utf8.RuneCount(value.contents)
	case asn1.TagPrintableString:
		if !validPrintableString(value.contents) {
			return "", asn1.StructuralError{Msg: "invalid PrintableString"}
		}
	case asn1.TagIA5String:
		if !allBytes(value.contents, func(b byte) bool { return b <= 0x7f }) {
			return "", asn1.StructuralError{Msg: "invalid IA5String"}
		}
	}
	if characters < 1 || maxCharacters > 0 && characters > maxCharacters {
		return "", asn1.StructuralError{Msg: "invalid subject string length"}
	}
	return decoded, nil
}

func validPrintableString(input []byte) bool {
	for _, character := range input {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune(" '()+,-./:=?", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func decodeDirectoryString(value derValue) (string, error) {
	if !validDirectoryString(value) {
		return "", asn1.StructuralError{Msg: "invalid DirectoryString"}
	}
	switch value.tag {
	case asn1.TagT61String, asn1.TagPrintableString, asn1.TagUTF8String:
		return string(value.contents), nil
	case asn1.TagBMPString:
		units := make([]uint16, len(value.contents)/2)
		for i := range units {
			units[i] = uint16(value.contents[2*i])<<8 | uint16(value.contents[2*i+1])
		}
		decoded := utf16.Decode(units)
		for _, character := range decoded {
			if character == utf8.RuneError {
				return "", asn1.StructuralError{Msg: "invalid BMPString"}
			}
		}
		return string(decoded), nil
	case tagUniversalString:
		decoded := make([]rune, len(value.contents)/4)
		for i := range decoded {
			character := rune(value.contents[4*i])<<24 | rune(value.contents[4*i+1])<<16 | rune(value.contents[4*i+2])<<8 | rune(value.contents[4*i+3])
			if !utf8.ValidRune(character) {
				return "", asn1.StructuralError{Msg: "invalid UniversalString"}
			}
			decoded[i] = character
		}
		return string(decoded), nil
	default:
		return "", asn1.StructuralError{Msg: "unsupported DirectoryString"}
	}
}

func decodeSubjectAttributeText(value derValue) (string, error) {
	if value.class != classUniversal || value.constructed {
		return "", asn1.StructuralError{Msg: "invalid subject attribute string"}
	}
	switch value.tag {
	case asn1.TagT61String:
		return string(value.contents), nil
	case asn1.TagPrintableString:
		if !validPrintableString(value.contents) {
			return "", asn1.StructuralError{Msg: "invalid PrintableString"}
		}
		return string(value.contents), nil
	case asn1.TagUTF8String:
		if !utf8.Valid(value.contents) {
			return "", asn1.StructuralError{Msg: "invalid UTF8String"}
		}
		return string(value.contents), nil
	case asn1.TagIA5String:
		for _, character := range value.contents {
			if character > 127 {
				return "", asn1.StructuralError{Msg: "invalid IA5String"}
			}
		}
		return string(value.contents), nil
	case asn1.TagBMPString:
		if len(value.contents)%2 != 0 {
			return "", asn1.StructuralError{Msg: "invalid BMPString"}
		}
		units := make([]uint16, len(value.contents)/2)
		for i := range units {
			units[i] = uint16(value.contents[2*i])<<8 | uint16(value.contents[2*i+1])
		}
		decoded := utf16.Decode(units)
		for _, character := range decoded {
			if character == utf8.RuneError {
				return "", asn1.StructuralError{Msg: "invalid BMPString"}
			}
		}
		return string(decoded), nil
	case tagUniversalString:
		if len(value.contents)%4 != 0 {
			return "", asn1.StructuralError{Msg: "invalid UniversalString"}
		}
		decoded := make([]rune, len(value.contents)/4)
		for i := range decoded {
			character := rune(value.contents[4*i])<<24 | rune(value.contents[4*i+1])<<16 | rune(value.contents[4*i+2])<<8 | rune(value.contents[4*i+3])
			if !utf8.ValidRune(character) {
				return "", asn1.StructuralError{Msg: "invalid UniversalString"}
			}
			decoded[i] = character
		}
		return string(decoded), nil
	default:
		return "", asn1.StructuralError{Msg: "unsupported subject attribute string"}
	}
}

func commonNameInSAN(commonName string, names []generalName) bool {
	for _, name := range names {
		switch name.tag {
		case 2:
			if commonName == string(name.contents) {
				return true
			}
		case 7:
			if ip := net.IP(name.contents); (len(ip) == net.IPv4len || len(ip) == net.IPv6len) && commonName == ip.String() {
				return true
			}
		}
	}
	return false
}

func validOVSubjectAttributes(attributes []subjectAttribute) bool {
	if !validCABFIdentityAttributes(attributes) ||
		countNameOID(attributes, oidOrganizationName) != 1 ||
		countNameOID(attributes, oidCountryName) != 1 ||
		!nameHasEitherOID(attributes, oidLocalityName, oidStateOrProvinceName) {
		return false
	}
	return !nameHasOID(attributes, oidSurname) &&
		!nameHasOID(attributes, oidGivenName) &&
		!nameHasOID(attributes, oidOrganizationalUnitName)
}

func validIVSubjectAttributes(attributes []subjectAttribute) bool {
	if !validCABFIdentityAttributes(attributes) ||
		countNameOID(attributes, oidGivenName) != 1 ||
		countNameOID(attributes, oidSurname) != 1 ||
		countNameOID(attributes, oidCountryName) != 1 ||
		!nameHasEitherOID(attributes, oidLocalityName, oidStateOrProvinceName) {
		return false
	}
	return !nameHasOID(attributes, oidOrganizationalUnitName)
}

func validDomainComponentSequence(attributes []subjectAttribute, when time.Time) bool {
	var labels []string
	for _, attribute := range attributes {
		if attribute.id.Equal(oidDomainComponent) {
			labels = append(labels, attribute.value)
		}
	}
	if len(labels) == 0 {
		return true
	}
	for left, right := 0, len(labels)-1; left < right; left, right = left+1, right-1 {
		labels[left], labels[right] = labels[right], labels[left]
	}
	return validCABFDNSName([]byte(strings.Join(labels, ".")), when)
}

func recommendedIVSubjectAttribute(id asn1.ObjectIdentifier) bool {
	return id.Equal(oidCountryName) ||
		id.Equal(oidLocalityName) ||
		id.Equal(oidStateOrProvinceName) ||
		id.Equal(oidSurname) ||
		id.Equal(oidGivenName)
}

func recommendedOVSubjectAttribute(id asn1.ObjectIdentifier) bool {
	return id.Equal(oidDomainComponent) ||
		id.Equal(oidCountryName) ||
		id.Equal(oidLocalityName) ||
		id.Equal(oidStateOrProvinceName) ||
		id.Equal(oidOrganizationName)
}

func validCABFIdentityAttributes(attributes []subjectAttribute) bool {
	tracked := []asn1.ObjectIdentifier{
		oidCommonName,
		oidOrganizationName,
		oidOrganizationalUnitName,
		oidCountryName,
		oidLocalityName,
		oidStateOrProvinceName,
		oidStreetAddress,
		oidBusinessCategory,
		oidPostalCode,
		oidOrganizationIdentifier,
		oidSerialNumber,
		oidSurname,
		oidGivenName,
		oidDomainComponent,
		oidJurisdictionLocality,
		oidJurisdictionState,
		oidJurisdictionCountry,
	}
	for _, oid := range tracked {
		if !oid.Equal(oidDomainComponent) && !oid.Equal(oidStreetAddress) && countNameOID(attributes, oid) > 1 {
			return false
		}
	}
	for _, attribute := range attributes {
		if attribute.textual && !containsInformationalCharacter(attribute.value) {
			return false
		}
		if attribute.id.Equal(oidCountryName) {
			country := strings.ToUpper(attribute.value)
			if country != "XX" && !zlintutil.IsISOCountryCode(country) {
				return false
			}
		}
	}
	return true
}

func containsInformationalCharacter(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character > 127 {
			return true
		}
	}
	return false
}

func countNameOID(attributes []subjectAttribute, oid asn1.ObjectIdentifier) int {
	count := 0
	for _, attribute := range attributes {
		if attribute.id.Equal(oid) {
			count++
		}
	}
	return count
}

func nameHasOID(attributes []subjectAttribute, oid asn1.ObjectIdentifier) bool {
	return countNameOID(attributes, oid) != 0
}

func nameHasEitherOID(attributes []subjectAttribute, left, right asn1.ObjectIdentifier) bool {
	return nameHasOID(attributes, left) || nameHasOID(attributes, right)
}
