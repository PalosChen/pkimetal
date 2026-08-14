package mtc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	zlintutil "github.com/zmap/zlint/v3/util"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	rfc5280Source   = "RFC 5280"
	cabfTLSBRSource = "CA/B Forum TLS Baseline Requirements"
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey            = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidCountryName            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidLocalityName           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidStateOrProvinceName    = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidSurname                = asn1.ObjectIdentifier{2, 5, 4, 4}
	oidGivenName              = asn1.ObjectIdentifier{2, 5, 4, 42}
)

type generalName struct {
	tag      int
	contents []byte
}

var rfc5280SubscriberRules = []Rule{
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
		if len(extensions) == 1 && (extensions[0].Critical || !validAuthorityKeyIdentifier(extensions[0].Value)) {
			return errorFinding("tbsCertificate.extensions.authorityKeyIdentifier", "subscriber authority key identifier is critical or malformed")
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
			if ok && usage&0x06 != 0 {
				return errorFinding("tbsCertificate.extensions.keyUsage", "TLS subscriber key usage asserts keyCertSign or cRLSign")
			}
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_san_missing", cabfTLSBRSource, "7.1.4.2.1", func(a *Artifact) *Finding {
		if countExtensions(a, oidSubjectAlternativeName) == 0 {
			return errorFinding("tbsCertificate.extensions.subjectAltName", "TLS subscriber certificate has no subject alternative name extension")
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
			if name.tag == 2 && !validCABFDNSName(name.contents) {
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
		if !ok || !nameHasOID(attributes, oidOrganizationName) || !nameHasOID(attributes, oidCountryName) || !nameHasEitherOID(attributes, oidLocalityName, oidStateOrProvinceName) {
			return errorFinding("tbsCertificate.subject", "OV TLS subscriber subject lacks organizationName, countryName, or locality/state identity")
		}
		return nil
	}),
	subscriberProfileRule("e_cabf_mtc_subscriber_iv_subject", cabfTLSBRSource, "7.1.2.7.3", func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if !ok || !containsOID(policies, oidPolicyIV) {
			return nil
		}
		attributes, ok := parseSubjectAttributes(a.SubjectRaw)
		if !ok || !nameHasOID(attributes, oidGivenName) || !nameHasOID(attributes, oidSurname) || !nameHasOID(attributes, oidCountryName) || !nameHasEitherOID(attributes, oidLocalityName, oidStateOrProvinceName) {
			return errorFinding("tbsCertificate.subject", "IV TLS subscriber subject lacks givenName, surname, countryName, or locality/state identity")
		}
		return nil
	}),
	subscriberProfileRule("w_cabf_mtc_subscriber_san_critical_with_subject", cabfTLSBRSource, "7.1.2.7.6", func(a *Artifact) *Finding {
		if subjectIsEmpty(a) {
			return nil
		}
		for _, extension := range matchingExtensions(a, oidSubjectAlternativeName) {
			if extension.Critical {
				return warningFinding("tbsCertificate.extensions.subjectAltName", "TLS subscriber subject alternative name is critical although the subject is not empty")
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

func validCABFDNSName(input []byte) bool {
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
	suffix, icann := publicsuffix.PublicSuffix(registrableName)
	if !icann || strings.EqualFold(suffix, "arpa") {
		return false
	}
	_, err := publicsuffix.EffectiveTLDPlusOne(registrableName)
	return err == nil
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
	id    asn1.ObjectIdentifier
	value string
}

func knownSubscriberExtension(oid asn1.ObjectIdentifier) bool {
	known := []asn1.ObjectIdentifier{
		oidSubjectKeyIdentifier,
		oidKeyUsage,
		oidSubjectAlternativeName,
		oidIssuerAlternativeName,
		oidBasicConstraints,
		oidAuthorityKeyIdentifier,
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

func parseKeyUsage(input []byte) (byte, bool) {
	value, err := parseExactDER(input)
	if err != nil {
		return 0, false
	}
	bits, _, err := parseBitString(value, "keyUsage")
	if err != nil || len(bits) == 0 || len(bits) > 2 {
		return 0, false
	}
	return bits[0], true
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
	hasIssuer, hasSerial := false, false
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
	return hasIssuer == hasSerial
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
		return publicKey.N != nil && publicKey.N.BitLen() >= 2048 && publicKey.E >= 65537 && publicKey.E%2 == 1
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
	for len(remainingRDNs) != 0 {
		rdn, rest, err := parseDER(remainingRDNs)
		if err != nil || expectDER(rdn, classUniversal, asn1.TagSet, true, "RelativeDistinguishedName") != nil || len(rdn.contents) == 0 {
			return nil, false
		}
		remainingAttributes := rdn.contents
		for len(remainingAttributes) != 0 {
			attribute, attributeRest, err := parseDER(remainingAttributes)
			if err != nil || expectDER(attribute, classUniversal, asn1.TagSequence, true, "AttributeTypeAndValue") != nil {
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
			if isSubscriberIdentityAttribute(id) {
				decoded, err = decodeDirectoryString(value)
				if err != nil || decoded == "" {
					return nil, false
				}
			}
			attributes = append(attributes, subjectAttribute{id: id, value: decoded})
			remainingAttributes = attributeRest
		}
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
		id.Equal(oidSurname) ||
		id.Equal(oidGivenName)
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

func nameHasOID(attributes []subjectAttribute, oid asn1.ObjectIdentifier) bool {
	for _, attribute := range attributes {
		if attribute.id.Equal(oid) {
			return true
		}
	}
	return false
}

func nameHasEitherOID(attributes []subjectAttribute, left, right asn1.ObjectIdentifier) bool {
	return nameHasOID(attributes, left) || nameHasOID(attributes, right)
}
