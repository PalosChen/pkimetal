package mtc

import (
	"bytes"
	"encoding/asn1"
	"time"
)

const cqrp020Source = "CQRP v0.2.0"

var (
	oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidServerAuth          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidSCTList             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidCommonName          = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrganizationName    = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidPolicyDV            = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	oidPolicyOV            = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}
	oidPolicyIV            = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 3}

	mlDSA44AlgorithmDER = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}
	mlDSA65AlgorithmDER = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	mlDSA87AlgorithmDER = []byte{0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13}
)

var cqrp020Rules = []Rule{
	cqrp020Rule("e_cqrp_ca_spki_algorithm", "4.5.1", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		algorithm := a.SubjectPublicKey.Algorithm.Algorithm
		if !algorithm.Equal(OIDMLDSA44) && !isHashMLDSA(algorithm) {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo.algorithm", "CA subject public key algorithm is not ML-DSA-44")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_ca_spki_parameters_present", "4.5.1", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		algorithm := a.SubjectPublicKey.Algorithm
		if algorithm.Algorithm.Equal(OIDMLDSA44) && algorithm.ParametersPresent {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", "ML-DSA-44 parameters are present")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_ca_spki_encoding", "4.5.1", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		algorithm := a.SubjectPublicKey.Algorithm
		if algorithm.Algorithm.Equal(OIDMLDSA44) && !bytes.Equal(algorithm.Raw, mlDSA44AlgorithmDER) {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo.algorithm", "ML-DSA-44 AlgorithmIdentifier does not have the required encoding")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_ca_hash_mldsa", "4.5.1", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		if isHashMLDSA(a.SubjectPublicKey.Algorithm.Algorithm) {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo.algorithm", "CA subject public key uses prohibited HashML-DSA")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_ca_key_usage_not_critical", "4.5.1", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidKeyUsage)
		if len(extensions) == 1 && !extensions[0].Critical {
			return errorFinding("tbsCertificate.extensions.keyUsage", "CA key usage extension is not critical")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_validity_too_long", "2.1", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if a.NotAfter.Sub(a.NotBefore) > 47*24*time.Hour {
			return errorFinding("tbsCertificate.validity", "subscriber certificate validity exceeds 47 days")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_mldsa_parameters_present", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		algorithm := a.SubjectPublicKey.Algorithm
		if isPureMLDSA(algorithm.Algorithm) && algorithm.ParametersPresent {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo.algorithm.parameters", "ML-DSA parameters are present")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_mldsa_encoding", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		algorithm := a.SubjectPublicKey.Algorithm
		if expected := expectedMLDSAAlgorithmDER(algorithm.Algorithm); expected != nil && !bytes.Equal(algorithm.Raw, expected) {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo.algorithm", "ML-DSA AlgorithmIdentifier does not have the required encoding")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_hash_mldsa", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if isHashMLDSA(a.SubjectPublicKey.Algorithm.Algorithm) {
			return errorFinding("tbsCertificate.subjectPublicKeyInfo.algorithm", "subscriber subject public key uses prohibited HashML-DSA")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_dv_subject_not_empty", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if ok && containsOID(policies, oidPolicyDV) && !bytes.Equal(a.SubjectRaw, []byte{0x30, 0x00}) {
			return errorFinding("tbsCertificate.subject", "DV subscriber subject is not empty")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_policies_missing", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if countExtensions(a, oidCertificatePolicies) == 0 {
			return errorFinding("tbsCertificate.extensions.certificatePolicies", "certificate policies extension is missing")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_policies_critical", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidCertificatePolicies)
		if len(extensions) == 1 && extensions[0].Critical {
			return errorFinding("tbsCertificate.extensions.certificatePolicies", "certificate policies extension is critical")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_policy_identifier", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if !ok && countExtensions(a, oidCertificatePolicies) == 1 {
			return errorFinding("tbsCertificate.extensions.certificatePolicies", "certificate policies does not contain only valid reserved policy identifiers")
		}
		for _, policy := range policies {
			if !isAllowedSubscriberPolicy(policy) {
				return errorFinding("tbsCertificate.extensions.certificatePolicies", "certificate policies contains an unrecognized policy identifier")
			}
		}
		return nil
	}),
	cqrp020Rule("w_cqrp_subscriber_policy_not_dv", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		policies, ok := subscriberPolicies(a)
		if !ok {
			return nil
		}
		for _, policy := range policies {
			if !isAllowedSubscriberPolicy(policy) {
				return nil
			}
			if !policy.Equal(oidPolicyDV) {
				return warningFinding("tbsCertificate.extensions.certificatePolicies", "subscriber certificate asserts a reserved policy other than DV")
			}
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_eku_missing", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if countExtensions(a, oidExtendedKeyUsage) == 0 {
			return errorFinding("tbsCertificate.extensions.extKeyUsage", "extended key usage extension is missing")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_eku_critical", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidExtendedKeyUsage)
		if len(extensions) == 1 && extensions[0].Critical {
			return errorFinding("tbsCertificate.extensions.extKeyUsage", "extended key usage extension is critical")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_eku_only_server_auth", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidExtendedKeyUsage)
		if len(extensions) == 1 && !isOnlyServerAuthEKU(extensions[0].Value) {
			return errorFinding("tbsCertificate.extensions.extKeyUsage", "extended key usage is not exactly id-kp-serverAuth")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_ian_critical", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidIssuerAlternativeName)
		if len(extensions) == 1 && extensions[0].Critical {
			return errorFinding("tbsCertificate.extensions.issuerAlternativeName", "issuer alternative name extension is critical")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_ian_form", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidIssuerAlternativeName)
		if len(extensions) == 1 {
			if _, ok := parseIssuerAlternativeNames(extensions[0].Value); !ok {
				return errorFinding("tbsCertificate.extensions.issuerAlternativeName", "issuer alternative name is not valid directoryName-only GeneralNames")
			}
		}
		return nil
	}),
	cqrp020Rule("w_cqrp_subscriber_ian_name_attributes", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidIssuerAlternativeName)
		if len(extensions) == 1 {
			otherAttributes, ok := parseIssuerAlternativeNames(extensions[0].Value)
			if ok && otherAttributes {
				return warningFinding("tbsCertificate.extensions.issuerAlternativeName", "issuer alternative name uses attributes other than organizationName or commonName")
			}
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_sct_present", "4.5.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if countExtensions(a, oidSCTList) != 0 {
			return errorFinding("tbsCertificate.extensions.signedCertificateTimestampList", "signed certificate timestamp list extension is present")
		}
		return nil
	}),
	cqrp020Rule("e_cqrp_subscriber_standalone_cosignatures", "4.7", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if proofAvailable(a) && len(a.Proof.Signatures) != 0 && len(a.Proof.Signatures) < 2 {
			return errorFinding("signatureValue.signatures", "standalone certificate has fewer than two cosignatures")
		}
		return nil
	}),
}

// LintCQRP020 evaluates only the CQRP v0.2.0 rules.
func LintCQRP020(artifact *Artifact) []Finding {
	return runRules(artifact, cqrp020Rules)
}

// LintCQRP020ForKind evaluates CQRP rules in an explicit profile context
// without changing the parsed artifact or reusing proof state from another kind.
func LintCQRP020ForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	if artifact == nil || expected != ArtifactCA && expected != ArtifactSubscriber {
		return nil
	}
	local := *artifact
	local.Kind = expected
	local.Proof = nil
	local.ProofParseError = nil
	if expected == ArtifactSubscriber && local.InputKind == InputCertificate {
		local.Proof, local.ProofParseError = ParseProof(local.SignatureValue)
	}
	return runRules(&local, cqrp020Rules)
}

func cqrp020Rule(code, section string, kinds []ArtifactKind, inputKinds []InputKind, evaluate func(*Artifact) *Finding) Rule {
	return Rule{Code: code, Source: cqrp020Source, Section: section, Kinds: kinds, InputKinds: inputKinds, Evaluate: evaluate}
}

func isPureMLDSA(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDMLDSA44) || oid.Equal(OIDMLDSA65) || oid.Equal(OIDMLDSA87)
}

func isHashMLDSA(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(OIDHashMLDSA44) || oid.Equal(OIDHashMLDSA65) || oid.Equal(OIDHashMLDSA87)
}

func expectedMLDSAAlgorithmDER(oid asn1.ObjectIdentifier) []byte {
	switch {
	case oid.Equal(OIDMLDSA44):
		return mlDSA44AlgorithmDER
	case oid.Equal(OIDMLDSA65):
		return mlDSA65AlgorithmDER
	case oid.Equal(OIDMLDSA87):
		return mlDSA87AlgorithmDER
	default:
		return nil
	}
}

func subscriberPolicies(artifact *Artifact) ([]asn1.ObjectIdentifier, bool) {
	extensions := matchingExtensions(artifact, oidCertificatePolicies)
	if len(extensions) != 1 {
		return nil, false
	}
	return parseCertificatePolicies(extensions[0].Value)
}

func parseCertificatePolicies(input []byte) ([]asn1.ObjectIdentifier, bool) {
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "certificatePolicies") != nil || len(sequence.contents) == 0 {
		return nil, false
	}
	var policies []asn1.ObjectIdentifier
	remaining := sequence.contents
	for len(remaining) != 0 {
		information, rest, err := parseDER(remaining)
		if err != nil || expectDER(information, classUniversal, asn1.TagSequence, true, "PolicyInformation") != nil {
			return nil, false
		}
		contents := information.contents
		identifierDER, err := takeDER(&contents, "policyIdentifier")
		if err != nil {
			return nil, false
		}
		identifier, err := parseOID(identifierDER, "policyIdentifier")
		if err != nil {
			return nil, false
		}
		if len(contents) != 0 {
			qualifiers, err := takeDER(&contents, "policyQualifiers")
			if err != nil || !validPolicyQualifiers(qualifiers) || len(contents) != 0 {
				return nil, false
			}
		}
		policies = append(policies, identifier)
		remaining = rest
	}
	return policies, true
}

func validPolicyQualifiers(sequence derValue) bool {
	if expectDER(sequence, classUniversal, asn1.TagSequence, true, "policyQualifiers") != nil || len(sequence.contents) == 0 {
		return false
	}
	remaining := sequence.contents
	for len(remaining) != 0 {
		qualifier, rest, err := parseDER(remaining)
		if err != nil || expectDER(qualifier, classUniversal, asn1.TagSequence, true, "PolicyQualifierInfo") != nil {
			return false
		}
		contents := qualifier.contents
		qualifierID, err := takeDER(&contents, "policyQualifierId")
		if err != nil {
			return false
		}
		if _, err := parseOID(qualifierID, "policyQualifierId"); err != nil {
			return false
		}
		if _, err := takeDER(&contents, "qualifier"); err != nil || len(contents) != 0 {
			return false
		}
		remaining = rest
	}
	return true
}

func containsOID(oids []asn1.ObjectIdentifier, want asn1.ObjectIdentifier) bool {
	for _, oid := range oids {
		if oid.Equal(want) {
			return true
		}
	}
	return false
}

func isAllowedSubscriberPolicy(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidPolicyDV) || oid.Equal(oidPolicyOV) || oid.Equal(oidPolicyIV)
}

func isOnlyServerAuthEKU(input []byte) bool {
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "extKeyUsage") != nil {
		return false
	}
	contents := sequence.contents
	oidDER, err := takeDER(&contents, "KeyPurposeId")
	if err != nil {
		return false
	}
	oid, err := parseOID(oidDER, "KeyPurposeId")
	return err == nil && oid.Equal(oidServerAuth) && len(contents) == 0
}

func parseIssuerAlternativeNames(input []byte) (bool, bool) {
	sequence, err := parseExactDER(input)
	if err != nil || expectDER(sequence, classUniversal, asn1.TagSequence, true, "GeneralNames") != nil || len(sequence.contents) == 0 {
		return false, false
	}
	otherAttributes := false
	remaining := sequence.contents
	for len(remaining) != 0 {
		name, rest, err := parseDER(remaining)
		if err != nil || name.class != classContext || name.tag != 4 || !name.constructed {
			return false, false
		}
		hasOther, ok := parseDirectoryName(name.contents)
		if !ok {
			return false, false
		}
		otherAttributes = otherAttributes || hasOther
		remaining = rest
	}
	return otherAttributes, true
}

func parseDirectoryName(input []byte) (bool, bool) {
	name, err := parseExactDER(input)
	if err != nil || expectDER(name, classUniversal, asn1.TagSequence, true, "Name") != nil || len(name.contents) == 0 {
		return false, false
	}
	otherAttributes := false
	rdns := name.contents
	for len(rdns) != 0 {
		rdn, rest, err := parseDER(rdns)
		if err != nil || expectDER(rdn, classUniversal, asn1.TagSet, true, "RelativeDistinguishedName") != nil || len(rdn.contents) == 0 {
			return false, false
		}
		attributes := rdn.contents
		for len(attributes) != 0 {
			attribute, attributeRest, err := parseDER(attributes)
			if err != nil || expectDER(attribute, classUniversal, asn1.TagSequence, true, "AttributeTypeAndValue") != nil {
				return false, false
			}
			contents := attribute.contents
			typeDER, err := takeDER(&contents, "attribute type")
			if err != nil {
				return false, false
			}
			typeOID, err := parseOID(typeDER, "attribute type")
			if err != nil {
				return false, false
			}
			if _, err := takeDER(&contents, "attribute value"); err != nil || len(contents) != 0 {
				return false, false
			}
			if !typeOID.Equal(oidOrganizationName) && !typeOID.Equal(oidCommonName) {
				otherAttributes = true
			}
			attributes = attributeRest
		}
		rdns = rest
	}
	return otherAttributes, true
}
