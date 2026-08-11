package mtc

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"math/bits"
	"sort"
)

const (
	draft05Source = "draft-ietf-plants-merkle-tree-certs-05"
	rfc9925Source = "RFC 9925"
	maxUint48     = uint64(1<<48) - 1
)

var (
	oidUnsigned               = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}
	oidKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidIssuerAlternativeName  = asn1.ObjectIdentifier{2, 5, 29, 18}
	maxMTCSerial              = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
)

var draft05Rules = []Rule{
	draftRule("e_mtc_artifact_type_conflict", "5.5 and 6.2", bothArtifactKinds, bothInputKinds, func(a *Artifact) *Finding {
		if a.TypeConflict {
			return errorFinding("tbsCertificate.signature,tbsCertificate.extensions.mtcCertificationAuthority", "Artifact matches both MTC CA and subscriber syntax")
		}
		return nil
	}),
	draftRule("e_mtc_signature_algorithm_oid", "6.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if !a.TBSSignature.Algorithm.Equal(OIDMTCProof) {
			return errorFinding("tbsCertificate.signature", "TBSCertificate signature algorithm is not id-alg-mtcProof")
		}
		if a.InputKind == InputCertificate && (a.OuterSignature == nil || !a.OuterSignature.Algorithm.Equal(OIDMTCProof)) {
			return errorFinding("signatureAlgorithm", "Certificate signature algorithm is not id-alg-mtcProof")
		}
		return nil
	}),
	draftRule("e_mtc_signature_algorithm_parameters_present", "6.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if a.TBSSignature.ParametersPresent {
			return errorFinding("tbsCertificate.signature.parameters", "id-alg-mtcProof parameters are present")
		}
		if a.InputKind == InputCertificate && a.OuterSignature != nil && a.OuterSignature.ParametersPresent {
			return errorFinding("signatureAlgorithm.parameters", "id-alg-mtcProof parameters are present")
		}
		return nil
	}),
	draftRule("e_mtc_cert_signature_algorithm_mismatch", "6.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if a.OuterSignature == nil || !algorithmIdentifiersEqual(a.TBSSignature, *a.OuterSignature) {
			return errorFinding("signatureAlgorithm", "Certificate and TBSCertificate signature algorithms do not match")
		}
		return nil
	}),
	draftRule("e_mtc_signature_value_unused_bits", "6.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if a.SignatureUnused != 0 {
			return errorFinding("signatureValue", "MTCProof signatureValue is not byte-aligned")
		}
		return nil
	}),
	draftRule("e_mtc_ca_subject_not_ca_id", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		if len(a.SubjectCAID) == 0 {
			return errorFinding("tbsCertificate.subject", "CA subject is not a CA-ID distinguished name")
		}
		return nil
	}),
	draftRule("e_mtc_ca_extension_missing", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		if countExtensions(a, OIDMTCCertificationAuthority) == 0 {
			return errorFinding("tbsCertificate.extensions", "MTC certification authority extension is missing")
		}
		return nil
	}),
	draftRule("e_mtc_ca_extension_not_critical", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, OIDMTCCertificationAuthority)
		if len(extensions) == 1 && !extensions[0].Critical {
			return errorFinding("tbsCertificate.extensions", "MTC certification authority extension is not critical")
		}
		return nil
	}),
	draftRule("f_mtc_ca_extension_malformed", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		count := countExtensions(a, OIDMTCCertificationAuthority)
		if count > 1 {
			return fatalFinding("tbsCertificate.extensions", "MTC certification authority extension is duplicated")
		}
		if count == 1 && (a.CAExtensionError != nil || a.CAParameters == nil) {
			return fatalFinding("tbsCertificate.extensions", "MTC certification authority extension is malformed")
		}
		return nil
	}),
	draftRule("e_mtc_ca_serial_range_invalid", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		params := a.CAParameters
		if params == nil {
			return nil
		}
		if !validMTCSerialBound(params.MinSerial) || !validMTCSerialBound(params.MaxSerial) || params.MinSerial.Cmp(params.MaxSerial) > 0 {
			return errorFinding("tbsCertificate.extensions.mtcCertificationAuthority", "MTC CA serial range is invalid")
		}
		return nil
	}),
	draftRule("e_mtc_ca_key_usage_missing", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		if countExtensions(a, oidKeyUsage) == 0 {
			return errorFinding("tbsCertificate.extensions.keyUsage", "key usage extension is missing")
		}
		return nil
	}),
	draftRule("e_mtc_ca_key_cert_sign_missing", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidKeyUsage)
		if len(extensions) != 1 {
			return nil
		}
		if !keyCertSignSet(extensions[0].Value) {
			return errorFinding("tbsCertificate.extensions.keyUsage", "key usage does not assert keyCertSign")
		}
		return nil
	}),
	draftRule("e_mtc_ca_basic_constraints_missing", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		if countExtensions(a, oidBasicConstraints) == 0 {
			return errorFinding("tbsCertificate.extensions.basicConstraints", "basic constraints extension is missing")
		}
		return nil
	}),
	draftRule("e_mtc_ca_basic_constraints_not_ca", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		extensions := matchingExtensions(a, oidBasicConstraints)
		if len(extensions) != 1 {
			return nil
		}
		if !basicConstraintsCA(extensions[0].Value) {
			return errorFinding("tbsCertificate.extensions.basicConstraints", "basic constraints does not set cA to TRUE")
		}
		return nil
	}),
	draftRule("w_mtc_ca_ski_not_ca_id", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		if len(a.SubjectCAID) == 0 {
			return nil
		}
		for _, extension := range matchingExtensions(a, oidSubjectKeyIdentifier) {
			if !subjectKeyIdentifierMatches(extension.Value, a.SubjectCAID) {
				return warningFinding("tbsCertificate.extensions.subjectKeyIdentifier", "subject key identifier does not encode the CA ID")
			}
		}
		return nil
	}),
	draftRule("w_mtc_ca_self_issued", "5.5", caKinds, bothInputKinds, func(a *Artifact) *Finding {
		if !usesUnsignedAlgorithm(a) && len(a.IssuerRaw) != 0 && bytes.Equal(a.IssuerRaw, a.SubjectRaw) {
			return warningFinding("tbsCertificate.issuer", "CA certificate is structurally self-issued; no signature verification was performed")
		}
		return nil
	}),
	draftRule("e_mtc_subscriber_issuer_not_ca_id", "6.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if len(a.IssuerCAID) == 0 {
			return errorFinding("tbsCertificate.issuer", "subscriber issuer is not a CA-ID distinguished name")
		}
		return nil
	}),
	draftRule("e_mtc_serial_non_positive", "6.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if a.SerialNumber == nil || a.SerialNumber.Sign() <= 0 {
			return errorFinding("tbsCertificate.serialNumber", "subscriber serial number is not positive")
		}
		return nil
	}),
	draftRule("e_mtc_serial_too_large", "6.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		if a.SerialNumber != nil && a.SerialNumber.Sign() > 0 && a.SerialNumber.BitLen() > 64 {
			return errorFinding("tbsCertificate.serialNumber", "subscriber serial number exceeds 2^64-1")
		}
		return nil
	}),
	draftRule("e_mtc_serial_log_number_zero", "6.2", subscriberKinds, bothInputKinds, func(a *Artifact) *Finding {
		logNumber, _, ok := SplitSerial(a.SerialNumber)
		if ok && logNumber == 0 {
			return errorFinding("tbsCertificate.serialNumber", "subscriber serial number has log number zero")
		}
		return nil
	}),
	draftRule("f_mtc_proof_malformed", "6.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if a.ProofParseError != nil || a.Proof == nil {
			return fatalFinding("signatureValue", "MTCProof is malformed")
		}
		return nil
	}),
	draftRule("e_mtc_proof_range_invalid", "6.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if proofAvailable(a) && !proofRangeValid(a.Proof) {
			return errorFinding("signatureValue.start,end", "MTCProof range is invalid")
		}
		return nil
	}),
	draftRule("e_mtc_proof_subtree_invalid", "4.1", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if proofAvailable(a) && proofRangeValid(a.Proof) && !ValidSubtree(a.Proof.Start, a.Proof.End) {
			return errorFinding("signatureValue.start,end", "MTCProof range does not describe a valid subtree")
		}
		return nil
	}),
	draftRule("e_mtc_proof_index_outside_range", "4.3.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if !proofAvailable(a) || !proofRangeValid(a.Proof) {
			return nil
		}
		_, index, ok := SplitSerial(a.SerialNumber)
		if ok && (index < a.Proof.Start || index >= a.Proof.End) {
			return errorFinding("signatureValue.start,end", "serial-derived entry index is outside the MTCProof range")
		}
		return nil
	}),
	draftRule("e_mtc_proof_extensions_order", "5.2.1", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if !proofAvailable(a) || proofExtensionsHaveDuplicate(a.Proof.Extensions) {
			return nil
		}
		for i := 1; i < len(a.Proof.Extensions); i++ {
			if a.Proof.Extensions[i-1].Type > a.Proof.Extensions[i].Type {
				return errorFinding("signatureValue.extensions", "MTCProof extensions are not in ascending type order")
			}
		}
		return nil
	}),
	draftRule("e_mtc_proof_extensions_duplicate", "5.2.1", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if proofAvailable(a) && proofExtensionsHaveDuplicate(a.Proof.Extensions) {
			return errorFinding("signatureValue.extensions", "MTCProof extensions contain a duplicate type")
		}
		return nil
	}),
	draftRule("e_mtc_proof_cosigner_id_empty", "6.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if !proofAvailable(a) {
			return nil
		}
		for _, signature := range a.Proof.Signatures {
			if len(signature.CosignerID) == 0 {
				return errorFinding("signatureValue.signatures.cosigner_id", "MTCProof cosigner ID is empty")
			}
		}
		return nil
	}),
	draftRule("e_mtc_proof_cosigner_order", "6.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if !proofAvailable(a) || cosignersHaveDuplicate(a.Proof.Signatures) {
			return nil
		}
		for i := 1; i < len(a.Proof.Signatures); i++ {
			if compareCosignerIDs(a.Proof.Signatures[i-1].CosignerID, a.Proof.Signatures[i].CosignerID) >= 0 {
				return errorFinding("signatureValue.signatures.cosigner_id", "MTCProof cosigner IDs are not in canonical order")
			}
		}
		return nil
	}),
	draftRule("e_mtc_proof_cosigner_duplicate", "6.2", subscriberKinds, certificateInputKinds, func(a *Artifact) *Finding {
		if proofAvailable(a) && cosignersHaveDuplicate(a.Proof.Signatures) {
			return errorFinding("signatureValue.signatures.cosigner_id", "MTCProof contains a duplicate cosigner ID")
		}
		return nil
	}),
	rfc9925Rule("e_rfc9925_unsigned_algorithm_mismatch", "3.1", certificateInputKinds, func(a *Artifact) *Finding {
		if !usesUnsignedAlgorithm(a) {
			return nil
		}
		if a.OuterSignature == nil || !a.TBSSignature.Algorithm.Equal(oidUnsigned) || !a.OuterSignature.Algorithm.Equal(oidUnsigned) {
			return errorFinding("signatureAlgorithm", "unsigned Certificate and TBSCertificate algorithms do not both use id-alg-unsigned")
		}
		return nil
	}),
	rfc9925Rule("e_rfc9925_unsigned_parameters_present", "3.1", bothInputKinds, func(a *Artifact) *Finding {
		if !usesUnsignedAlgorithm(a) {
			return nil
		}
		if a.TBSSignature.Algorithm.Equal(oidUnsigned) && a.TBSSignature.ParametersPresent ||
			a.OuterSignature != nil && a.OuterSignature.Algorithm.Equal(oidUnsigned) && a.OuterSignature.ParametersPresent {
			return errorFinding("signatureAlgorithm.parameters", "id-alg-unsigned parameters are present")
		}
		return nil
	}),
	rfc9925Rule("e_rfc9925_unsigned_signature_not_empty", "3.1", certificateInputKinds, func(a *Artifact) *Finding {
		if usesUnsignedAlgorithm(a) && (len(a.SignatureValue) != 0 || a.SignatureUnused != 0) {
			return errorFinding("signatureValue", "id-alg-unsigned signatureValue is not empty")
		}
		return nil
	}),
	rfc9925Rule("e_rfc9925_unsigned_issuer_unique_id_present", "3.2", bothInputKinds, func(a *Artifact) *Finding {
		if usesUnsignedAlgorithm(a) && a.IssuerUniqueIDPresent {
			return errorFinding("tbsCertificate.issuerUniqueID", "unsigned certificate contains issuerUniqueID")
		}
		return nil
	}),
	rfc9925Rule("w_rfc9925_unsigned_authority_key_identifier_present", "3.3", bothInputKinds, func(a *Artifact) *Finding {
		if usesUnsignedAlgorithm(a) && countExtensions(a, oidAuthorityKeyIdentifier) != 0 {
			return warningFinding("tbsCertificate.extensions.authorityKeyIdentifier", "unsigned certificate contains authority key identifier")
		}
		return nil
	}),
	rfc9925Rule("w_rfc9925_unsigned_issuer_alternative_name_present", "3.3", bothInputKinds, func(a *Artifact) *Finding {
		if usesUnsignedAlgorithm(a) && countExtensions(a, oidIssuerAlternativeName) != 0 {
			return warningFinding("tbsCertificate.extensions.issuerAlternativeName", "unsigned certificate contains issuer alternative name")
		}
		return nil
	}),
}

var (
	caKinds               = []ArtifactKind{ArtifactCA}
	subscriberKinds       = []ArtifactKind{ArtifactSubscriber}
	bothArtifactKinds     = []ArtifactKind{ArtifactCA, ArtifactSubscriber}
	bothInputKinds        = []InputKind{InputCertificate, InputTBSCertificate}
	certificateInputKinds = []InputKind{InputCertificate}
)

func LintDraft05(artifact *Artifact) []Finding {
	return runRules(artifact, draft05Rules)
}

// Draft05RuleCodes returns the stable finding codes registered for draft-05,
// including the conditional RFC 9925 checks.
func Draft05RuleCodes() []string {
	codes := make([]string, len(draft05Rules))
	for i, rule := range draft05Rules {
		codes[i] = rule.Code
	}
	sort.Strings(codes)
	return codes
}

// LintDraft05ForKind evaluates draft-05 rules in an explicit CA or subscriber
// profile context without changing the parsed artifact's autodetected kind.
func LintDraft05ForKind(artifact *Artifact, expected ArtifactKind) []Finding {
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
	return runRules(&local, draft05Rules)
}

func draftRule(code, section string, kinds []ArtifactKind, inputKinds []InputKind, evaluate func(*Artifact) *Finding) Rule {
	return Rule{Code: code, Source: draft05Source, Section: section, Kinds: kinds, InputKinds: inputKinds, Evaluate: evaluate}
}

func rfc9925Rule(code, section string, inputKinds []InputKind, evaluate func(*Artifact) *Finding) Rule {
	return Rule{Code: code, Source: rfc9925Source, Section: section, Kinds: caKinds, InputKinds: inputKinds, Evaluate: evaluate}
}

func errorFinding(field, message string) *Finding {
	return &Finding{Field: field, Message: message, Severity: Error}
}

func warningFinding(field, message string) *Finding {
	return &Finding{Field: field, Message: message, Severity: Warning}
}

func fatalFinding(field, message string) *Finding {
	return &Finding{Field: field, Message: message, Severity: Fatal}
}

func algorithmIdentifiersEqual(left, right AlgorithmIdentifier) bool {
	if len(left.Raw) != 0 && len(right.Raw) != 0 {
		return bytes.Equal(left.Raw, right.Raw)
	}
	if !left.Algorithm.Equal(right.Algorithm) || left.ParametersPresent != right.ParametersPresent {
		return false
	}
	return !left.ParametersPresent || bytes.Equal(left.Parameters.FullBytes, right.Parameters.FullBytes)
}

func validMTCSerialBound(serial *big.Int) bool {
	return serial != nil && serial.Sign() >= 0 && serial.Cmp(maxMTCSerial) <= 0
}

func matchingExtensions(artifact *Artifact, oid asn1.ObjectIdentifier) []Extension {
	var matches []Extension
	for _, extension := range artifact.Extensions {
		if extension.ID.Equal(oid) {
			matches = append(matches, extension)
		}
	}
	return matches
}

func countExtensions(artifact *Artifact, oid asn1.ObjectIdentifier) int {
	count := 0
	for _, extension := range artifact.Extensions {
		if extension.ID.Equal(oid) {
			count++
		}
	}
	return count
}

func keyCertSignSet(input []byte) bool {
	value, err := parseExactDER(input)
	if err != nil {
		return false
	}
	namedBits, unused, err := parseBitString(value, "keyUsage")
	if err != nil || len(namedBits) == 0 {
		return false
	}
	last := namedBits[len(namedBits)-1]
	return last != 0 && unused == bits.TrailingZeros8(last) && namedBits[0]&0x04 != 0
}

func basicConstraintsCA(input []byte) bool {
	value, err := parseExactDER(input)
	if err != nil || expectDER(value, classUniversal, asn1.TagSequence, true, "basicConstraints") != nil {
		return false
	}
	contents := value.contents
	caDER, err := takeDER(&contents, "basicConstraints cA")
	if err != nil || caDER.class != classUniversal || caDER.tag != asn1.TagBoolean || caDER.constructed || !bytes.Equal(caDER.contents, []byte{0xff}) {
		return false
	}
	if len(contents) == 0 {
		return true
	}
	pathLenDER, err := takeDER(&contents, "basicConstraints pathLenConstraint")
	if err != nil {
		return false
	}
	pathLen, err := parseInteger(pathLenDER, "basicConstraints pathLenConstraint")
	return err == nil && pathLen.Sign() >= 0 && noRemainingDER(contents, "basicConstraints") == nil
}

func subjectKeyIdentifierMatches(input, caID []byte) bool {
	if len(caID) == 0 {
		return false
	}
	value, err := parseExactDER(input)
	if err != nil || expectDER(value, classUniversal, asn1.TagOctetString, false, "subjectKeyIdentifier") != nil {
		return false
	}
	return bytes.Equal(value.contents, caID)
}

func usesUnsignedAlgorithm(artifact *Artifact) bool {
	return artifact.TBSSignature.Algorithm.Equal(oidUnsigned) ||
		artifact.OuterSignature != nil && artifact.OuterSignature.Algorithm.Equal(oidUnsigned)
}

func proofAvailable(artifact *Artifact) bool {
	return artifact.Proof != nil && artifact.ProofParseError == nil
}

func proofRangeValid(proof *Proof) bool {
	return proof.Start <= maxUint48 && proof.End <= maxUint48 && proof.Start < proof.End
}

func proofExtensionsHaveDuplicate(extensions []EntryExtension) bool {
	seen := make(map[uint16]struct{}, len(extensions))
	for _, extension := range extensions {
		if _, ok := seen[extension.Type]; ok {
			return true
		}
		seen[extension.Type] = struct{}{}
	}
	return false
}

func cosignersHaveDuplicate(signatures []MTCSignature) bool {
	seen := make(map[string]struct{}, len(signatures))
	for _, signature := range signatures {
		id := string(signature.CosignerID)
		if _, ok := seen[id]; ok {
			return true
		}
		seen[id] = struct{}{}
	}
	return false
}

func compareCosignerIDs(left, right []byte) int {
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return bytes.Compare(left, right)
}
