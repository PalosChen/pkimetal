package mtc

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

func Parse(input []byte, kind InputKind) (*Artifact, error) {
	if kind != InputCertificate && kind != InputTBSCertificate {
		return nil, fmt.Errorf("unsupported input kind %d", kind)
	}
	raw := append([]byte(nil), input...)
	root, err := parseExactDER(raw)
	if err != nil {
		return nil, err
	}
	if err := expectDER(root, classUniversal, asn1.TagSequence, true, "input"); err != nil {
		return nil, err
	}
	artifact := &Artifact{InputKind: kind, Raw: raw}
	var tbs derValue
	if kind == InputCertificate {
		certificate := root.contents
		if tbs, err = takeDER(&certificate, "tbsCertificate"); err != nil {
			return nil, err
		}
		outerDER, err := takeDER(&certificate, "signatureAlgorithm")
		if err != nil {
			return nil, err
		}
		outer, err := parseAlgorithmIdentifier(outerDER)
		if err != nil {
			return nil, fmt.Errorf("parse outer signature algorithm: %w", err)
		}
		artifact.OuterSignature = &outer
		signatureDER, err := takeDER(&certificate, "signatureValue")
		if err != nil {
			return nil, err
		}
		artifact.SignatureValue, artifact.SignatureUnused, err = parseBitString(signatureDER, "signatureValue")
		if err != nil {
			return nil, err
		}
		if err := noRemainingDER(certificate, "Certificate"); err != nil {
			return nil, err
		}
	} else {
		tbs = root
	}
	if err := parseTBSCertificate(tbs, artifact); err != nil {
		return nil, err
	}
	classifyArtifact(artifact)
	if artifact.InputKind == InputCertificate && artifact.Kind == ArtifactSubscriber {
		artifact.Proof, artifact.ProofParseError = ParseProof(artifact.SignatureValue)
	}
	return artifact, nil
}

func parseTBSCertificate(tbs derValue, artifact *Artifact) error {
	if err := expectDER(tbs, classUniversal, asn1.TagSequence, true, "TBSCertificate"); err != nil {
		return err
	}
	artifact.RawTBS = tbs.raw
	contents := tbs.contents
	first, err := takeDER(&contents, "version or serialNumber")
	if err != nil {
		return err
	}
	serialDER := first
	if first.class == classContext && first.tag == 0 && first.constructed {
		versionContents := first.contents
		versionDER, err := takeDER(&versionContents, "version")
		if err != nil {
			return err
		}
		version, err := parseInteger(versionDER, "version")
		if err != nil {
			return err
		}
		if err := noRemainingDER(versionContents, "version"); err != nil {
			return err
		}
		// Version is DEFAULT v1: an absent field means v1, while explicitly
		// encoding v1 is non-canonical DER. Other integers are outside the
		// TBSCertificate Version type; v2/v3 profile semantics remain lintable.
		switch {
		case version.Sign() < 0 || !version.IsInt64() || version.Int64() > 2:
			return fmt.Errorf("unsupported TBSCertificate version %s", version)
		case version.Sign() == 0:
			return errors.New("explicitly encoded default TBSCertificate version v1")
		}
		serialDER, err = takeDER(&contents, "serialNumber")
		if err != nil {
			return err
		}
	}
	artifact.SerialNumber, err = parseInteger(serialDER, "serialNumber")
	if err != nil {
		return err
	}
	signatureDER, err := takeDER(&contents, "signature")
	if err != nil {
		return err
	}
	artifact.TBSSignature, err = parseAlgorithmIdentifier(signatureDER)
	if err != nil {
		return fmt.Errorf("parse TBS signature algorithm: %w", err)
	}
	issuer, err := takeDER(&contents, "issuer")
	if err != nil {
		return err
	}
	if err := expectDER(issuer, classUniversal, asn1.TagSequence, true, "issuer"); err != nil {
		return err
	}
	artifact.IssuerRaw = issuer.raw
	artifact.IssuerCAID, _ = ParseCAIDName(issuer.raw)
	validity, err := takeDER(&contents, "validity")
	if err != nil {
		return err
	}
	artifact.NotBefore, artifact.NotAfter, err = parseValidity(validity)
	if err != nil {
		return err
	}
	subject, err := takeDER(&contents, "subject")
	if err != nil {
		return err
	}
	if err := expectDER(subject, classUniversal, asn1.TagSequence, true, "subject"); err != nil {
		return err
	}
	artifact.SubjectRaw = subject.raw
	artifact.SubjectCAID, _ = ParseCAIDName(subject.raw)
	spki, err := takeDER(&contents, "subjectPublicKeyInfo")
	if err != nil {
		return err
	}
	artifact.SubjectPublicKey, err = parseSubjectPublicKeyInfo(spki)
	if err != nil {
		return err
	}
	lastOptionalTag := 0
	for len(contents) != 0 {
		optional, err := takeDER(&contents, "optional TBSCertificate field")
		if err != nil {
			return err
		}
		if optional.class != classContext || optional.tag < 1 || optional.tag > 3 || optional.tag <= lastOptionalTag {
			return errors.New("invalid optional TBSCertificate field")
		}
		lastOptionalTag = optional.tag
		switch optional.tag {
		case 1:
			if optional.constructed {
				return errors.New("issuerUniqueID is constructed")
			}
			if _, _, err := parseImplicitBitString(optional, "issuerUniqueID"); err != nil {
				return err
			}
			artifact.IssuerUniqueIDPresent = true
		case 2:
			if optional.constructed {
				return errors.New("subjectUniqueID is constructed")
			}
			if _, _, err := parseImplicitBitString(optional, "subjectUniqueID"); err != nil {
				return err
			}
			artifact.SubjectUniqueIDPresent = true
		case 3:
			if !optional.constructed {
				return errors.New("extensions field is primitive")
			}
			artifact.Extensions, err = parseExtensions(optional)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func parseSubjectPublicKeyInfo(value derValue) (SubjectPublicKeyInfo, error) {
	if err := expectDER(value, classUniversal, asn1.TagSequence, true, "SubjectPublicKeyInfo"); err != nil {
		return SubjectPublicKeyInfo{}, err
	}
	contents := value.contents
	algorithmDER, err := takeDER(&contents, "SPKI algorithm")
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}
	algorithm, err := parseAlgorithmIdentifier(algorithmDER)
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}
	keyDER, err := takeDER(&contents, "subjectPublicKey")
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}
	key, unused, err := parseBitString(keyDER, "subjectPublicKey")
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}
	if err := noRemainingDER(contents, "SubjectPublicKeyInfo"); err != nil {
		return SubjectPublicKeyInfo{}, err
	}
	return SubjectPublicKeyInfo{
		Raw:              value.raw,
		Algorithm:        algorithm,
		SubjectPublicKey: key,
		UnusedBits:       unused,
	}, nil
}

func parseValidity(value derValue) (time.Time, time.Time, error) {
	if err := expectDER(value, classUniversal, asn1.TagSequence, true, "validity"); err != nil {
		return time.Time{}, time.Time{}, err
	}
	contents := value.contents
	notBeforeDER, err := takeDER(&contents, "notBefore")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notBefore, err := parseTime(notBeforeDER, "notBefore")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfterDER, err := takeDER(&contents, "notAfter")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := parseTime(notAfterDER, "notAfter")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if err := noRemainingDER(contents, "validity"); err != nil {
		return time.Time{}, time.Time{}, err
	}
	return notBefore, notAfter, nil
}

func parseTime(value derValue, field string) (time.Time, error) {
	if value.class != classUniversal || value.constructed || value.tag != asn1.TagUTCTime && value.tag != asn1.TagGeneralizedTime {
		return time.Time{}, fmt.Errorf("%s has unexpected DER tag", field)
	}
	var result time.Time
	if rest, err := asn1.Unmarshal(value.raw, &result); err != nil || len(rest) != 0 {
		return time.Time{}, fmt.Errorf("invalid %s", field)
	}
	return result, nil
}

func parseExtensions(explicit derValue) ([]Extension, error) {
	contents := explicit.contents
	sequence, err := takeDER(&contents, "extensions")
	if err != nil {
		return nil, err
	}
	if err := expectDER(sequence, classUniversal, asn1.TagSequence, true, "extensions"); err != nil {
		return nil, err
	}
	if err := noRemainingDER(contents, "extensions explicit wrapper"); err != nil {
		return nil, err
	}
	var extensions []Extension
	remaining := sequence.contents
	for len(remaining) != 0 {
		extensionDER, err := takeDER(&remaining, "extension")
		if err != nil {
			return nil, err
		}
		extension, err := parseExtension(extensionDER)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, extension)
	}
	return extensions, nil
}

func parseExtension(value derValue) (Extension, error) {
	if err := expectDER(value, classUniversal, asn1.TagSequence, true, "Extension"); err != nil {
		return Extension{}, err
	}
	contents := value.contents
	oidDER, err := takeDER(&contents, "extension ID")
	if err != nil {
		return Extension{}, err
	}
	oid, err := parseOID(oidDER, "extension ID")
	if err != nil {
		return Extension{}, err
	}
	critical := false
	next, err := takeDER(&contents, "extension critical or value")
	if err != nil {
		return Extension{}, err
	}
	if next.class == classUniversal && next.tag == asn1.TagBoolean && !next.constructed {
		critical = next.contents[0] != 0
		if !critical {
			return Extension{}, errors.New("DER Extension explicitly encodes default critical FALSE")
		}
		next, err = takeDER(&contents, "extension value")
		if err != nil {
			return Extension{}, err
		}
	}
	if err := expectDER(next, classUniversal, asn1.TagOctetString, false, "extension value"); err != nil {
		return Extension{}, err
	}
	if err := noRemainingDER(contents, "Extension"); err != nil {
		return Extension{}, err
	}
	return Extension{Raw: value.raw, ID: oid, Critical: critical, Value: next.contents}, nil
}

func parseBitString(value derValue, field string) ([]byte, int, error) {
	if err := expectDER(value, classUniversal, asn1.TagBitString, false, field); err != nil {
		return nil, 0, err
	}
	return append([]byte(nil), value.contents[1:]...), int(value.contents[0]), nil
}

func parseImplicitBitString(value derValue, field string) ([]byte, int, error) {
	if len(value.contents) == 0 || value.contents[0] > 7 {
		return nil, 0, fmt.Errorf("invalid %s BIT STRING", field)
	}
	unused := int(value.contents[0])
	bits := value.contents[1:]
	if len(bits) == 0 && unused != 0 || unused != 0 && bits[len(bits)-1]&byte((1<<unused)-1) != 0 {
		return nil, 0, fmt.Errorf("invalid %s BIT STRING", field)
	}
	return append([]byte(nil), bits...), unused, nil
}

func classifyArtifact(artifact *Artifact) {
	var caExtensionValue []byte
	caExtensionCount := 0
	for _, extension := range artifact.Extensions {
		if !extension.ID.Equal(OIDMTCCertificationAuthority) {
			continue
		}
		caExtensionCount++
		caExtensionValue = extension.Value
	}
	if caExtensionCount != 0 {
		artifact.Kind = ArtifactCA
		if caExtensionCount == 1 {
			artifact.CAParameters, artifact.CAExtensionError = ParseCertificationAuthorityExtension(caExtensionValue)
		} else {
			artifact.CAParameters = nil
			artifact.CAExtensionError = fmt.Errorf("duplicate MTC CA extensions: found %d", caExtensionCount)
		}
		return
	}
	if len(artifact.IssuerCAID) != 0 || artifact.TBSSignature.Algorithm.Equal(OIDMTCProof) {
		artifact.Kind = ArtifactSubscriber
	}
}
