package mtc

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

const (
	maxTrustAnchorIDLength        = 255
	maxTrustAnchorIDArcTextLength = 3 * maxTrustAnchorIDLength
	maxTrustAnchorIDTextLength    = 4*maxTrustAnchorIDLength - 1
)

func ParseCAIDName(input []byte) ([]byte, error) {
	root, err := parseExactDER(append([]byte(nil), input...))
	if err != nil {
		return nil, fmt.Errorf("parse CA-ID Name: %w", err)
	}
	if err := expectDER(root, classUniversal, asn1.TagSequence, true, "Name"); err != nil {
		return nil, err
	}
	name := root.contents
	rdn, err := takeDER(&name, "CA-ID RDN")
	if err != nil {
		return nil, err
	}
	if err := expectDER(rdn, classUniversal, asn1.TagSet, true, "CA-ID RDN"); err != nil {
		return nil, err
	}
	if err := noRemainingDER(name, "CA-ID Name"); err != nil {
		return nil, err
	}
	rdnContents := rdn.contents
	atv, err := takeDER(&rdnContents, "CA-ID attribute")
	if err != nil {
		return nil, err
	}
	if err := expectDER(atv, classUniversal, asn1.TagSequence, true, "CA-ID attribute"); err != nil {
		return nil, err
	}
	if err := noRemainingDER(rdnContents, "CA-ID RDN"); err != nil {
		return nil, err
	}
	attribute := atv.contents
	oidValue, err := takeDER(&attribute, "CA-ID attribute type")
	if err != nil {
		return nil, err
	}
	oid, err := parseOID(oidValue, "CA-ID attribute type")
	if err != nil {
		return nil, err
	}
	if !oid.Equal(OIDCAID) {
		return nil, errors.New("Name attribute is not id-rdna-trustAnchorID")
	}
	caID, err := takeDER(&attribute, "CA-ID attribute value")
	if err != nil {
		return nil, err
	}
	if err := expectDER(caID, classUniversal, asn1.TagUTF8String, false, "CA-ID attribute value"); err != nil {
		return nil, err
	}
	if err := noRemainingDER(attribute, "CA-ID attribute"); err != nil {
		return nil, err
	}
	return encodeRelativeOID(caID.contents)
}

func encodeRelativeOID(text []byte) ([]byte, error) {
	if len(text) == 0 {
		return nil, errors.New("CA-ID attribute value is empty")
	}
	// An arc needs at most three decimal digits per base-128 byte, and the
	// number of separators is less than the number of encoded bytes. Therefore
	// no valid 255-byte identifier can exceed 4*255-1 text bytes, or contain an
	// arc longer than 3*255 decimal digits.
	if len(text) > maxTrustAnchorIDTextLength {
		return nil, errors.New("CA-ID textual representation exceeds maximum length")
	}
	encodedCapacity := len(text)
	if encodedCapacity > maxTrustAnchorIDLength {
		encodedCapacity = maxTrustAnchorIDLength
	}
	encoded := make([]byte, 0, encodedCapacity)
	for len(text) != 0 {
		dot := len(text)
		for i, b := range text {
			if b == '.' {
				dot = i
				break
			}
		}
		arc := text[:dot]
		if len(arc) == 0 {
			return nil, errors.New("CA-ID attribute value contains an empty arc")
		}
		if len(arc) > maxTrustAnchorIDArcTextLength {
			return nil, errors.New("CA-ID decimal arc exceeds maximum length")
		}
		if len(arc) > 1 && arc[0] == '0' {
			return nil, errors.New("CA-ID attribute value contains a non-canonical arc")
		}
		for _, b := range arc {
			if b < '0' || b > '9' {
				return nil, errors.New("CA-ID attribute value is not an ASCII dotted-decimal identifier")
			}
		}
		value, ok := new(big.Int).SetString(string(arc), 10)
		if !ok {
			return nil, errors.New("CA-ID attribute value contains an invalid arc")
		}
		encodedLength := (value.BitLen() + 6) / 7
		if encodedLength == 0 {
			encodedLength = 1
		}
		if len(encoded)+encodedLength > maxTrustAnchorIDLength {
			return nil, errors.New("CA-ID binary representation exceeds 255 bytes")
		}
		encoded = appendBase128(encoded, value)
		if dot == len(text) {
			break
		}
		text = text[dot+1:]
		if len(text) == 0 {
			return nil, errors.New("CA-ID attribute value contains an empty arc")
		}
	}
	return encoded, nil
}

func appendBase128(output []byte, value *big.Int) []byte {
	length := (value.BitLen() + 6) / 7
	if length == 0 {
		return append(output, 0)
	}
	encoded := make([]byte, length)
	remaining := new(big.Int).Set(value)
	for i := len(encoded) - 1; i >= 0; i-- {
		encoded[i] = byte(remaining.Uint64() & 0x7f)
		if i != len(encoded)-1 {
			encoded[i] |= 0x80
		}
		remaining.Rsh(remaining, 7)
	}
	return append(output, encoded...)
}

func ParseCertificationAuthorityExtension(input []byte) (*CertificationAuthority, error) {
	root, err := parseExactDER(append([]byte(nil), input...))
	if err != nil {
		return nil, fmt.Errorf("parse MTC CA extension: %w", err)
	}
	if err := expectDER(root, classUniversal, asn1.TagSequence, true, "MTCCertificationAuthority"); err != nil {
		return nil, err
	}
	contents := root.contents
	logHashDER, err := takeDER(&contents, "logHash")
	if err != nil {
		return nil, err
	}
	logHash, err := parseAlgorithmIdentifier(logHashDER)
	if err != nil {
		return nil, fmt.Errorf("parse logHash: %w", err)
	}
	sigAlgDER, err := takeDER(&contents, "sigAlg")
	if err != nil {
		return nil, err
	}
	sigAlg, err := parseAlgorithmIdentifier(sigAlgDER)
	if err != nil {
		return nil, fmt.Errorf("parse sigAlg: %w", err)
	}
	minDER, err := takeDER(&contents, "minSerial")
	if err != nil {
		return nil, err
	}
	minSerial, err := parseInteger(minDER, "minSerial")
	if err != nil {
		return nil, err
	}
	maxDER, err := takeDER(&contents, "maxSerial")
	if err != nil {
		return nil, err
	}
	maxSerial, err := parseInteger(maxDER, "maxSerial")
	if err != nil {
		return nil, err
	}
	if err := noRemainingDER(contents, "MTCCertificationAuthority"); err != nil {
		return nil, err
	}
	return &CertificationAuthority{
		LogHash:            logHash,
		SignatureAlgorithm: sigAlg,
		MinSerial:          minSerial,
		MaxSerial:          maxSerial,
	}, nil
}

func parseAlgorithmIdentifier(value derValue) (AlgorithmIdentifier, error) {
	if err := expectDER(value, classUniversal, asn1.TagSequence, true, "AlgorithmIdentifier"); err != nil {
		return AlgorithmIdentifier{}, err
	}
	contents := value.contents
	oidDER, err := takeDER(&contents, "algorithm")
	if err != nil {
		return AlgorithmIdentifier{}, err
	}
	oid, err := parseOID(oidDER, "algorithm")
	if err != nil {
		return AlgorithmIdentifier{}, err
	}
	result := AlgorithmIdentifier{Raw: value.raw, Algorithm: oid}
	if len(contents) != 0 {
		parameters, err := takeDER(&contents, "parameters")
		if err != nil {
			return AlgorithmIdentifier{}, err
		}
		var raw asn1.RawValue
		if rest, err := asn1.Unmarshal(parameters.raw, &raw); err != nil || len(rest) != 0 {
			return AlgorithmIdentifier{}, errors.New("invalid AlgorithmIdentifier parameters")
		}
		result.ParametersPresent = true
		result.Parameters = raw
	}
	if err := noRemainingDER(contents, "AlgorithmIdentifier"); err != nil {
		return AlgorithmIdentifier{}, err
	}
	return result, nil
}

func parseOID(value derValue, field string) (asn1.ObjectIdentifier, error) {
	if err := expectDER(value, classUniversal, asn1.TagOID, false, field); err != nil {
		return nil, err
	}
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(value.raw, &oid); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("invalid %s OBJECT IDENTIFIER", field)
	}
	return oid, nil
}

func parseInteger(value derValue, field string) (*big.Int, error) {
	if err := expectDER(value, classUniversal, asn1.TagInteger, false, field); err != nil {
		return nil, err
	}
	var integer *big.Int
	if rest, err := asn1.Unmarshal(value.raw, &integer); err != nil || len(rest) != 0 || integer == nil {
		return nil, fmt.Errorf("invalid %s INTEGER", field)
	}
	return integer, nil
}
