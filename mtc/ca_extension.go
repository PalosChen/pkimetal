package mtc

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
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
	encoded := make([]byte, 0, len(text))
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
		if len(arc) > 1 && arc[0] == '0' {
			return nil, errors.New("CA-ID attribute value contains a non-canonical arc")
		}
		for _, b := range arc {
			if b < '0' || b > '9' {
				return nil, errors.New("CA-ID attribute value is not an ASCII dotted-decimal identifier")
			}
		}
		value, err := strconv.ParseUint(string(arc), 10, 64)
		if err != nil {
			return nil, errors.New("CA-ID attribute value arc overflows uint64")
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

func appendBase128(output []byte, value uint64) []byte {
	var encoded [10]byte
	i := len(encoded) - 1
	encoded[i] = byte(value & 0x7f)
	for value >>= 7; value != 0; value >>= 7 {
		i--
		encoded[i] = byte(value&0x7f) | 0x80
	}
	return append(output, encoded[i:]...)
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
