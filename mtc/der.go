package mtc

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

const (
	classUniversal           = 0
	classContext             = 2
	maxDERDepth              = 64
	tagEndOfContents         = 0
	tagObjectDescriptor      = 7
	tagExternal              = 8
	tagReal                  = 9
	tagEmbeddedPDV           = 11
	tagRelativeOID           = 13
	tagTime                  = 14
	tagReserved              = 15
	tagVideotexString        = 21
	tagGraphicString         = 25
	tagVisibleString         = 26
	tagUniversalString       = 28
	tagCharacterString       = 29
	tagDate                  = 31
	tagTimeOfDay             = 32
	tagDateTime              = 33
	tagDuration              = 34
	tagOIDIRI                = 35
	tagRelativeOIDIRI        = 36
	lastAssignedUniversalTag = tagRelativeOIDIRI
)

type derValue struct {
	class       int
	tag         int
	constructed bool
	raw         []byte
	contents    []byte
}

func parseExactDER(input []byte) (derValue, error) {
	value, rest, err := parseDER(input)
	if err != nil {
		return derValue{}, err
	}
	if len(rest) != 0 {
		return derValue{}, errors.New("trailing data after DER value")
	}
	if err := validateDER(value, 0); err != nil {
		return derValue{}, err
	}
	return value, nil
}

func parseDER(input []byte) (derValue, []byte, error) {
	if len(input) < 2 {
		return derValue{}, nil, errors.New("truncated DER value")
	}
	first := input[0]
	value := derValue{
		class:       int(first >> 6),
		constructed: first&0x20 != 0,
		tag:         int(first & 0x1f),
	}
	offset := 1
	if value.tag == 0x1f {
		value.tag = 0
		if offset >= len(input) || input[offset]&0x7f == 0 {
			return derValue{}, nil, errors.New("non-minimal high-tag-number form")
		}
		for {
			if offset >= len(input) {
				return derValue{}, nil, errors.New("truncated high-tag-number form")
			}
			part := input[offset]
			offset++
			if value.tag > (math.MaxInt-int(part&0x7f))/128 {
				return derValue{}, nil, errors.New("DER tag overflows int")
			}
			value.tag = value.tag*128 + int(part&0x7f)
			if part&0x80 == 0 {
				break
			}
		}
		if value.tag < 31 {
			return derValue{}, nil, errors.New("non-minimal high-tag-number form")
		}
	}
	if offset >= len(input) {
		return derValue{}, nil, errors.New("missing DER length")
	}
	firstLength := input[offset]
	offset++
	length := 0
	if firstLength&0x80 == 0 {
		length = int(firstLength)
	} else {
		lengthBytes := int(firstLength & 0x7f)
		if lengthBytes == 0 {
			return derValue{}, nil, errors.New("indefinite DER length")
		}
		if lengthBytes > len(input)-offset {
			return derValue{}, nil, errors.New("truncated DER length")
		}
		if input[offset] == 0 {
			return derValue{}, nil, errors.New("non-minimal DER length")
		}
		for i := 0; i < lengthBytes; i++ {
			if length > (math.MaxInt-int(input[offset+i]))/256 {
				return derValue{}, nil, errors.New("DER length overflows int")
			}
			length = length*256 + int(input[offset+i])
		}
		offset += lengthBytes
		if length < 128 {
			return derValue{}, nil, errors.New("non-minimal DER length")
		}
	}
	if length > len(input)-offset {
		return derValue{}, nil, errors.New("truncated DER contents")
	}
	end := offset + length
	value.raw = input[:end]
	value.contents = input[offset:end]
	return value, input[end:], nil
}

func validateDER(value derValue, depth int) error {
	if depth > maxDERDepth {
		return fmt.Errorf("DER nesting exceeds maximum depth %d", maxDERDepth)
	}
	if value.class == classUniversal {
		if err := validateUniversalDER(value); err != nil {
			return err
		}
	}
	if !value.constructed {
		return nil
	}
	remaining := value.contents
	var previous []byte
	for len(remaining) > 0 {
		child, rest, err := parseDER(remaining)
		if err != nil {
			return fmt.Errorf("invalid constructed DER contents: %w", err)
		}
		if value.class == classUniversal && value.tag == asn1.TagSet && previous != nil && bytes.Compare(previous, child.raw) > 0 {
			return errors.New("DER SET elements are not in canonical order")
		}
		if err := validateDER(child, depth+1); err != nil {
			return err
		}
		previous = child.raw
		remaining = rest
	}
	return nil
}

func validateUniversalDER(value derValue) error {
	switch value.tag {
	case tagEndOfContents, tagReserved:
		return fmt.Errorf("reserved universal DER tag %d", value.tag)
	case tagExternal, tagEmbeddedPDV, asn1.TagSequence, asn1.TagSet, tagCharacterString:
		if !value.constructed {
			return fmt.Errorf("primitive universal DER tag %d is not permitted", value.tag)
		}
		return nil
	}
	if value.tag > lastAssignedUniversalTag {
		return fmt.Errorf("unassigned universal DER tag %d", value.tag)
	}
	if value.constructed {
		return fmt.Errorf("constructed universal DER tag %d is not permitted", value.tag)
	}
	switch value.tag {
	case asn1.TagBoolean:
		if len(value.contents) != 1 || value.contents[0] != 0 && value.contents[0] != 0xff {
			return errors.New("invalid DER BOOLEAN")
		}
	case asn1.TagInteger:
		if !isMinimalInteger(value.contents) {
			return errors.New("invalid DER INTEGER")
		}
	case asn1.TagBitString:
		if len(value.contents) == 0 || value.contents[0] > 7 {
			return errors.New("invalid DER BIT STRING")
		}
		unused := value.contents[0]
		if len(value.contents) == 1 && unused != 0 {
			return errors.New("empty DER BIT STRING has unused bits")
		}
		if unused != 0 && value.contents[len(value.contents)-1]&byte((1<<unused)-1) != 0 {
			return errors.New("non-zero unused DER BIT STRING bits")
		}
	case asn1.TagOctetString:
		return nil
	case asn1.TagNull:
		if len(value.contents) != 0 {
			return errors.New("invalid DER NULL")
		}
	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(value.raw, &oid); err != nil || len(rest) != 0 {
			return errors.New("invalid DER OBJECT IDENTIFIER")
		}
	case asn1.TagEnum:
		if !isMinimalInteger(value.contents) {
			return errors.New("invalid DER ENUMERATED")
		}
	case asn1.TagUTF8String:
		if !utf8.Valid(value.contents) {
			return errors.New("invalid DER UTF8String")
		}
	case tagRelativeOID:
		if !isMinimalBase128(value.contents) {
			return errors.New("invalid DER RELATIVE-OID")
		}
	case tagObjectDescriptor, tagTime, tagVideotexString, tagGraphicString:
		// These schema-driven character types remain opaque in ANY values.
		return nil
	case tagReal:
		if !validDERReal(value.contents) {
			return errors.New("invalid or non-canonical DER REAL")
		}
	case asn1.TagNumericString:
		if !allBytes(value.contents, isNumericStringByte) {
			return errors.New("invalid DER NumericString")
		}
	case asn1.TagPrintableString:
		if !allBytes(value.contents, isPrintableStringByte) {
			return errors.New("invalid DER PrintableString")
		}
	case asn1.TagT61String:
		// TeletexString uses an octet-oriented character repertoire.
		return nil
	case asn1.TagIA5String:
		if !allBytes(value.contents, func(b byte) bool { return b <= 0x7f }) {
			return errors.New("invalid DER IA5String")
		}
	case asn1.TagUTCTime:
		if err := validateUTCTime(value); err != nil {
			return err
		}
	case asn1.TagGeneralizedTime:
		if err := validateGeneralizedTime(value); err != nil {
			return err
		}
	case tagVisibleString:
		if !allBytes(value.contents, func(b byte) bool { return b >= 0x20 && b <= 0x7e }) {
			return errors.New("invalid DER VisibleString")
		}
	case asn1.TagGeneralString:
		// GeneralString uses an octet-oriented character repertoire.
		return nil
	case tagUniversalString:
		if !validUniversalString(value.contents) {
			return errors.New("invalid DER UniversalString")
		}
	case asn1.TagBMPString:
		if !validBMPString(value.contents) {
			return errors.New("invalid DER BMPString")
		}
	case tagDate, tagTimeOfDay, tagDateTime, tagDuration:
		if !allBytes(value.contents, func(b byte) bool { return b <= 0x7f }) {
			return fmt.Errorf("invalid DER universal time type %d", value.tag)
		}
	case tagOIDIRI, tagRelativeOIDIRI:
		if !utf8.Valid(value.contents) {
			return fmt.Errorf("invalid DER OID internationalized resource identifier type %d", value.tag)
		}
	}
	return nil
}

func validDERReal(contents []byte) bool {
	if len(contents) == 0 {
		return true
	}
	if len(contents) == 1 && contents[0] >= 0x40 && contents[0] <= 0x43 {
		return true
	}
	first := contents[0]
	if first&0x80 == 0 {
		return first == 0x03 && validDERDecimalReal(contents[1:])
	}
	if first&0x30 != 0 || first&0x0c != 0 {
		return false
	}
	exponentLength := int(first&0x03) + 1
	offset := 1
	if exponentLength == 4 {
		if len(contents) < 2 || contents[1] <= 3 {
			return false
		}
		exponentLength = int(contents[1])
		offset++
	}
	if exponentLength >= len(contents)-offset {
		return false
	}
	exponent := contents[offset : offset+exponentLength]
	if !isMinimalInteger(exponent) {
		return false
	}
	mantissa := contents[offset+exponentLength:]
	return mantissa[0] != 0 && mantissa[len(mantissa)-1]&1 == 1
}

func validDERDecimalReal(contents []byte) bool {
	marker := bytes.Index(contents, []byte(".E"))
	if marker < 1 || marker+2 >= len(contents) {
		return false
	}
	mantissa := contents[:marker]
	if mantissa[0] == '-' {
		mantissa = mantissa[1:]
	}
	if len(mantissa) == 0 || !allBytes(mantissa, isDigit) || mantissa[0] == '0' || mantissa[len(mantissa)-1] == '0' {
		return false
	}
	exponent := contents[marker+2:]
	if bytes.Equal(exponent, []byte("+0")) {
		return true
	}
	if exponent[0] == '+' {
		return false
	}
	if exponent[0] == '-' {
		exponent = exponent[1:]
	}
	return len(exponent) != 0 && exponent[0] != '0' && allBytes(exponent, isDigit)
}

func validateUTCTime(value derValue) error {
	if len(value.contents) != 13 || value.contents[12] != 'Z' || !allBytes(value.contents[:12], isDigit) {
		return errors.New("non-canonical DER UTCTime")
	}
	return validateTimeValue(value, "UTCTime")
}

func validateGeneralizedTime(value derValue) error {
	contents := value.contents
	if len(contents) < 15 || contents[len(contents)-1] != 'Z' || !allBytes(contents[:14], isDigit) {
		return errors.New("non-canonical DER GeneralizedTime")
	}
	if len(contents) > 15 {
		fraction := contents[15 : len(contents)-1]
		if contents[14] != '.' || len(fraction) == 0 || !allBytes(fraction, isDigit) || fraction[len(fraction)-1] == '0' {
			return errors.New("non-canonical DER GeneralizedTime fraction")
		}
	}
	return validateTimeValue(value, "GeneralizedTime")
}

func validateTimeValue(value derValue, name string) error {
	var parsed time.Time
	if rest, err := asn1.Unmarshal(value.raw, &parsed); err != nil || len(rest) != 0 {
		return fmt.Errorf("invalid DER %s", name)
	}
	return nil
}

func allBytes(input []byte, valid func(byte) bool) bool {
	for _, b := range input {
		if !valid(b) {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isNumericStringByte(b byte) bool {
	return b == ' ' || isDigit(b)
}

func isPrintableStringByte(b byte) bool {
	if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || isDigit(b) {
		return true
	}
	return bytes.ContainsRune([]byte(" '()+,-./:=?"), rune(b))
}

func validUniversalString(contents []byte) bool {
	if len(contents)%4 != 0 {
		return false
	}
	for len(contents) != 0 {
		codePoint := uint32(contents[0])<<24 | uint32(contents[1])<<16 | uint32(contents[2])<<8 | uint32(contents[3])
		if codePoint > utf8.MaxRune || codePoint >= 0xd800 && codePoint <= 0xdfff {
			return false
		}
		contents = contents[4:]
	}
	return true
}

func validBMPString(contents []byte) bool {
	if len(contents)%2 != 0 {
		return false
	}
	for len(contents) != 0 {
		codePoint := uint16(contents[0])<<8 | uint16(contents[1])
		if codePoint >= 0xd800 && codePoint <= 0xdfff {
			return false
		}
		contents = contents[2:]
	}
	return true
}

func isMinimalInteger(contents []byte) bool {
	if len(contents) == 0 {
		return false
	}
	if len(contents) > 1 {
		if contents[0] == 0 && contents[1]&0x80 == 0 {
			return false
		}
		if contents[0] == 0xff && contents[1]&0x80 != 0 {
			return false
		}
	}
	return true
}

func isMinimalBase128(contents []byte) bool {
	if len(contents) == 0 {
		return false
	}
	atComponentStart := true
	for _, b := range contents {
		if atComponentStart && b == 0x80 {
			return false
		}
		atComponentStart = b&0x80 == 0
	}
	return atComponentStart
}

func expectDER(value derValue, class, tag int, constructed bool, field string) error {
	if value.class != class || value.tag != tag || value.constructed != constructed {
		return fmt.Errorf("%s has unexpected DER tag", field)
	}
	return nil
}

func takeDER(input *[]byte, field string) (derValue, error) {
	value, rest, err := parseDER(*input)
	if err != nil {
		return derValue{}, fmt.Errorf("parse %s: %w", field, err)
	}
	*input = rest
	return value, nil
}

func noRemainingDER(input []byte, structure string) error {
	if len(input) != 0 {
		return fmt.Errorf("unexpected fields in %s", structure)
	}
	return nil
}
