package mtc

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
)

const (
	classUniversal = 0
	classContext   = 2
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
	if err := validateDER(value); err != nil {
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

func validateDER(value derValue) error {
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
		if err := validateDER(child); err != nil {
			return err
		}
		previous = child.raw
		remaining = rest
	}
	return nil
}

func validateUniversalDER(value derValue) error {
	switch value.tag {
	case asn1.TagBoolean:
		if value.constructed || len(value.contents) != 1 || value.contents[0] != 0 && value.contents[0] != 0xff {
			return errors.New("invalid DER BOOLEAN")
		}
	case asn1.TagInteger:
		if value.constructed || !isMinimalInteger(value.contents) {
			return errors.New("invalid DER INTEGER")
		}
	case asn1.TagBitString:
		if value.constructed || len(value.contents) == 0 || value.contents[0] > 7 {
			return errors.New("invalid DER BIT STRING")
		}
		unused := value.contents[0]
		if len(value.contents) == 1 && unused != 0 {
			return errors.New("empty DER BIT STRING has unused bits")
		}
		if unused != 0 && value.contents[len(value.contents)-1]&byte((1<<unused)-1) != 0 {
			return errors.New("non-zero unused DER BIT STRING bits")
		}
	case asn1.TagNull:
		if value.constructed || len(value.contents) != 0 {
			return errors.New("invalid DER NULL")
		}
	case asn1.TagOID:
		if value.constructed {
			return errors.New("constructed DER OBJECT IDENTIFIER")
		}
		var oid asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(value.raw, &oid); err != nil || len(rest) != 0 {
			return errors.New("invalid DER OBJECT IDENTIFIER")
		}
	case 13: // RELATIVE-OID
		if value.constructed || !isMinimalBase128(value.contents) {
			return errors.New("invalid DER RELATIVE-OID")
		}
	case asn1.TagSequence, asn1.TagSet:
		if !value.constructed {
			return errors.New("primitive DER SEQUENCE or SET")
		}
	}
	return nil
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
