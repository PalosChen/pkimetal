package mtc

import (
	"bytes"
	"testing"
)

const desiredMaxDERDepth = 64

func TestParseExactDERRejectsInvalidUniversalValues(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"end-of-contents", []byte{0x00, 0x00}},
		{"reserved universal tag", []byte{0x0f, 0x00}},
		{"constructed octet string", []byte{0x24, 0x00}},
		{"constructed UTF-8 string", []byte{0x2c, 0x00}},
		{"malformed UTF-8", []byte{0x0c, 0x01, 0xff}},
		{"invalid numeric string", []byte{0x12, 0x01, 'A'}},
		{"invalid printable string", []byte{0x13, 0x01, '@'}},
		{"invalid IA5 string", []byte{0x16, 0x01, 0x80}},
		{"invalid universal string length", []byte{0x1c, 0x01, 0x00}},
		{"invalid BMP surrogate", []byte{0x1e, 0x02, 0xd8, 0x00}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseExactDER(tc.input); err == nil {
				t.Fatalf("parseExactDER(%x) succeeded", tc.input)
			}
		})
	}
}

func TestParseExactDERValidatesDERTimeSyntax(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"UTC time without seconds", primitiveDER(0x17, []byte("2608111200Z"))},
		{"UTC time with offset", primitiveDER(0x17, []byte("260811120000+0800"))},
		{"generalized time with offset", primitiveDER(0x18, []byte("20260811120000+0800"))},
		{"generalized time with comma fraction", primitiveDER(0x18, []byte("20260811120000,12Z"))},
		{"generalized time with trailing fractional zero", primitiveDER(0x18, []byte("20260811120000.120Z"))},
		{"generalized time with zero fraction", primitiveDER(0x18, []byte("20260811120000.0Z"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseExactDER(tc.input); err == nil {
				t.Fatalf("parseExactDER(%q) succeeded", tc.input[2:])
			}
		})
	}

	for _, input := range [][]byte{
		primitiveDER(0x17, []byte("260811120000Z")),
		primitiveDER(0x18, []byte("20260811120000Z")),
		primitiveDER(0x18, []byte("20260811120000.12Z")),
	} {
		if _, err := parseExactDER(input); err != nil {
			t.Fatalf("parseExactDER(%q): %v", input[2:], err)
		}
	}
}

func TestParseExactDERLimitsConstructedDepth(t *testing.T) {
	if _, err := parseExactDER(nestedSequenceDER(desiredMaxDERDepth)); err != nil {
		t.Fatalf("maximum depth rejected: %v", err)
	}
	if _, err := parseExactDER(nestedSequenceDER(desiredMaxDERDepth + 1)); err == nil {
		t.Fatal("depth above maximum accepted")
	}
}

func nestedSequenceDER(depth int) []byte {
	value := []byte{0x05, 0x00}
	for range depth {
		value = append(append([]byte{0x30}, testDERLength(len(value))...), value...)
	}
	return value
}

func primitiveDER(tag byte, contents []byte) []byte {
	return append(append([]byte{tag}, testDERLength(len(contents))...), contents...)
}

func testDERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	encoded := []byte{byte(length)}
	if length > 255 {
		encoded = []byte{byte(length >> 8), byte(length)}
	}
	return append([]byte{0x80 | byte(len(encoded))}, encoded...)
}

func TestParseExactDERAcceptsStructurallyValidUnknownClasses(t *testing.T) {
	input := []byte{0x60, 0x04, 0x80, 0x02, 0xde, 0xad}
	got, err := parseExactDER(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.raw, input) {
		t.Fatalf("raw = %x", got.raw)
	}
}
