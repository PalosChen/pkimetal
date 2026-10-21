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
		{"primitive EXTERNAL", []byte{0x08, 0x00}},
		{"constructed REAL", []byte{0x29, 0x00}},
		{"non-canonical decimal REAL", []byte{0x09, 0x07, 0x03, '1', '0', '.', 'E', '-', '1'}},
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

func TestParseExactDERValidatesExternalStructure(t *testing.T) {
	valid := [][]byte{
		{0x28, 0x04, 0xa0, 0x02, 0x05, 0x00},
		{0x28, 0x0e, 0x06, 0x02, 0x2a, 0x03, 0x02, 0x01, 0x01, 0x07, 0x01, 'A', 0x81, 0x02, 0xde, 0xad},
		{0x28, 0x02, 0x81, 0x00},
		{0x28, 0x03, 0x82, 0x01, 0x00},
	}
	for _, input := range valid {
		if _, err := parseExactDER(input); err != nil {
			t.Fatalf("valid EXTERNAL %x rejected: %v", input, err)
		}
	}

	invalid := [][]byte{
		{0x28, 0x00},
		{0x28, 0x04, 0x06, 0x02, 0x2a, 0x03},
		{0x28, 0x04, 0x81, 0x00, 0x81, 0x00},
		{0x28, 0x02, 0x05, 0x00},
		{0x28, 0x02, 0xa0, 0x00},
		{0x28, 0x06, 0xa0, 0x04, 0x05, 0x00, 0x05, 0x00},
		{0x28, 0x02, 0x80, 0x00},
		{0x28, 0x02, 0xa1, 0x00},
		{0x28, 0x02, 0xa2, 0x00},
		{0x28, 0x04, 0x82, 0x02, 0x01, 0x01},
		{0x28, 0x08, 0x07, 0x01, 'A', 0x02, 0x01, 0x01, 0x81, 0x00},
	}
	for _, input := range invalid {
		if _, err := parseExactDER(input); err == nil {
			t.Fatalf("malformed EXTERNAL %x accepted", input)
		}
	}
}

func TestParseExactDERValidatesREALCanonicalForm(t *testing.T) {
	valid := [][]byte{
		{0x09, 0x00},
		{0x09, 0x01, 0x40},
		{0x09, 0x01, 0x41},
		{0x09, 0x01, 0x42},
		{0x09, 0x01, 0x43},
		{0x09, 0x03, 0x80, 0x00, 0x01},
		{0x09, 0x03, 0xc0, 0x00, 0x01},
		{0x09, 0x04, 0x81, 0x00, 0x80, 0x01},
		{0x09, 0x05, 0x82, 0x00, 0x80, 0x00, 0x01},
		{0x09, 0x07, 0x83, 0x04, 0x00, 0x80, 0x00, 0x00, 0x01},
		{0x09, 0x07, 0x03, '1', '5', '.', 'E', '-', '1'},
	}
	for _, input := range valid {
		if _, err := parseExactDER(input); err != nil {
			t.Fatalf("valid REAL %x rejected: %v", input, err)
		}
	}

	invalid := [][]byte{
		{0x09, 0x01, 0x80},
		{0x09, 0x02, 0x80, 0x00},
		{0x09, 0x03, 0x80, 0x00, 0x02},
		{0x09, 0x04, 0x80, 0x00, 0x00, 0x01},
		{0x09, 0x03, 0x90, 0x00, 0x01},
		{0x09, 0x03, 0x84, 0x00, 0x01},
		{0x09, 0x04, 0x81, 0x00, 0x01, 0x01},
		{0x09, 0x06, 0x83, 0x03, 0x00, 0x80, 0x00, 0x01},
		{0x09, 0x03, 0x83, 0x04, 0x00},
		{0x09, 0x02, 0x40, 0x00},
		{0x09, 0x02, 0x01, '1'},
		{0x09, 0x07, 0x03, '1', '0', '.', 'E', '-', '1'},
	}
	for _, input := range invalid {
		if _, err := parseExactDER(input); err == nil {
			t.Fatalf("non-canonical REAL %x accepted", input)
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
