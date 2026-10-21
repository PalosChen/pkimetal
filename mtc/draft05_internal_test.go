package mtc

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestAlgorithmIdentifiersEqualSemanticFallback(t *testing.T) {
	null := asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	integer := asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x01}}
	tests := []struct {
		name        string
		left, right AlgorithmIdentifier
		want        bool
	}{
		{"equal without raw", AlgorithmIdentifier{Algorithm: OIDMTCProof}, AlgorithmIdentifier{Algorithm: OIDMTCProof}, true},
		{"different OID", AlgorithmIdentifier{Algorithm: OIDMTCProof}, AlgorithmIdentifier{Algorithm: oidUnsigned}, false},
		{"different presence", AlgorithmIdentifier{Algorithm: OIDMTCProof}, AlgorithmIdentifier{Algorithm: OIDMTCProof, ParametersPresent: true, Parameters: null}, false},
		{"equal parameters", AlgorithmIdentifier{Algorithm: OIDMTCProof, ParametersPresent: true, Parameters: null}, AlgorithmIdentifier{Algorithm: OIDMTCProof, ParametersPresent: true, Parameters: null}, true},
		{"different parameters", AlgorithmIdentifier{Algorithm: OIDMTCProof, ParametersPresent: true, Parameters: null}, AlgorithmIdentifier{Algorithm: OIDMTCProof, ParametersPresent: true, Parameters: integer}, false},
		{"equal raw", AlgorithmIdentifier{Raw: []byte{1}}, AlgorithmIdentifier{Raw: []byte{1}}, true},
		{"different raw", AlgorithmIdentifier{Raw: []byte{1}}, AlgorithmIdentifier{Raw: []byte{2}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := algorithmIdentifiersEqual(tc.left, tc.right); got != tc.want {
				t.Fatalf("algorithmIdentifiersEqual = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestBasicConstraintsCAStrictDecoding(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"CA without path length", []byte{0x30, 0x03, 0x01, 0x01, 0xff}, true},
		{"CA with path length", []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03}, true},
		{"negative path length", []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0xff}, false},
		{"wrong path length tag", []byte{0x30, 0x05, 0x01, 0x01, 0xff, 0x05, 0x00}, false},
		{"trailing field", []byte{0x30, 0x08, 0x01, 0x01, 0xff, 0x02, 0x01, 0x03, 0x05, 0x00}, false},
		{"explicit false", []byte{0x30, 0x03, 0x01, 0x01, 0x00}, false},
		{"not a sequence", []byte{0x05, 0x00}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := basicConstraintsCA(tc.input); got != tc.want {
				t.Fatalf("basicConstraintsCA = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestSubjectKeyIdentifierMatchingRejectsMissingOrMalformedValues(t *testing.T) {
	caID := []byte{1, 2, 3}
	for _, tc := range []struct {
		name      string
		input, id []byte
		want      bool
	}{
		{"match", []byte{0x04, 0x03, 1, 2, 3}, caID, true},
		{"different", []byte{0x04, 0x01, 1}, caID, false},
		{"missing CA ID", []byte{0x04, 0x00}, nil, false},
		{"wrong type", []byte{0x05, 0x00}, caID, false},
		{"malformed", []byte{0x04, 0x02, 1}, caID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := subjectKeyIdentifierMatches(tc.input, tc.id); got != tc.want {
				t.Fatalf("subjectKeyIdentifierMatches = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCompareCosignerIDs(t *testing.T) {
	for _, tc := range []struct {
		left, right []byte
		want        int
	}{
		{[]byte("a"), []byte("aa"), -1},
		{[]byte("aa"), []byte("b"), 1},
		{[]byte("a"), []byte("b"), -1},
		{[]byte("a"), []byte("a"), 0},
	} {
		if got := compareCosignerIDs(tc.left, tc.right); got != tc.want {
			t.Fatalf("compareCosignerIDs(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestCertificationAuthorityExtensionRejectsMalformedFields(t *testing.T) {
	algorithm := testDER(0x30, mustASN1Marshal(t, OIDMTCProof))
	integer := mustASN1Marshal(t, 1)
	tests := []struct {
		name  string
		input []byte
	}{
		{"wrong outer type", []byte{0x05, 0x00}},
		{"missing log hash", testDER(0x30)},
		{"malformed log hash", testDER(0x30, []byte{0x05, 0x00})},
		{"missing signature algorithm", testDER(0x30, algorithm)},
		{"malformed signature algorithm", testDER(0x30, algorithm, []byte{0x05, 0x00})},
		{"missing minimum serial", testDER(0x30, algorithm, algorithm)},
		{"malformed minimum serial", testDER(0x30, algorithm, algorithm, []byte{0x05, 0x00})},
		{"missing maximum serial", testDER(0x30, algorithm, algorithm, integer)},
		{"malformed maximum serial", testDER(0x30, algorithm, algorithm, integer, []byte{0x05, 0x00})},
		{"trailing field", testDER(0x30, algorithm, algorithm, integer, integer, []byte{0x05, 0x00})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCertificationAuthorityExtension(tc.input); err == nil {
				t.Fatalf("accepted malformed extension %x", tc.input)
			}
		})
	}
}

func TestCAIDNameRejectsMalformedComponents(t *testing.T) {
	oid := mustASN1Marshal(t, OIDCAID)
	caID := testDER(0x0c, []byte("42"))
	atv := testDER(0x30, oid, caID)
	rdn := testDER(0x31, atv)
	tests := []struct {
		name  string
		input []byte
	}{
		{"wrong outer type", []byte{0x05, 0x00}},
		{"RDN wrong type", testDER(0x30, []byte{0x05, 0x00})},
		{"multiple RDNs", testDER(0x30, rdn, rdn)},
		{"missing attribute", testDER(0x30, testDER(0x31))},
		{"attribute wrong type", testDER(0x30, testDER(0x31, []byte{0x05, 0x00}))},
		{"multiple attributes", testDER(0x30, testDER(0x31, atv, atv))},
		{"missing attribute OID", testDER(0x30, testDER(0x31, testDER(0x30)))},
		{"attribute OID wrong type", testDER(0x30, testDER(0x31, testDER(0x30, []byte{0x05, 0x00})))},
		{"missing CA ID value", testDER(0x30, testDER(0x31, testDER(0x30, oid)))},
		{"CA ID value wrong type", testDER(0x30, testDER(0x31, testDER(0x30, oid, []byte{0x05, 0x00})))},
		{"CA ID value RELATIVE-OID", testDER(0x30, testDER(0x31, testDER(0x30, oid, testDER(0x0d, []byte{0x2a}))))},
		{"trailing attribute field", testDER(0x30, testDER(0x31, testDER(0x30, oid, caID, []byte{0x05, 0x00})))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCAIDName(tc.input); err == nil {
				t.Fatalf("accepted malformed CA-ID Name %x", tc.input)
			}
		})
	}
}

func testDER(tag byte, values ...[]byte) []byte {
	contents := bytes.Join(values, nil)
	if len(contents) >= 128 {
		panic("testDER only supports short lengths")
	}
	return append([]byte{tag, byte(len(contents))}, contents...)
}

func mustASN1Marshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
