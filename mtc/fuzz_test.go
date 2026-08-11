package mtc_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/mtc"
)

func FuzzParseMTC(f *testing.F) {
	f.Add(mtctest.Certificate(mtctest.ValidSubscriberTemplate()), uint8(mtc.InputCertificate))
	f.Add(mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), uint8(mtc.InputTBSCertificate))
	f.Add([]byte{0x30, 0x80}, uint8(mtc.InputCertificate))
	f.Add(nestedSequence(65), uint8(mtc.InputTBSCertificate))

	f.Fuzz(func(t *testing.T, input []byte, rawKind uint8) {
		kind := mtc.InputKind(rawKind%2 + 1)
		first, firstErr := mtc.Parse(input, kind)
		second, secondErr := mtc.Parse(bytes.Clone(input), kind)
		assertSameParseError(t, firstErr, secondErr)
		if (first == nil) != (second == nil) {
			t.Fatal("parse result changed after copying input")
		}
		if first == nil {
			return
		}
		if first.InputKind != second.InputKind || first.Kind != second.Kind {
			t.Fatalf("parse classification changed after copying input: (%v, %v) != (%v, %v)", first.InputKind, first.Kind, second.InputKind, second.Kind)
		}
		if !reflect.DeepEqual(mtc.LintDraft05(first), mtc.LintDraft05(second)) {
			t.Fatal("draft-05 findings changed after copying input")
		}
		if !reflect.DeepEqual(mtc.LintCQRP020(first), mtc.LintCQRP020(second)) {
			t.Fatal("CQRP findings changed after copying input")
		}
	})
}

func FuzzParseProof(f *testing.F) {
	f.Add(mtctest.ProofBytes(mtctest.ValidProof()))
	f.Add(mtctest.MalformedProofBytes())
	f.Add(mtctest.ProofBytes(mtctest.Proof{
		Extensions:     []mtctest.ProofExtension{{Type: 1, Data: bytes.Repeat([]byte{0x11}, 65531)}},
		Start:          0,
		End:            1,
		InclusionProof: bytes.Repeat([]byte{0x22}, 65535),
		Signatures: []mtctest.ProofSignature{{
			Signature: bytes.Repeat([]byte{0x33}, 65532),
		}},
	}))

	f.Fuzz(func(t *testing.T, input []byte) {
		first, firstErr := mtc.ParseProof(input)
		second, secondErr := mtc.ParseProof(bytes.Clone(input))
		assertSameParseError(t, firstErr, secondErr)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("proof parse result changed after copying input")
		}
		if first != nil {
			assertProofBoundedByInput(t, first, len(input))
		}
	})
}

func FuzzParseCAExtension(f *testing.F) {
	f.Add(mtctest.ValidCAExtensionDER())
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add(nestedSequence(65))

	f.Fuzz(func(t *testing.T, input []byte) {
		first, firstErr := mtc.ParseCertificationAuthorityExtension(input)
		second, secondErr := mtc.ParseCertificationAuthorityExtension(bytes.Clone(input))
		assertSameParseError(t, firstErr, secondErr)
		if !reflect.DeepEqual(first, second) {
			t.Fatal("CA extension parse result changed after copying input")
		}
	})
}

func FuzzParseCAID(f *testing.F) {
	f.Add(mtctest.ValidCAIDNameDER())
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add(nestedSequence(65))

	f.Fuzz(func(t *testing.T, input []byte) {
		first, firstErr := mtc.ParseCAIDName(input)
		second, secondErr := mtc.ParseCAIDName(bytes.Clone(input))
		assertSameParseError(t, firstErr, secondErr)
		if !bytes.Equal(first, second) {
			t.Fatal("CA-ID parse result changed after copying input")
		}
		if len(first) > len(input) {
			t.Fatalf("decoded CA-ID length %d exceeds input length %d", len(first), len(input))
		}
	})
}

func assertSameParseError(t *testing.T, first, second error) {
	t.Helper()
	if (first == nil) != (second == nil) {
		t.Fatalf("parse error presence changed after copying input: %v != %v", first, second)
	}
	if first != nil && first.Error() != second.Error() {
		t.Fatalf("parse error changed after copying input: %q != %q", first, second)
	}
}

func assertProofBoundedByInput(t *testing.T, proof *mtc.Proof, inputLength int) {
	t.Helper()
	if len(proof.Extensions) > inputLength/4 {
		t.Fatalf("decoded %d extensions from %d input bytes", len(proof.Extensions), inputLength)
	}
	if len(proof.Signatures) > inputLength/3 {
		t.Fatalf("decoded %d signatures from %d input bytes", len(proof.Signatures), inputLength)
	}
	if len(proof.InclusionProof) > 65535 {
		t.Fatalf("inclusion proof exceeds uint16 vector bound: %d", len(proof.InclusionProof))
	}
	retainedBytes := len(proof.InclusionProof)
	for _, extension := range proof.Extensions {
		if len(extension.Data) > 65535 {
			t.Fatalf("extension data exceeds uint16 vector bound: %d", len(extension.Data))
		}
		retainedBytes += len(extension.Data)
	}
	for _, signature := range proof.Signatures {
		if len(signature.CosignerID) > 255 {
			t.Fatalf("cosigner ID exceeds uint8 vector bound: %d", len(signature.CosignerID))
		}
		if len(signature.Signature) > 65535 {
			t.Fatalf("signature exceeds uint16 vector bound: %d", len(signature.Signature))
		}
		retainedBytes += len(signature.CosignerID) + len(signature.Signature)
	}
	if retainedBytes > inputLength {
		t.Fatalf("parser retained %d payload bytes from %d input bytes", retainedBytes, inputLength)
	}
}

func nestedSequence(depth int) []byte {
	value := []byte{0x05, 0x00}
	for range depth {
		value = append(append([]byte{0x30}, encodedDERLength(len(value))...), value...)
	}
	return value
}

func encodedDERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	encoded := []byte{byte(length)}
	if length > 255 {
		encoded = []byte{byte(length >> 8), byte(length)}
	}
	return append([]byte{0x80 | byte(len(encoded))}, encoded...)
}
