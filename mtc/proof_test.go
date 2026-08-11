package mtc_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestParseProofPreservesWireOrderAndDuplicates(t *testing.T) {
	want := mtctest.Proof{
		Extensions: []mtctest.ProofExtension{
			{Type: 7, Data: []byte{0x70}},
			{Type: 2, Data: nil},
			{Type: 7, Data: []byte{0x71, 0x72}},
		},
		Start:          8,
		End:            13,
		InclusionProof: []byte{0xaa, 0xbb},
		Signatures: []mtctest.ProofSignature{
			{CosignerID: []byte("bb"), Signature: []byte{2}},
			{CosignerID: nil, Signature: nil},
			{CosignerID: []byte("a"), Signature: []byte{1}},
			{CosignerID: []byte("bb"), Signature: []byte{3}},
		},
	}

	got, err := mtc.ParseProof(mtctest.ProofBytes(want))
	if err != nil {
		t.Fatal(err)
	}
	wantProof := &mtc.Proof{
		Extensions: []mtc.EntryExtension{
			{Type: 7, Data: []byte{0x70}},
			{Type: 2, Data: nil},
			{Type: 7, Data: []byte{0x71, 0x72}},
		},
		Start:          8,
		End:            13,
		InclusionProof: []byte{0xaa, 0xbb},
		Signatures: []mtc.MTCSignature{
			{CosignerID: []byte("bb"), Signature: []byte{2}},
			{CosignerID: nil, Signature: nil},
			{CosignerID: []byte("a"), Signature: []byte{1}},
			{CosignerID: []byte("bb"), Signature: []byte{3}},
		},
	}
	if !reflect.DeepEqual(got, wantProof) {
		t.Fatalf("ParseProof = %#v, want %#v", got, wantProof)
	}
}

func TestParseProofAcceptsZeroLengthVectors(t *testing.T) {
	input := mtctest.ProofBytes(mtctest.Proof{Start: 0, End: 1})
	got, err := mtc.ParseProof(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.Start != 0 || got.End != 1 {
		t.Fatalf("range = [%d,%d)", got.Start, got.End)
	}
	if len(got.Extensions) != 0 || len(got.InclusionProof) != 0 || len(got.Signatures) != 0 {
		t.Fatalf("zero-length vectors were not retained: %#v", got)
	}
}

func TestParseProofReportsTypedTruncation(t *testing.T) {
	prefix := proofThroughInclusion(nil)
	tests := []struct {
		name  string
		input []byte
		field string
	}{
		{"extensions prefix", []byte{0}, "extensions length"},
		{"extensions payload", []byte{0, 1}, "extensions"},
		{"extension type", []byte{0, 1, 0}, "extension type"},
		{"extension data prefix", []byte{0, 3, 0, 1, 0}, "extension data length"},
		{"extension data payload", []byte{0, 5, 0, 1, 0, 2, 0xff}, "extension data"},
		{"start uint48", append([]byte{0, 0}, make([]byte, 5)...), "start"},
		{"end uint48", append(append([]byte{0, 0}, make([]byte, 6)...), make([]byte, 5)...), "end"},
		{"inclusion proof prefix", append(append(append([]byte{0, 0}, make([]byte, 6)...), make([]byte, 6)...), 0), "inclusion_proof length"},
		{"inclusion proof payload", proofThroughInclusion([]byte{0, 2, 0xff}), "inclusion_proof"},
		{"signatures prefix", appendProofBytes(prefix, 0), "signatures length"},
		{"signatures payload", appendProofBytes(prefix, 0, 2, 0), "signatures"},
		{"cosigner ID payload", appendProofBytes(prefix, 0, 2, 2, 0xaa), "cosigner ID"},
		{"signature prefix", appendProofBytes(prefix, 0, 3, 1, 0xaa, 0), "signature length"},
		{"signature payload", appendProofBytes(prefix, 0, 5, 1, 0xaa, 0, 2, 0xbb), "signature"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mtc.ParseProof(tc.input)
			var truncation *mtc.ProofTruncationError
			if !errors.As(err, &truncation) {
				t.Fatalf("error = %T %v, want *mtc.ProofTruncationError", err, err)
			}
			if truncation.Field != tc.field {
				t.Fatalf("truncation field = %q, want %q", truncation.Field, tc.field)
			}
		})
	}
}

func TestParseProofReportsTypedTrailingData(t *testing.T) {
	input := append(mtctest.ProofBytes(mtctest.Proof{Start: 4, End: 8}), 0xff)
	_, err := mtc.ParseProof(input)
	var trailing *mtc.ProofTrailingDataError
	if !errors.As(err, &trailing) {
		t.Fatalf("error = %T %v, want *mtc.ProofTrailingDataError", err, err)
	}
}

func TestCertificateParsesSubscriberProofWithoutRejectingMalformedProof(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tpl := mtctest.ValidSubscriberTemplate()
		want := mtctest.ValidProof()
		tpl.Signature = mtctest.ProofBytes(want)
		got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
		if err != nil {
			t.Fatal(err)
		}
		if got.Proof == nil || got.ProofParseError != nil {
			t.Fatalf("proof/error = %#v/%v", got.Proof, got.ProofParseError)
		}
		if got.Proof.Start != want.Start || got.Proof.End != want.End {
			t.Fatalf("proof range = [%d,%d), want [%d,%d)", got.Proof.Start, got.Proof.End, want.Start, want.End)
		}
		if !bytes.Equal(got.SignatureValue, tpl.Signature) {
			t.Fatal("signature BIT STRING contents were not retained")
		}
	})

	t.Run("malformed remains lintable", func(t *testing.T) {
		tpl := mtctest.ValidSubscriberTemplate()
		tpl.Signature = mtctest.MalformedProofBytes()
		got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
		if err != nil {
			t.Fatalf("envelope parse failed: %v", err)
		}
		var truncation *mtc.ProofTruncationError
		if got.Proof != nil || !errors.As(got.ProofParseError, &truncation) {
			t.Fatalf("proof/error = %#v/%T %v", got.Proof, got.ProofParseError, got.ProofParseError)
		}
	})

	t.Run("CA signature is not a proof", func(t *testing.T) {
		got, err := mtc.Parse(mtctest.Certificate(mtctest.ValidCATemplate()), mtc.InputCertificate)
		if err != nil {
			t.Fatal(err)
		}
		if got.Proof != nil || got.ProofParseError != nil {
			t.Fatalf("CA proof/error = %#v/%v", got.Proof, got.ProofParseError)
		}
	})

	t.Run("TBS has no proof state", func(t *testing.T) {
		got, err := mtc.Parse(mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), mtc.InputTBSCertificate)
		if err != nil {
			t.Fatal(err)
		}
		if got.Proof != nil || got.ProofParseError != nil {
			t.Fatalf("TBS proof/error = %#v/%v", got.Proof, got.ProofParseError)
		}
	})
}

func proofThroughInclusion(inclusionEncoding []byte) []byte {
	input := []byte{0, 0}
	input = append(input, make([]byte, 6)...)
	input = append(input, 0, 0, 0, 0, 0, 1)
	if inclusionEncoding == nil {
		return append(input, 0, 0)
	}
	return append(input, inclusionEncoding...)
}

func appendProofBytes(prefix []byte, suffix ...byte) []byte {
	return append(append([]byte(nil), prefix...), suffix...)
}
