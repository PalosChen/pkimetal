package mtc_test

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestDraft07DerivedLogIDLengthIncludesZeroAndSerialLogNumber(t *testing.T) {
	for _, tc := range []struct {
		caBytes, logNumber int
		invalid            bool
	}{
		{30, 127, false}, {31, 1, true}, {30, 128, true}, {29, 128, false}, {32, 1, true},
	} {
		tpl := mtctest.ValidDraft07SubscriberTemplate()
		tpl.Issuer = mtctest.NameDER(mtctest.NameAttribute{ID: mtc.OIDCAIDDraft07,
			RawValue: append([]byte{13, byte(tc.caBytes)}, bytes.Repeat([]byte{1}, tc.caBytes)...)})
		tpl.Serial = new(big.Int).Lsh(big.NewInt(int64(tc.logNumber)), 48)
		a, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range mtc.LintDraft07ForKind(a, mtc.ArtifactSubscriber) {
			if f.Code == "e_mtc_log_id_too_long" {
				found = true
			}
		}
		if found != tc.invalid {
			t.Fatalf("CA bytes=%d N=%d invalid=%v findings=%v", tc.caBytes, tc.logNumber, tc.invalid, mtc.LintDraft07ForKind(a, mtc.ArtifactSubscriber))
		}
	}
}

func TestDraft07RecognitionPreservesLegacyArtifacts(t *testing.T) {
	for _, tc := range []struct {
		revision       string
		ca, subscriber mtctest.Template
	}{
		{"05", mtctest.ValidCATemplate(), mtctest.ValidSubscriberTemplate()},
		{"06", mtctest.ValidDraft06CATemplate(), mtctest.ValidDraft06SubscriberTemplate()},
		{"07", mtctest.ValidDraft07CATemplate(), mtctest.ValidDraft07SubscriberTemplate()},
	} {
		for _, tpl := range []mtctest.Template{tc.ca, tc.subscriber} {
			for _, kind := range []mtc.InputKind{mtc.InputCertificate, mtc.InputTBSCertificate} {
				der := mtctest.Certificate(tpl)
				if kind == mtc.InputTBSCertificate {
					der = mtctest.TBSCertificate(tpl)
				}
				original := bytes.Clone(der)
				a, err := mtc.Parse(der, kind)
				if err != nil {
					t.Fatal(err)
				}
				if a.Revision != tc.revision || a.Kind == mtc.ArtifactUnknown || a.RevisionError != nil {
					t.Fatalf("%s: kind=%v revision=%q error=%v", tc.revision, a.Kind, a.Revision, a.RevisionError)
				}
				if !bytes.Equal(der, original) {
					t.Fatal("input rewritten")
				}
				if kind == mtc.InputCertificate && a.Kind == mtc.ArtifactSubscriber && (a.Proof == nil || a.ProofParseError != nil) {
					t.Fatalf("proof: %v", a.ProofParseError)
				}
			}
		}
	}
}

func TestDraft07ProofFramingAndCanonicalOrder(t *testing.T) {
	proof := mtctest.ValidProof()
	proof.Signatures = []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: []byte{0xff}}}
	encoded := mtctest.ProofBytesForRevision(proof, "07")
	if _, err := mtc.ParseProofForRevision(encoded, "07"); err != nil {
		t.Fatal(err)
	}
	if _, err := mtc.ParseProofForRevision(mtctest.ProofBytes(proof), "07"); err == nil {
		t.Fatal("vector16 accepted")
	}
	for i := range encoded {
		if _, err := mtc.ParseProofForRevision(encoded[:i], "07"); err == nil {
			t.Fatalf("truncation %d accepted", i)
		}
	}
	if _, err := mtc.ParseProofForRevision(append(bytes.Clone(encoded), 0), "07"); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	for _, ids := range [][][]byte{{{2}, {1}}, {{1}, {1}}} {
		proof.Signatures = []mtctest.ProofSignature{{CosignerID: ids[0]}, {CosignerID: ids[1]}}
		if _, err := mtc.ParseProofForRevision(mtctest.ProofBytesForRevision(proof, "07"), "07"); err == nil {
			t.Fatal("duplicate/unordered accepted")
		}
	}
	proof.Start = proof.End
	proof.Signatures = nil
	if _, err := mtc.ParseProofForRevision(mtctest.ProofBytesForRevision(proof, "07"), "07"); err == nil {
		t.Fatal("empty subtree accepted")
	}
}

func TestDraft07CAID32ByteBoundaryAndLargeComponents(t *testing.T) {
	for _, n := range []int{32, 33} {
		// One base-128 component far above uint64. Preserve exact bytes.
		id := append(bytes.Repeat([]byte{0x81}, n-1), 0x01)
		name := mtctest.NameDER(mtctest.NameAttribute{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}, RawValue: append([]byte{13, byte(n)}, id...)})
		got, err := mtc.ParseCAIDNameForRevision(name, "07")
		if n == 32 && (err != nil || !bytes.Equal(got, id)) {
			t.Fatalf("large ID changed: %x %v", got, err)
		}
		if n == 33 && err == nil {
			t.Fatal("33-byte ID accepted")
		}
		name = mtctest.NameDER(mtctest.NameAttribute{ID: mtc.OIDCAIDDraft06, RawValue: append([]byte{13, byte(n)}, id...)})
		if got, err = mtc.ParseCAIDNameForRevision(name, "06"); err != nil || !bytes.Equal(got, id) {
			t.Fatalf("legacy ID changed: %x %v", got, err)
		}
	}
}

func TestDraft07ProofRejectsOversizedCosignerID(t *testing.T) {
	proof := mtctest.ValidProof()
	proof.Signatures = []mtctest.ProofSignature{{CosignerID: bytes.Repeat([]byte{1}, 33)}}
	if _, err := mtc.ParseProofForRevision(mtctest.ProofBytesForRevision(proof, "07"), "07"); err == nil {
		t.Fatal("33-byte cosigner ID accepted by 07 parser")
	}
	if _, err := mtc.ParseProofForRevision(mtctest.ProofBytesForRevision(proof, "06"), "06"); err != nil {
		t.Fatalf("historical 06 proof rejected: %v", err)
	}
}
