package mtc

import (
	"github.com/pkimetal/pkimetal/internal/mtctest"
	"testing"
)

func TestDraft07CQRPCannotClassifyGreaseAsStandalone(t *testing.T) {
	for _, signatures := range [][]mtctest.ProofSignature{
		nil, {{CosignerID: []byte{1}, Signature: nil}}, {{CosignerID: []byte{1}}, {CosignerID: []byte{2}}},
	} {
		tpl := mtctest.ValidCQRPSubscriberTemplate()
		identity := mtctest.ValidDraft07SubscriberTemplate()
		tpl.Issuer = identity.Issuer
		tpl.TBSSignature, tpl.OuterSignature = identity.TBSSignature, identity.OuterSignature
		proof := mtctest.ValidProof()
		proof.Signatures = signatures
		tpl.Signature = mtctest.ProofBytesForRevision(proof, "07")
		a := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
		// No trusted subtree or cosigner keys are available locally. Neither
		// one GREASE signature nor two prove standalone status or quorum.
		if got := LintCQRP030ForKind(a, ArtifactSubscriber); len(got) != 0 {
			t.Fatalf("GREASE rejected without trust context: %#v", got)
		}
	}
}
