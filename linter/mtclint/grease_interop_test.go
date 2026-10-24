package mtclint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestDraft07GreaseSharedCertificateFixtures(t *testing.T) {
	// Identical public fixture used by ACME HTTP downloads, the demo and the CA verifier.
	data, err := os.ReadFile("../../mtc/testdata/draft07-grease.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "ce8a3bce563ebc6ee3ef13a4e91e849e7e20411798a7d2f059c0c0fe30ebdb9a" {
		t.Fatal("shared GREASE fixture changed; update all consumers together")
	}
	var fixture map[string]string
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"standalone", "landmark"} {
		t.Run(variant, func(t *testing.T) {
			block, rest := pem.Decode([]byte(fixture[variant+"Pem"]))
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				t.Fatal("invalid certificate fixture")
			}
			artifact, err := mtc.Parse(block.Bytes, mtc.InputCertificate)
			if err != nil {
				t.Fatal(err)
			}
			if artifact.Revision != "07" || artifact.ProofParseError != nil || artifact.Proof == nil {
				t.Fatalf("draft-07 proof rejected: %+v", artifact)
			}
			wantCount := 4
			if variant == "landmark" {
				wantCount = 2
			}
			if len(artifact.Proof.Signatures) != wantCount {
				t.Fatalf("lost signature bytes: got %d, want %d", len(artifact.Proof.Signatures), wantCount)
			}
			// MTC-07 §§6.2,6.4.4: real ML-DSA signatures and arbitrary/empty GREASE
			// are accepted structurally. A local lint result does not prove quorum.
			if findings := handle(t, linter.MTC_DRAFT07_SUBSCRIBER, artifact); len(findings) != 0 {
				t.Fatalf("native lint rejected shared GREASE certificate: %#v", findings)
			}
		})
	}
}
