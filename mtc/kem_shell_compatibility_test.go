package mtc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

// Optional cross-repository check of public artifacts emitted by real CA issuance tests.
func TestExperimentalKEMCAShellCompatibility(t *testing.T) {
	directory := os.Getenv("KEM_CA_CERTIFICATES_DIR")
	if directory == "" {
		t.Skip("select public CA KEM shell artifacts for cross-repository validation")
	}
	for _, revision := range []string{"05", "06"} {
		for _, parameterSet := range []string{"ml-kem-512", "ml-kem-768", "ml-kem-1024"} {
			for _, profile := range []string{"mtc-7d", "mtc-47d"} {
				t.Run("draft"+revision+"/"+parameterSet+"-"+profile, func(t *testing.T) {
					der, err := os.ReadFile(filepath.Join(directory, parameterSet+"-"+profile+".der"))
					if err != nil {
						t.Fatal(err)
					}
					artifact, err := Parse(der, InputCertificate)
					if err != nil {
						t.Fatal(err)
					}
					// The shell has a random X.509 serial and no final proof. Select the
					// existing revision fixture explicitly, retaining real CA key/profile
					// bytes. For 06, the fixture supplies its RELATIVE-OID issuer identity;
					// this does not establish issuance from a real 06 CA generation.
					// The proof is a syntax fixture, not real inclusion/quorum evidence.
					shell := artifact
					template := mtctest.ValidSubscriberTemplate()
					template.Issuer = shell.IssuerRaw
					if revision == "06" {
						template = mtctest.ValidDraft06SubscriberTemplate()
					}
					template.Subject = shell.SubjectRaw
					template.NotBefore = shell.NotBefore
					template.NotAfter = shell.NotAfter
					template.SPKIAlgorithm = mtctest.Algorithm{OID: shell.SubjectPublicKey.Algorithm.Algorithm,
						ParametersPresent: shell.SubjectPublicKey.Algorithm.ParametersPresent,
						Parameters:        shell.SubjectPublicKey.Algorithm.Parameters.FullBytes}
					template.SubjectPublicKey = shell.SubjectPublicKey.SubjectPublicKey
					template.SubjectPublicKeyUnused = shell.SubjectPublicKey.UnusedBits
					template.Extensions = nil
					for _, extension := range shell.Extensions {
						template.Extensions = append(template.Extensions, mtctest.Extension{
							ID: extension.ID, Critical: extension.Critical, Value: extension.Value})
					}
					artifact, err = Parse(mtctest.Certificate(template), InputCertificate)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(artifact.SubjectPublicKey.Raw, shell.SubjectPublicKey.Raw) {
						t.Fatal("fixture changed actual CA public key encoding")
					}
					if len(artifact.Extensions) != len(shell.Extensions) {
						t.Fatal("fixture changed actual CA certificate extensions")
					}
					for index, extension := range artifact.Extensions {
						if !bytes.Equal(extension.Raw, shell.Extensions[index].Raw) {
							t.Fatal("fixture changed actual CA extension encoding")
						}
					}
					if artifact.Revision != revision || artifact.Kind != ArtifactSubscriber {
						t.Fatalf("final fixture identity = %s/%d", artifact.Revision, artifact.Kind)
					}
					if _, err := ParseProofForRevision(artifact.SignatureValue, revision); err != nil {
						t.Fatalf("explicit draft%s proof syntax: %v", revision, err)
					}
					var findings []Finding
					switch revision {
					case "05":
						findings = LintDraft05ForKind(artifact, ArtifactSubscriber)
					case "06":
						findings = LintDraft06ForKind(artifact, ArtifactSubscriber)
					}
					findings = append(findings, LintRFC5280SubscriberForKind(artifact, ArtifactSubscriber)...)
					for _, finding := range findings {
						if finding.Severity == Error || finding.Severity == Fatal {
							t.Errorf("native lint rejected: %s: %s", finding.Code, finding.Message)
						}
					}
					rejectedKey := false
					for _, finding := range LintCQRP030ForKind(artifact, ArtifactSubscriber) {
						if finding.Code == "e_cqrp_subscriber_mldsa_encoding" && finding.Severity == Error {
							rejectedKey = true
						}
					}
					if !rejectedKey {
						t.Fatal("CQRP accepted an experimental ML-KEM subscriber key")
					}
				})
			}
		}
	}
}
