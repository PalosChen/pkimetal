package mtc_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestParseCertificateWithoutKnownPublicKeyAlgorithm(t *testing.T) {
	der := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	got, err := mtc.Parse(der, mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != mtc.ArtifactSubscriber {
		t.Fatalf("kind = %v", got.Kind)
	}
	if !got.TBSSignature.Algorithm.Equal(mtc.OIDMTCProof) {
		t.Fatal("wrong TBS signature OID")
	}
	if got.TBSSignature.ParametersPresent {
		t.Fatal("MTCProof parameters are present")
	}
	if !got.SubjectPublicKey.Algorithm.Algorithm.Equal(mtctest.OIDMLDSA44) {
		t.Fatal("wrong SPKI OID")
	}
	if !bytes.Equal(got.SignatureValue, mtctest.ValidSubscriberTemplate().Signature) {
		t.Fatal("signature bytes were not retained")
	}
	if got.Proof == nil || got.ProofParseError != nil {
		t.Fatalf("proof/error = %#v/%v", got.Proof, got.ProofParseError)
	}
}

func TestParseTBSCertificateHasNoOuterEnvelope(t *testing.T) {
	der := mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate())
	got, err := mtc.Parse(der, mtc.InputTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if got.OuterSignature != nil {
		t.Fatal("TBS input has an outer signature")
	}
	if len(got.SignatureValue) != 0 || got.SignatureUnused != 0 {
		t.Fatal("TBS input has an outer signature value")
	}
	if got.Proof != nil || got.ProofParseError != nil {
		t.Fatalf("TBS proof/error = %#v/%v", got.Proof, got.ProofParseError)
	}
	if !bytes.Equal(got.Raw, der) || !bytes.Equal(got.RawTBS, der) {
		t.Fatal("TBS raw bytes were not retained")
	}
}

func TestParseRejectsNonCanonicalOrIncompleteDER(t *testing.T) {
	valid := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	tests := []struct {
		name  string
		input []byte
	}{
		{"trailing bytes", append(append([]byte(nil), valid...), 0)},
		{"truncated", valid[:len(valid)-1]},
		{"indefinite length", []byte{0x30, 0x80, 0x00, 0x00}},
		{"non-minimal long length", []byte{0x30, 0x81, 0x00}},
		{"leading zero long length", []byte{0x30, 0x82, 0x00, 0x80}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mtc.Parse(tc.input, mtc.InputCertificate); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestParseValidatesCertificateVersion(t *testing.T) {
	tests := []struct {
		name    string
		version byte
		wantErr bool
	}{
		{"explicit v1 default", 0x00, true},
		{"v2", 0x01, false},
		{"v3", 0x02, false},
		{"future version", 0x03, true},
		{"negative version", 0xff, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			der := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
			version := []byte{0xa0, 0x03, 0x02, 0x01, 0x02}
			if bytes.Count(der, version) != 1 {
				t.Fatal("fixture does not contain exactly one explicit v3 version")
			}
			der = bytes.Replace(der, version, []byte{0xa0, 0x03, 0x02, 0x01, tc.version}, 1)
			_, err := mtc.Parse(der, mtc.InputCertificate)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Parse error = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func TestParseDistinguishesAbsentAndNULLParameters(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.SPKIAlgorithm.ParametersPresent = true
	tpl.SPKIAlgorithm.Parameters = []byte{0x05, 0x00}
	got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if got.TBSSignature.ParametersPresent {
		t.Fatal("absent signature parameters reported present")
	}
	alg := got.SubjectPublicKey.Algorithm
	if !alg.ParametersPresent || alg.Parameters.Tag != asn1.TagNull || !bytes.Equal(alg.Parameters.FullBytes, []byte{0x05, 0x00}) {
		t.Fatalf("NULL parameters not retained: %+v", alg)
	}
	if !bytes.Equal(alg.Raw[len(alg.Raw)-2:], []byte{0x05, 0x00}) {
		t.Fatal("raw AlgorithmIdentifier does not contain NULL")
	}
}

func TestParseRejectsEOCAlgorithmParameters(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.SPKIAlgorithm.ParametersPresent = true
	tpl.SPKIAlgorithm.Parameters = []byte{0x00, 0x00}
	if _, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate); err == nil {
		t.Fatal("Parse accepted EOC AlgorithmIdentifier parameters")
	}
}

func TestParseRetainsLessCommonAlgorithmParameters(t *testing.T) {
	tests := []struct {
		name        string
		parameters  []byte
		tag         int
		constructed bool
	}{
		{"EXTERNAL", []byte{0x28, 0x04, 0xa0, 0x02, 0x05, 0x00}, 8, true},
		{"zero REAL", []byte{0x09, 0x00}, 9, false},
		{"decimal REAL", []byte{0x09, 0x07, 0x03, '1', '5', '.', 'E', '-', '1'}, 9, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidSubscriberTemplate()
			tpl.SPKIAlgorithm.ParametersPresent = true
			tpl.SPKIAlgorithm.Parameters = tc.parameters
			got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
			if err != nil {
				t.Fatal(err)
			}
			parameters := got.SubjectPublicKey.Algorithm.Parameters
			if parameters.Tag != tc.tag || parameters.IsCompound != tc.constructed {
				t.Fatalf("parameters tag/form = %d/%t", parameters.Tag, parameters.IsCompound)
			}
			if !bytes.Equal(parameters.FullBytes, tc.parameters) {
				t.Fatalf("parameters raw = %x, want %x", parameters.FullBytes, tc.parameters)
			}
		})
	}
}

func TestParseRetainsNonByteAlignedSignature(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.Signature = []byte{0xaa, 0xa8}
	tpl.SignatureUnused = 3
	got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if got.SignatureUnused != 3 || !bytes.Equal(got.SignatureValue, tpl.Signature) {
		t.Fatalf("signature = %x/%d", got.SignatureValue, got.SignatureUnused)
	}
}

func TestParseRetainsMismatchedSignatureAlgorithms(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.OuterSignature.OID = mtctest.OIDSHA256
	got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if got.OuterSignature == nil || !got.OuterSignature.Algorithm.Equal(mtctest.OIDSHA256) {
		t.Fatal("outer signature algorithm not retained")
	}
	if !got.TBSSignature.Algorithm.Equal(mtc.OIDMTCProof) {
		t.Fatal("inner signature algorithm changed")
	}
}

func TestParseMalformedCAExtensionRemainsLintable(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	tpl.Extensions[0].Value = []byte{0x30, 0x80, 0x00, 0x00}
	got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != mtc.ArtifactCA {
		t.Fatalf("kind = %v", got.Kind)
	}
	if got.CAParameters != nil || got.CAExtensionError == nil {
		t.Fatalf("CA parameters/error = %+v/%v", got.CAParameters, got.CAExtensionError)
	}
}

func TestParseDuplicateMTCCAExtensionsRemainLintable(t *testing.T) {
	valid := mtctest.ValidCAExtensionDER()
	malformed := []byte{0x30, 0x80, 0x00, 0x00}
	differentValid := mtctest.CAExtensionDER(
		mtctest.Algorithm{OID: mtctest.OIDSHA256},
		mtctest.Algorithm{OID: mtctest.OIDMLDSA65},
		big.NewInt(200),
		big.NewInt(500),
	)
	tests := []struct {
		name   string
		values [][]byte
	}{
		{"valid then malformed", [][]byte{valid, malformed}},
		{"malformed then valid", [][]byte{malformed, valid}},
		{"differing valid duplicates", [][]byte{valid, differentValid}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			tpl.Extensions = nil
			for _, value := range tc.values {
				tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
					ID:       mtctest.OIDMTC_CA,
					Critical: true,
					Value:    value,
				})
			}
			got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != mtc.ArtifactCA {
				t.Fatalf("kind = %v", got.Kind)
			}
			if got.CAParameters != nil {
				t.Fatalf("CAParameters = %+v", got.CAParameters)
			}
			if got.CAExtensionError == nil || !strings.Contains(got.CAExtensionError.Error(), "duplicate") {
				t.Fatalf("CAExtensionError = %v", got.CAExtensionError)
			}
		})
	}
}

func TestParseCertificationAuthorityExtension(t *testing.T) {
	got, err := mtc.ParseCertificationAuthorityExtension(mtctest.ValidCAExtensionDER())
	if err != nil {
		t.Fatal(err)
	}
	if !got.LogHash.Algorithm.Equal(mtctest.OIDSHA256) {
		t.Fatal("wrong logHash")
	}
	if !got.SignatureAlgorithm.Algorithm.Equal(mtctest.OIDMLDSA65) {
		t.Fatal("wrong sigAlg")
	}
	if got.MinSerial.Cmp(big.NewInt(100)) != 0 || got.MaxSerial.Cmp(big.NewInt(999)) != 0 {
		t.Fatalf("serial bounds = %v..%v", got.MinSerial, got.MaxSerial)
	}
}

func TestParseCAIDNameRequiresExactShape(t *testing.T) {
	want := []byte{0x88, 0x22, 0x38, 0x03}
	got, err := mtc.ParseCAIDName(mtctest.ValidCAIDNameDER())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("CA ID = %x, want %x", got, want)
	}

	wrongValue, err := asn1.Marshal("1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		{0x30, 0x00},
		append(append([]byte(nil), mtctest.ValidCAIDNameDER()...), 0),
		nameWithCAIDValue(wrongValue),
	} {
		if _, err := mtc.ParseCAIDName(input); err == nil {
			t.Fatalf("accepted malformed CA-ID Name %x", input)
		}
	}
}

func TestParseClassificationAndUniqueIDs(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.IssuerUniqueID = []byte{0x80}
	tpl.IssuerUniqueIDUnused = 7
	tpl.SubjectUniqueID = []byte{0x40}
	tpl.SubjectUniqueIDUnused = 6
	got, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IssuerUniqueIDPresent || !got.SubjectUniqueIDPresent {
		t.Fatal("unique ID presence was not retained")
	}
	if !bytes.Equal(got.IssuerCAID, []byte{0x88, 0x22, 0x38, 0x03}) {
		t.Fatalf("issuer CA ID = %x", got.IssuerCAID)
	}
}

func TestParseRejectsUnknownInputKind(t *testing.T) {
	if _, err := mtc.Parse(mtctest.Certificate(mtctest.ValidSubscriberTemplate()), mtc.InputKind(0)); err == nil {
		t.Fatal("Parse accepted unknown input kind")
	}
}

func TestCheckedInFixtures(t *testing.T) {
	tests := []struct {
		name string
		kind mtc.InputKind
		want mtc.ArtifactKind
	}{
		{"draft05-ca.pem", mtc.InputCertificate, mtc.ArtifactCA},
		{"draft05-standalone.pem", mtc.InputCertificate, mtc.ArtifactSubscriber},
		{"draft05-landmark.pem", mtc.InputCertificate, mtc.ArtifactSubscriber},
		{"draft05-subscriber-tbs.pem", mtc.InputTBSCertificate, mtc.ArtifactSubscriber},
		{"cqrp-subscriber.pem", mtc.InputCertificate, mtc.ArtifactSubscriber},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contents, err := os.ReadFile(filepath.Join("testdata", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			block, rest := pem.Decode(contents)
			if block == nil || len(bytes.TrimSpace(rest)) != 0 {
				t.Fatal("invalid PEM fixture")
			}
			got, err := mtc.Parse(block.Bytes, tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != tc.want {
				t.Fatalf("kind = %v, want %v", got.Kind, tc.want)
			}
		})
	}
}

func TestGeneratedFixturesAreReproducible(t *testing.T) {
	dir := t.TempDir()
	if err := mtctest.WriteGeneratedFixtures(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"draft05-ca.pem", "draft05-subscriber-tbs.pem", "cqrp-subscriber.pem"} {
		want, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("generated %s differs from checked-in fixture", name)
		}
	}
}

func TestSiblingFixturesMatchWhenAvailable(t *testing.T) {
	for _, name := range []string{"standalone.pem", "landmark.pem"} {
		sibling := filepath.Join("..", "..", "..", "..", "docs", "scripts", name)
		outside, err := os.ReadFile(sibling)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		inside, err := os.ReadFile(filepath.Join("testdata", "draft05-"+name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(inside, outside) {
			t.Fatalf("%s differs from sibling fixture", name)
		}
	}
}

func nameWithCAIDValue(value []byte) []byte {
	oid, err := asn1.Marshal(mtctest.OIDCAID)
	if err != nil {
		panic(err)
	}
	atv := append(append([]byte{0x30, byte(len(oid) + len(value))}, oid...), value...)
	set := append([]byte{0x31, byte(len(atv))}, atv...)
	return append([]byte{0x30, byte(len(set))}, set...)
}
