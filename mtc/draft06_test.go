package mtc_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestDraft06ProofParserRejectsNoncanonicalCosignerIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  [][]byte
		code string
	}{
		{"duplicate", [][]byte{{1}, {1}}, "e_mtc_proof_cosigner_duplicate"},
		{"nonadjacent duplicate", [][]byte{{1}, {2}, {1}}, "e_mtc_proof_cosigner_duplicate"},
		{"lexicographic disorder", [][]byte{{2}, {1}}, "e_mtc_proof_cosigner_order"},
		{"length first disorder", [][]byte{{0, 0}, {2}}, "e_mtc_proof_cosigner_order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := mtctest.Proof{Start: 0, End: 1}
			for _, id := range tc.ids {
				proof.Signatures = append(proof.Signatures, mtctest.ProofSignature{CosignerID: id, Signature: []byte{7}})
			}
			if _, err := mtc.ParseProofForRevision(mtctest.ProofBytesForRevision(proof, "06"), "06"); err == nil {
				t.Fatal("draft06 parser accepted noncanonical cosigner IDs")
			}
			legacy := mtctest.ProofBytes(proof)
			if _, err := mtc.ParseProof(legacy); err != nil {
				t.Fatalf("legacy default changed: %v", err)
			}
			if _, err := mtc.ParseProofForRevision(legacy, "05"); err != nil {
				t.Fatalf("legacy explicit changed: %v", err)
			}
			tpl := mtctest.ValidDraft06SubscriberTemplate()
			tpl.Signature = mtctest.ProofBytesForRevision(proof, "06")
			artifact, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range mtc.LintDraft06ForKind(artifact, mtc.ArtifactSubscriber) {
				if f.Code == tc.code {
					found = true
				}
			}
			if !found {
				t.Fatalf("specific lint %s lost", tc.code)
			}
		})
	}
}

func TestDraft06ProofParserAcceptsCanonicalCosignerIDs(t *testing.T) {
	proof := mtctest.Proof{Start: 0, End: 1, Signatures: []mtctest.ProofSignature{
		{CosignerID: []byte{2}, Signature: []byte{7}},
		{CosignerID: []byte{3}, Signature: []byte{8}},
		{CosignerID: []byte{0, 0}, Signature: []byte{9}},
	}}
	parsed, err := mtc.ParseProofForRevision(mtctest.ProofBytesForRevision(proof, "06"), "06")
	if err != nil || len(parsed.Signatures) != 3 {
		t.Fatalf("canonical length-first/lexicographic ordering rejected: %v", err)
	}
}

func TestDraft06SignatureVectorBoundaries(t *testing.T) {
	for _, n := range []int{65535, 65536} {
		proof := mtctest.Proof{Start: 0, End: 1, Signatures: []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: bytes.Repeat([]byte{7}, 32763)}, {CosignerID: []byte{2}, Signature: bytes.Repeat([]byte{8}, n-32771)}}}
		encoded := mtctest.ProofBytesForRevision(proof, "06")
		parsed, err := mtc.ParseProofForRevision(encoded, "06")
		if err != nil || len(parsed.Signatures) != 2 {
			t.Fatalf("size %d: %v", n, err)
		}
		if _, err := mtc.ParseProof(encoded); err == nil {
			t.Fatal("legacy accepted draft06")
		}
		for i := 0; i < len(encoded); i += 997 {
			if _, err := mtc.ParseProofForRevision(encoded[:i], "06"); err == nil {
				t.Fatalf("truncation %d", i)
			}
		}
		if _, err := mtc.ParseProofForRevision(append(encoded, 0), "06"); err == nil {
			t.Fatal("trailing accepted")
		}
	}
}

func TestDraft06EntryLengthBoundaryAndApplicability(t *testing.T) {
	for _, n := range []int{65331, 65332} {
		tpl := draft06Subscriber()
		tpl.Extensions = append(tpl.Extensions, mtctest.Extension{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: make([]byte, n)})
		for _, kind := range []mtc.InputKind{mtc.InputCertificate, mtc.InputTBSCertificate} {
			der := mtctest.Certificate(tpl)
			if kind == mtc.InputTBSCertificate {
				der = mtctest.TBSCertificate(tpl)
			}
			a, err := mtc.Parse(der, kind)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range mtc.LintDraft06ForKind(a, mtc.ArtifactSubscriber) {
				if f.Code == "e_mtc_entry_too_large" {
					found = true
				}
			}
			if found != (n == 65332) {
				t.Fatalf("padding %d kind %d: oversized=%v", n, kind, found)
			}
		}
	}
	ca, err := mtc.Parse(mtctest.Certificate(draft06CA()), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range mtc.LintDraft06ForKind(ca, mtc.ArtifactCA) {
		if f.Code == "e_mtc_entry_too_large" {
			t.Fatal("entry check applies to CA")
		}
	}
	unknown, err := mtc.Parse(mtctest.Certificate(mtctest.ValidSubscriberTemplate()), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	unknown.Kind = mtc.ArtifactUnknown
	found := false
	for _, f := range mtc.LintDraft06ForKind(unknown, mtc.ArtifactSubscriber) {
		if f.Code == "e_mtc_profile_artifact_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatal("wrong kind accepted")
	}
}

func TestDraft06MalformedIdentitiesAndRuleApplicability(t *testing.T) {
	for _, value := range [][]byte{{13, 1, 0x80}, {13, 0}, {13, 2, 0x80, 0}, {13, 1, 0x81}, {0x0c, 1, '1'}} {
		name := mtctest.NameDER(mtctest.NameAttribute{ID: mtc.OIDCAIDDraft06, RawValue: value})
		if _, err := mtc.ParseCAIDNameForRevision(name, "06"); err == nil {
			t.Fatalf("invalid relative OID accepted: %x", value)
		}
	}
	tpl := draft06CA()
	tpl.Extensions = append(tpl.Extensions, mtctest.ValidCATemplate().Extensions[0])
	a, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != mtc.ArtifactCA || a.CAExtensionError == nil || a.RevisionError == nil {
		t.Fatal("conflicting CA OIDs lost")
	}
	subscriber := draft06Subscriber()
	subscriber.Signature = append(subscriber.Signature, 0)
	a, err = mtc.Parse(mtctest.TBSCertificate(subscriber), mtc.InputTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range mtc.LintDraft06ForKind(a, mtc.ArtifactSubscriber) {
		if f.Code == "f_mtc_proof_malformed" || f.Code == "e_mtc_proof_subtree_invalid" || f.Code == "e_mtc_ca_extension_missing" {
			t.Fatalf("wrong applicability %#v", f)
		}
	}
	proof := mtctest.ValidProof()
	proof.Signatures = []mtctest.ProofSignature{{CosignerID: []byte{0x80, 0}, Signature: []byte{1}}}
	subscriber.Signature = mtctest.ProofBytesForRevision(proof, "06")
	a, err = mtc.Parse(mtctest.Certificate(subscriber), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range mtc.LintDraft06ForKind(a, mtc.ArtifactSubscriber) {
		if f.Code == "e_mtc_proof_cosigner_id_malformed" {
			found = true
			if f.Source != "draft-ietf-tls-trust-anchor-ids-05" || f.Section != "4" {
				t.Fatal(f)
			}
		}
	}
	if !found {
		t.Fatal("invalid TAI syntax not linted")
	}
	ordinary := mtctest.ValidSubscriberTemplate()
	ordinary.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDMLDSA44}
	ordinary.Issuer = mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "ordinary"})
	a, err = mtc.Parse(mtctest.Certificate(ordinary), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != mtc.ArtifactUnknown || a.Revision != "" {
		t.Fatal("non-MTC classified")
	}
}

func TestDraft06Fixtures(t *testing.T) {
	for _, name := range []string{"draft06-ca.pem", "draft06-standalone.pem", "draft06-landmark.pem", "draft06-subscriber-tbs.pem"} {
		input, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(input)
		if block == nil {
			t.Fatal("missing PEM")
		}
		kind := mtc.InputCertificate
		if block.Type == "TBS CERTIFICATE" {
			kind = mtc.InputTBSCertificate
		}
		a, err := mtc.Parse(block.Bytes, kind)
		if err != nil {
			t.Fatal(err)
		}
		if findings := mtc.LintDraft06ForKind(a, a.Kind); len(findings) != 0 {
			t.Fatalf("%s: %#v", name, findings)
		}
	}
}

func TestDraft06EmptySignatureFraming(t *testing.T) {
	old := make([]byte, 18)
	old[13] = 1
	current := append(append([]byte(nil), old...), 0)
	if _, err := mtc.ParseProofForRevision(current, "06"); err != nil {
		t.Fatal(err)
	}
	if _, err := mtc.ParseProofForRevision(current, "05"); err == nil {
		t.Fatal("legacy parser accepted vector24")
	}
	if _, err := mtc.ParseProofForRevision(old, "06"); err == nil {
		t.Fatal("draft06 parser accepted vector16")
	}
	for _, revision := range []string{"", "08"} {
		if _, err := mtc.ParseProofForRevision(current, revision); err == nil {
			t.Fatal("unsupported revision accepted")
		}
	}
	if _, err := mtc.ParseProofForRevision(make([]byte, 19), "06"); err == nil {
		t.Fatal("empty certificate subtree accepted")
	}
}

func draft06Subscriber() mtctest.Template {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.Issuer = mtctest.NameDER(mtctest.NameAttribute{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 3}, RawValue: []byte{13, 4, 0x81, 0xfd, 0x59, 1}})
	tpl.Signature = append(tpl.Signature[:16:16], append([]byte{0}, tpl.Signature[16:]...)...)
	return tpl
}

func draft06CA() mtctest.Template {
	tpl := mtctest.ValidCATemplate()
	tpl.Subject = draft06Subscriber().Issuer
	// SEQUENCE { ML-DSA-65 AlgorithmIdentifier, INTEGER 2^48, INTEGER 2^48+99 }.
	tpl.Extensions[0] = mtctest.Extension{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 4}, Critical: true, Value: []byte{0x30, 0x1f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x12, 2, 7, 1, 0, 0, 0, 0, 0, 0, 2, 7, 1, 0, 0, 0, 0, 0, 99}}
	return tpl
}

func TestDraft06RevisionRecognition(t *testing.T) {
	for _, tpl := range []mtctest.Template{draft06Subscriber(), draft06CA()} {
		for _, kind := range []mtc.InputKind{mtc.InputCertificate, mtc.InputTBSCertificate} {
			der := mtctest.Certificate(tpl)
			if kind == mtc.InputTBSCertificate {
				der = mtctest.TBSCertificate(tpl)
			}
			a, err := mtc.Parse(der, kind)
			if err != nil {
				t.Fatal(err)
			}
			if a.Revision != "06" {
				t.Fatalf("revision = %q", a.Revision)
			}
			if got := mtc.LintDraft06ForKind(a, a.Kind); len(got) != 0 {
				t.Fatalf("valid findings: %#v", got)
			}
		}
	}
	tpl := draft06CA()
	tpl.Subject = mtctest.ValidCAIDNameDER()
	a, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if a.RevisionError == nil {
		t.Fatal("conflicting OIDs accepted")
	}
	if len(mtc.LintDraft06ForKind(a, mtc.ArtifactCA)) == 0 {
		t.Fatal("conflict not linted")
	}
}

func TestDraft06NameAndExtensionExplicitRevision(t *testing.T) {
	for _, revision := range []string{"05", "", "08"} {
		if _, err := mtc.ParseCAIDNameForRevision(draft06CA().Subject, revision); err == nil {
			t.Fatalf("Name accepted for %q", revision)
		}
		if _, err := mtc.ParseCertificationAuthorityExtensionForRevision(draft06CA().Extensions[0].Value, revision); err == nil {
			t.Fatalf("extension accepted for %q", revision)
		}
	}
	id, err := mtc.ParseCAIDNameForRevision(draft06CA().Subject, "06")
	if err != nil || !bytes.Equal(id, []byte{0x81, 0xfd, 0x59, 1}) {
		t.Fatalf("CA ID: %x %v", id, err)
	}
	params, err := mtc.ParseCertificationAuthorityExtensionForRevision(draft06CA().Extensions[0].Value, "06")
	if err != nil || params.MinSerial.Cmp(new(big.Int).Lsh(big.NewInt(1), 48)) != 0 {
		t.Fatalf("CA params: %#v %v", params, err)
	}
}

func TestDraft06SubtreeWireDomain(t *testing.T) {
	for _, tc := range []struct {
		start, end uint64
		want       bool
	}{{8, 8, true}, {0, 1<<47 | 1, true}, {0, 1<<48 - 1, true}, {1 << 46, 1<<47 | 1, false}, {1 << 46, 1<<48 - 1, false}, {0, 1 << 48, false}, {1 << 48, 1 << 48, false}, {0, ^uint64(0), false}} {
		if got := mtc.ValidSubtree(tc.start, tc.end); got != tc.want {
			t.Fatalf("ValidSubtree(%d,%d)=%v", tc.start, tc.end, got)
		}
	}
}

func TestDraft06ChangedRules(t *testing.T) {
	tests := []struct {
		name, code string
		ca         bool
		mutate     func(*mtctest.Template)
	}{
		{"minimum serial", "e_mtc_ca_serial_range_invalid", true, func(tpl *mtctest.Template) {
			tpl.Extensions[0].Value = mtctest.Draft06CAExtensionDER(mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, new(big.Int).SetUint64(1<<48-1), new(big.Int).SetUint64(1<<48|99))
		}},
		{"critical", "e_mtc_ca_extension_not_critical", true, func(tpl *mtctest.Template) { tpl.Extensions[0].Critical = false }},
		{"duplicate", "f_mtc_ca_extension_malformed", true, func(tpl *mtctest.Template) { tpl.Extensions = append(tpl.Extensions, tpl.Extensions[0]) }},
		{"schema", "f_mtc_ca_extension_malformed", true, func(tpl *mtctest.Template) { tpl.Extensions[0].Value = mtctest.ValidCAExtensionDER() }},
		{"issuer type", "e_mtc_subscriber_issuer_not_ca_id", false, func(tpl *mtctest.Template) {
			tpl.Issuer = mtctest.NameDER(mtctest.NameAttribute{ID: mtc.OIDCAIDDraft06, Value: "32473.1"})
		}},
		{"subtree", "e_mtc_proof_subtree_invalid", false, func(tpl *mtctest.Template) { tpl.Signature[7] = 5 }},
		{"empty proof", "f_mtc_proof_malformed", false, func(tpl *mtctest.Template) { tpl.Signature[13] = 0 }},
		{"last index", "e_mtc_serial_index_outside_wire_domain", false, func(tpl *mtctest.Template) { tpl.Serial.SetUint64(1<<49 - 1) }},
		{"entry length", "e_mtc_entry_too_large", false, func(tpl *mtctest.Template) {
			tpl.Extensions = append(tpl.Extensions, mtctest.Extension{ID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{0}, 65535)})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := draft06Subscriber()
			expected := mtc.ArtifactSubscriber
			if tc.ca {
				tpl = draft06CA()
				expected = mtc.ArtifactCA
			}
			valid, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
			if err != nil {
				t.Fatal(err)
			}
			if got := mtc.LintDraft06ForKind(valid, expected); len(got) != 0 {
				t.Fatalf("positive: %#v", got)
			}
			tc.mutate(&tpl)
			invalid, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range mtc.LintDraft06ForKind(invalid, expected) {
				if f.Code == tc.code {
					found = true
					if f.Source != "draft-ietf-plants-merkle-tree-certs-06" {
						t.Fatal(f)
					}
				}
			}
			if !found {
				t.Fatalf("missing %s in %#v", tc.code, mtc.LintDraft06ForKind(invalid, expected))
			}
			if mtc.LintDraft06ForKind(nil, expected) != nil {
				t.Fatal("nil applicable")
			}
		})
	}
}
