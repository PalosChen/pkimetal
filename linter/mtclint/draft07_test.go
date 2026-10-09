package mtclint

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestDraft07ProfilesKeepExplicitRevisionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		tpl     mtctest.Template
		profile linter.ProfileId
	}{
		{mtctest.ValidDraft07CATemplate(), 111}, {mtctest.ValidDraft07SubscriberTemplate(), 112},
	} {
		a, err := mtc.Parse(mtctest.Certificate(tc.tpl), mtc.InputCertificate)
		if err != nil {
			t.Fatal(err)
		}
		if got := handle(t, tc.profile, a); len(got) != 0 {
			t.Fatalf("valid 07: %#v", got)
		}
		legacy := linter.MTC_CA
		current06 := linter.MTC_DRAFT06_CA
		cqrp := linter.CQRP_MTC_CA
		if tc.profile == 112 {
			legacy = linter.MTC_SUBSCRIBER
			current06 = linter.MTC_DRAFT06_SUBSCRIBER
			cqrp = linter.CQRP_MTC_SUBSCRIBER
		}
		assertHasCode(t, handle(t, legacy, a), "e_mtc_profile_revision_mismatch")
		assertHasCode(t, handle(t, current06, a), "e_mtc_profile_revision_mismatch")
		if got := handle(t, cqrp, a); len(got) != 0 {
			t.Fatalf("CQRP base 07: %#v", got)
		}
	}
	for _, tpl := range []mtctest.Template{mtctest.ValidSubscriberTemplate(), mtctest.ValidDraft06SubscriberTemplate()} {
		a, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
		if err != nil {
			t.Fatal(err)
		}
		assertHasCode(t, handle(t, 112, a), "e_mtc_profile_revision_mismatch")
	}
}

func TestDraft07LintChangedRulesAndApplicability(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		ca         bool
		mutate     func(*mtctest.Template)
	}{
		{"proof OID", "e_mtc_signature_algorithm_oid", false, func(x *mtctest.Template) {
			x.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDMTCProof}
			x.OuterSignature = x.TBSSignature
		}},
		{"proof parameters", "e_mtc_signature_algorithm_parameters_present", false, func(x *mtctest.Template) {
			x.TBSSignature.ParametersPresent = true
			x.TBSSignature.Parameters = []byte{5, 0}
		}},
		{"issuer tag", "e_mtc_subscriber_issuer_not_ca_id", false, func(x *mtctest.Template) {
			x.Issuer = mtctest.NameDER(mtctest.NameAttribute{ID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}, Value: "32473.1"})
		}},
		{"CA critical", "e_mtc_ca_extension_not_critical", true, func(x *mtctest.Template) { x.Extensions[0].Critical = false }},
		{"CA schema", "f_mtc_ca_extension_malformed", true, func(x *mtctest.Template) { x.Extensions[0].Value = mtctest.ValidCAExtensionDER() }},
		{"last index", "e_mtc_serial_index_outside_wire_domain", false, func(x *mtctest.Template) { x.Serial.SetUint64(1<<49 - 1) }},
		{"entry size", "e_mtc_entry_too_large", false, func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: asn1.ObjectIdentifier{1, 2, 3}, Value: bytes.Repeat([]byte{0}, 65535)})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidDraft07SubscriberTemplate()
			profile := linter.ProfileId(112)
			if tc.ca {
				tpl = mtctest.ValidDraft07CATemplate()
				profile = 111
			}
			tc.mutate(&tpl)
			for _, kind := range []mtc.InputKind{mtc.InputCertificate, mtc.InputTBSCertificate} {
				der := mtctest.Certificate(tpl)
				if kind == mtc.InputTBSCertificate {
					der = mtctest.TBSCertificate(tpl)
				}
				a, err := mtc.Parse(der, kind)
				if err != nil {
					t.Fatal(err)
				}
				assertHasCode(t, handle(t, profile, a), tc.code)
			}
		})
	}
}

func TestDraft07CosignerIDLimitMetadataAndGrease(t *testing.T) {
	for _, n := range []int{32, 33} {
		tpl := mtctest.ValidDraft07SubscriberTemplate()
		proof := mtctest.ValidProof()
		proof.Signatures = []mtctest.ProofSignature{{CosignerID: append(bytes.Repeat([]byte{0x81}, n-1), 1), Signature: nil}}
		tpl.Signature = mtctest.ProofBytesForRevision(proof, "07")
		a, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
		if err != nil {
			t.Fatal(err)
		}
		got := handle(t, 112, a)
		if n == 32 && len(got) != 0 {
			t.Fatalf("valid GREASE/large component: %#v", got)
		}
		if n == 33 {
			assertHasCode(t, got, "e_mtc_proof_cosigner_id_malformed")
			for _, f := range got {
				if f.Code == "e_mtc_proof_cosigner_id_malformed" && !bytes.Contains([]byte(f.Finding), []byte("draft-ietf-tls-trust-anchor-ids-06")) {
					t.Fatal(f)
				}
			}
		}
	}
}
