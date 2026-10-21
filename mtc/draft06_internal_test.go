package mtc

import (
	"github.com/pkimetal/pkimetal/internal/mtctest"
	"math/big"
	"testing"
)

func TestDraft06ChangedRuleApplicabilityMatrix(t *testing.T) {
	// Wrong kind and TBS masks must suppress these specific rules, independent of profile mismatch findings.
	cases := []struct {
		code    string
		ca, tbs bool
		mutate  func(*mtctest.Template)
	}{
		{"e_mtc_ca_serial_range_invalid", true, true, func(v *mtctest.Template) {
			v.Extensions[0].Value = mtctest.Draft06CAExtensionDER(mtctest.Algorithm{OID: mtctest.OIDMLDSA65}, big.NewInt(1), new(big.Int).SetUint64(1<<48|99))
		}},
		{"e_mtc_ca_extension_not_critical", true, true, func(v *mtctest.Template) { v.Extensions[0].Critical = false }},
		{"f_mtc_ca_extension_malformed", true, true, func(v *mtctest.Template) { v.Extensions[0].Value = mtctest.ValidCAExtensionDER() }},
		{"e_mtc_ca_subject_not_ca_id", true, true, func(v *mtctest.Template) { v.Subject = mtctest.ValidCAIDNameDER() }},
		{"e_mtc_subscriber_issuer_not_ca_id", false, true, func(v *mtctest.Template) {
			v.Issuer = mtctest.NameDER(mtctest.NameAttribute{ID: OIDCAIDDraft06, Value: "32473.1"})
		}},
		{"e_mtc_proof_subtree_invalid", false, false, func(v *mtctest.Template) { v.Signature[7] = 5 }},
		{"f_mtc_proof_malformed", false, false, func(v *mtctest.Template) { v.Signature[13] = 0 }},
	}
	ordinary := mtctest.ValidSubscriberTemplate()
	ordinary.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDMLDSA65}
	ordinary.OuterSignature = ordinary.TBSSignature
	ordinary.Issuer = mtctest.NameDER(mtctest.NameAttribute{ID: mtctest.OIDCommonName, Value: "ordinary"})
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			for _, input := range []InputKind{InputCertificate, InputTBSCertificate} {
				v := mtctest.ValidDraft06SubscriberTemplate()
				if tc.ca {
					v = mtctest.ValidDraft06CATemplate()
				}
				tc.mutate(&v)
				encode := mtctest.Certificate
				if input == InputTBSCertificate {
					encode = mtctest.TBSCertificate
				}
				a, err := Parse(encode(v), input)
				if err != nil {
					t.Fatal(err)
				}
				var selected []Rule
				for _, rule := range draft06Rules {
					if rule.Code == tc.code {
						selected = append(selected, rule)
					}
				}
				if len(selected) != 1 {
					t.Fatal("missing rule", tc.code)
				}
				want := input == InputCertificate || tc.tbs
				if got := len(runRules(a, selected)) > 0; got != want {
					t.Fatalf("input %v applicable=%v want=%v", input, got, want)
				}
				wrong := *a
				if tc.ca {
					wrong.Kind = ArtifactSubscriber
				} else {
					wrong.Kind = ArtifactCA
				}
				if len(runRules(&wrong, selected)) != 0 {
					t.Fatal("wrong artifact kind applicable")
				}
				nonMTC, err := Parse(encode(ordinary), input)
				if err != nil {
					t.Fatal(err)
				}
				if nonMTC.Kind != ArtifactUnknown || len(runRules(nonMTC, selected)) != 0 {
					t.Fatal("ordinary non-MTC applicable")
				}
			}
		})
	}
}

func TestDraft06EntrySizeCharacterization(t *testing.T) {
	a, err := Parse(mtctest.Certificate(mtctest.ValidDraft06SubscriberTemplate()), InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	size, ok := certificateLogEntrySize(a)
	// 4 framing + 5 version + 24 issuer + 32 validity + 2 subject + 13 algorithm + 34 hash + 73 extensions.
	if !ok || size != 187 {
		t.Fatalf("entry size=%d ok=%v", size, ok)
	}
}
