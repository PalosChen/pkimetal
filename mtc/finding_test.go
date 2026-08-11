package mtc

import (
	"reflect"
	"strings"
	"testing"
)

func TestRunRulesRecoversPanicsAndContinues(t *testing.T) {
	rules := []Rule{
		{
			Code: "z_panics", Source: "test source", Section: "1",
			Kinds: []ArtifactKind{ArtifactSubscriber}, InputKinds: []InputKind{InputCertificate},
			Evaluate: func(*Artifact) *Finding { panic("boom") },
		},
		{
			Code: "a_normal", Source: "test source", Section: "2",
			Kinds: []ArtifactKind{ArtifactSubscriber}, InputKinds: []InputKind{InputCertificate},
			Evaluate: func(*Artifact) *Finding {
				return &Finding{Field: "subject", Message: "normal evaluator ran", Severity: Error}
			},
		},
	}

	got := runRules(&Artifact{Kind: ArtifactSubscriber, InputKind: InputCertificate}, rules)
	if len(got) != 2 {
		t.Fatalf("findings = %#v", got)
	}
	if got[0].Code != "a_normal" || got[0].Severity != Error {
		t.Fatalf("normal finding = %#v", got[0])
	}
	if got[1].Code != "b_mtc_rule_panic" || got[1].Severity != Bug {
		t.Fatalf("panic finding = %#v", got[1])
	}
	if !strings.Contains(got[1].Message, "z_panics") {
		t.Fatalf("panic message does not identify rule: %q", got[1].Message)
	}
}

func TestRunRulesUsesExplicitApplicability(t *testing.T) {
	called := 0
	rules := []Rule{
		{
			Code: "wrong_kind", Kinds: []ArtifactKind{ArtifactCA}, InputKinds: []InputKind{InputCertificate},
			Evaluate: func(*Artifact) *Finding { called++; return &Finding{Severity: Error} },
		},
		{
			Code: "wrong_input", Kinds: []ArtifactKind{ArtifactSubscriber}, InputKinds: []InputKind{InputTBSCertificate},
			Evaluate: func(*Artifact) *Finding { called++; return &Finding{Severity: Error} },
		},
		{
			Code: "applicable", Source: "source", Section: "section",
			Kinds: []ArtifactKind{ArtifactSubscriber}, InputKinds: []InputKind{InputCertificate},
			Evaluate: func(*Artifact) *Finding { called++; return &Finding{Message: "found", Severity: Warning} },
		},
	}

	got := runRules(&Artifact{Kind: ArtifactSubscriber, InputKind: InputCertificate}, rules)
	if called != 1 || len(got) != 1 {
		t.Fatalf("called/findings = %d/%#v", called, got)
	}
	if got[0].Code != "applicable" || got[0].Source != "source" || got[0].Section != "section" {
		t.Fatalf("rule metadata not applied: %#v", got[0])
	}
}

func TestRunRulesSortsDeterministically(t *testing.T) {
	makeRule := func(code, message string) Rule {
		return Rule{
			Code: code, Source: "source", Section: "section",
			Kinds: []ArtifactKind{ArtifactSubscriber}, InputKinds: []InputKind{InputCertificate},
			Evaluate: func(*Artifact) *Finding { return &Finding{Message: message, Severity: Warning} },
		}
	}
	rules := []Rule{makeRule("z", "last"), makeRule("a", "second"), makeRule("a", "first")}

	got := runRules(&Artifact{Kind: ArtifactSubscriber, InputKind: InputCertificate}, rules)
	want := []string{"a:first", "a:second", "z:last"}
	var order []string
	for _, finding := range got {
		order = append(order, finding.Code+":"+finding.Message)
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestRunRulesHandlesNilArtifactAndNilFinding(t *testing.T) {
	if got := runRules(nil, nil); got != nil {
		t.Fatalf("nil artifact findings = %#v", got)
	}
	called := false
	rules := []Rule{{
		Code: "none", Kinds: []ArtifactKind{ArtifactCA}, InputKinds: []InputKind{InputCertificate},
		Evaluate: func(*Artifact) *Finding { called = true; return nil },
	}}
	if got := runRules(&Artifact{Kind: ArtifactCA, InputKind: InputCertificate}, rules); got != nil || !called {
		t.Fatalf("nil finding result/called = %#v/%t", got, called)
	}
}

func TestRunRulesSortTieBreakers(t *testing.T) {
	findings := []*Finding{
		{Code: "same", Source: "b", Section: "1", Field: "a", Message: "a", Severity: Warning},
		{Code: "same", Source: "a", Section: "2", Field: "a", Message: "a", Severity: Warning},
		{Code: "same", Source: "a", Section: "1", Field: "b", Message: "a", Severity: Warning},
		{Code: "same", Source: "a", Section: "1", Field: "a", Message: "b", Severity: Warning},
		{Code: "same", Source: "a", Section: "1", Field: "a", Message: "a", Severity: Error},
		{Code: "same", Source: "a", Section: "1", Field: "a", Message: "a", Severity: Warning},
	}
	rules := make([]Rule, len(findings))
	for i := range findings {
		finding := findings[i]
		rules[i] = Rule{
			Code: "registry-code", Kinds: []ArtifactKind{ArtifactCA}, InputKinds: []InputKind{InputCertificate},
			Evaluate: func(*Artifact) *Finding { return finding },
		}
	}
	got := runRules(&Artifact{Kind: ArtifactCA, InputKind: InputCertificate}, rules)
	want := []Finding{*findings[5], *findings[4], *findings[3], *findings[2], *findings[1], *findings[0]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tie order = %#v, want %#v", got, want)
	}
}

func TestDraft05RegistersEveryRequiredRule(t *testing.T) {
	want := map[string]bool{
		"e_mtc_signature_algorithm_oid":                       false,
		"e_mtc_signature_algorithm_parameters_present":        false,
		"e_mtc_cert_signature_algorithm_mismatch":             false,
		"e_mtc_signature_value_unused_bits":                   false,
		"e_mtc_ca_subject_not_ca_id":                          false,
		"e_mtc_ca_extension_missing":                          false,
		"e_mtc_ca_extension_not_critical":                     false,
		"f_mtc_ca_extension_malformed":                        false,
		"e_mtc_ca_serial_range_invalid":                       false,
		"e_mtc_ca_key_usage_missing":                          false,
		"e_mtc_ca_key_cert_sign_missing":                      false,
		"e_mtc_ca_basic_constraints_missing":                  false,
		"e_mtc_ca_basic_constraints_not_ca":                   false,
		"w_mtc_ca_ski_not_ca_id":                              false,
		"w_mtc_ca_self_issued":                                false,
		"e_mtc_subscriber_issuer_not_ca_id":                   false,
		"e_mtc_serial_non_positive":                           false,
		"e_mtc_serial_too_large":                              false,
		"e_mtc_serial_log_number_zero":                        false,
		"f_mtc_proof_malformed":                               false,
		"e_mtc_proof_range_invalid":                           false,
		"e_mtc_proof_subtree_invalid":                         false,
		"e_mtc_proof_index_outside_range":                     false,
		"e_mtc_proof_extensions_order":                        false,
		"e_mtc_proof_extensions_duplicate":                    false,
		"e_mtc_proof_cosigner_id_empty":                       false,
		"e_mtc_proof_cosigner_order":                          false,
		"e_mtc_proof_cosigner_duplicate":                      false,
		"e_rfc9925_unsigned_algorithm_mismatch":               false,
		"e_rfc9925_unsigned_parameters_present":               false,
		"e_rfc9925_unsigned_signature_not_empty":              false,
		"e_rfc9925_unsigned_issuer_unique_id_present":         false,
		"w_rfc9925_unsigned_authority_key_identifier_present": false,
		"w_rfc9925_unsigned_issuer_alternative_name_present":  false,
	}
	for _, rule := range draft05Rules {
		seen, ok := want[rule.Code]
		if !ok {
			t.Errorf("unexpected rule %q", rule.Code)
			continue
		}
		if seen {
			t.Errorf("duplicate rule %q", rule.Code)
		}
		want[rule.Code] = true
		if rule.Code == "" || rule.Source == "" || rule.Section == "" || len(rule.Kinds) == 0 || len(rule.InputKinds) == 0 || rule.Evaluate == nil {
			t.Errorf("rule %q has incomplete metadata or applicability: %#v", rule.Code, rule)
		}
	}
	for code, seen := range want {
		if !seen {
			t.Errorf("missing rule %q", code)
		}
	}
}
