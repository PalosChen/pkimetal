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
	if got[1].Field != "" || got[1].Source != "test source" || got[1].Section != "1" {
		t.Fatalf("panic finding metadata = %#v", got[1])
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
	want := make(map[string]findingExpectation)
	for id, expectation := range draft05Expectations {
		if previous, ok := want[expectation.Code]; ok {
			if previous.Source != expectation.Source || previous.Section != expectation.Section || previous.Severity != expectation.Severity {
				t.Fatalf("expectation %q conflicts with another variant for %q", id, expectation.Code)
			}
			continue
		}
		want[expectation.Code] = expectation
	}
	seen := make(map[string]bool, len(want))
	for _, rule := range draft05Rules {
		expectation, ok := want[rule.Code]
		if !ok {
			t.Errorf("unexpected rule %q", rule.Code)
			continue
		}
		if seen[rule.Code] {
			t.Errorf("duplicate rule %q", rule.Code)
		}
		seen[rule.Code] = true
		if rule.Source != expectation.Source || rule.Section != expectation.Section {
			t.Errorf("rule %q metadata = %q/%q, want %q/%q", rule.Code, rule.Source, rule.Section, expectation.Source, expectation.Section)
		}
		if rule.Code == "" || rule.Source == "" || rule.Section == "" || len(rule.Kinds) == 0 || len(rule.InputKinds) == 0 || rule.Evaluate == nil {
			t.Errorf("rule %q has incomplete metadata or applicability: %#v", rule.Code, rule)
		}
	}
	for code := range want {
		if !seen[code] {
			t.Errorf("missing rule %q", code)
		}
	}
}
