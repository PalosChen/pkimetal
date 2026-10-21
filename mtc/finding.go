package mtc

import (
	"fmt"
	"sort"
)

type Severity uint8

const (
	Warning Severity = iota + 1
	Error
	Bug
	Fatal
)

type Finding struct {
	Code     string
	Field    string
	Message  string
	Source   string
	Section  string
	Severity Severity
}

type Rule struct {
	Code       string
	Source     string
	Section    string
	Kinds      []ArtifactKind
	InputKinds []InputKind
	Evaluate   func(*Artifact) *Finding
}

func runRules(artifact *Artifact, rules []Rule) []Finding {
	if artifact == nil {
		return nil
	}

	var findings []Finding
	for _, rule := range rules {
		if !containsArtifactKind(rule.Kinds, artifact.Kind) || !containsInputKind(rule.InputKinds, artifact.InputKind) {
			continue
		}
		finding := evaluateRule(artifact, rule)
		if finding == nil {
			continue
		}
		if finding.Code == "" {
			finding.Code = rule.Code
		}
		if finding.Source == "" {
			finding.Source = rule.Source
		}
		if finding.Section == "" {
			finding.Section = rule.Section
		}
		findings = append(findings, *finding)
	}

	sortFindings(findings)
	return findings
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Section != right.Section {
			return left.Section < right.Section
		}
		if left.Field != right.Field {
			return left.Field < right.Field
		}
		if left.Message != right.Message {
			return left.Message < right.Message
		}
		return left.Severity < right.Severity
	})
}

func evaluateRule(artifact *Artifact, rule Rule) (finding *Finding) {
	defer func() {
		if recovered := recover(); recovered != nil {
			finding = &Finding{
				Code:     "b_mtc_rule_panic",
				Message:  fmt.Sprintf("rule %s panicked: %v", rule.Code, recovered),
				Source:   rule.Source,
				Section:  rule.Section,
				Severity: Bug,
			}
		}
	}()
	finding = rule.Evaluate(artifact)
	if finding == nil {
		return nil
	}
	copy := *finding
	return &copy
}

func containsArtifactKind(kinds []ArtifactKind, want ArtifactKind) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}

func containsInputKind(kinds []InputKind, want InputKind) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}
