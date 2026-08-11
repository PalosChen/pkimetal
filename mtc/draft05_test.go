package mtc

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"go.yaml.in/yaml/v3"
)

type findingExpectation struct {
	Code     string
	Severity Severity
	Field    string
	Source   string
	Section  string
}

var draft05Expectations = map[string]findingExpectation{
	"signature_algorithm_oid_inner":                       {"e_mtc_signature_algorithm_oid", Error, "tbsCertificate.signature", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"signature_algorithm_oid_outer":                       {"e_mtc_signature_algorithm_oid", Error, "signatureAlgorithm", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"signature_algorithm_parameters_present_inner":        {"e_mtc_signature_algorithm_parameters_present", Error, "tbsCertificate.signature.parameters", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"signature_algorithm_parameters_present_outer":        {"e_mtc_signature_algorithm_parameters_present", Error, "signatureAlgorithm.parameters", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_cert_signature_algorithm_mismatch":             {"e_mtc_cert_signature_algorithm_mismatch", Error, "signatureAlgorithm", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_signature_value_unused_bits":                   {"e_mtc_signature_value_unused_bits", Error, "signatureValue", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_ca_subject_not_ca_id":                          {"e_mtc_ca_subject_not_ca_id", Error, "tbsCertificate.subject", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_extension_missing":                          {"e_mtc_ca_extension_missing", Error, "tbsCertificate.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_extension_not_critical":                     {"e_mtc_ca_extension_not_critical", Error, "tbsCertificate.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"f_mtc_ca_extension_malformed":                        {"f_mtc_ca_extension_malformed", Fatal, "tbsCertificate.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_serial_range_invalid":                       {"e_mtc_ca_serial_range_invalid", Error, "tbsCertificate.extensions.mtcCertificationAuthority", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_key_usage_missing":                          {"e_mtc_ca_key_usage_missing", Error, "tbsCertificate.extensions.keyUsage", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_key_cert_sign_missing":                      {"e_mtc_ca_key_cert_sign_missing", Error, "tbsCertificate.extensions.keyUsage", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_basic_constraints_missing":                  {"e_mtc_ca_basic_constraints_missing", Error, "tbsCertificate.extensions.basicConstraints", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_ca_basic_constraints_not_ca":                   {"e_mtc_ca_basic_constraints_not_ca", Error, "tbsCertificate.extensions.basicConstraints", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"w_mtc_ca_ski_not_ca_id":                              {"w_mtc_ca_ski_not_ca_id", Warning, "tbsCertificate.extensions.subjectKeyIdentifier", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"w_mtc_ca_self_issued":                                {"w_mtc_ca_self_issued", Warning, "tbsCertificate.issuer", "draft-ietf-plants-merkle-tree-certs-05", "5.5"},
	"e_mtc_subscriber_issuer_not_ca_id":                   {"e_mtc_subscriber_issuer_not_ca_id", Error, "tbsCertificate.issuer", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_serial_non_positive":                           {"e_mtc_serial_non_positive", Error, "tbsCertificate.serialNumber", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_serial_too_large":                              {"e_mtc_serial_too_large", Error, "tbsCertificate.serialNumber", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_serial_log_number_zero":                        {"e_mtc_serial_log_number_zero", Error, "tbsCertificate.serialNumber", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"f_mtc_proof_malformed":                               {"f_mtc_proof_malformed", Fatal, "signatureValue", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_range_invalid":                           {"e_mtc_proof_range_invalid", Error, "signatureValue.start,end", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_subtree_invalid":                         {"e_mtc_proof_subtree_invalid", Error, "signatureValue.start,end", "draft-ietf-plants-merkle-tree-certs-05", "4.1"},
	"e_mtc_proof_index_outside_range":                     {"e_mtc_proof_index_outside_range", Error, "signatureValue.start,end", "draft-ietf-plants-merkle-tree-certs-05", "4.3.2"},
	"e_mtc_proof_extensions_order":                        {"e_mtc_proof_extensions_order", Error, "signatureValue.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.2.1"},
	"e_mtc_proof_extensions_duplicate":                    {"e_mtc_proof_extensions_duplicate", Error, "signatureValue.extensions", "draft-ietf-plants-merkle-tree-certs-05", "5.2.1"},
	"e_mtc_proof_cosigner_id_empty":                       {"e_mtc_proof_cosigner_id_empty", Error, "signatureValue.signatures.cosigner_id", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_cosigner_order":                          {"e_mtc_proof_cosigner_order", Error, "signatureValue.signatures.cosigner_id", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_mtc_proof_cosigner_duplicate":                      {"e_mtc_proof_cosigner_duplicate", Error, "signatureValue.signatures.cosigner_id", "draft-ietf-plants-merkle-tree-certs-05", "6.2"},
	"e_rfc9925_unsigned_algorithm_mismatch":               {"e_rfc9925_unsigned_algorithm_mismatch", Error, "signatureAlgorithm", "RFC 9925", "3.1"},
	"e_rfc9925_unsigned_parameters_present":               {"e_rfc9925_unsigned_parameters_present", Error, "signatureAlgorithm.parameters", "RFC 9925", "3.1"},
	"e_rfc9925_unsigned_signature_not_empty":              {"e_rfc9925_unsigned_signature_not_empty", Error, "signatureValue", "RFC 9925", "3.1"},
	"e_rfc9925_unsigned_issuer_unique_id_present":         {"e_rfc9925_unsigned_issuer_unique_id_present", Error, "tbsCertificate.issuerUniqueID", "RFC 9925", "3.2"},
	"w_rfc9925_unsigned_authority_key_identifier_present": {"w_rfc9925_unsigned_authority_key_identifier_present", Warning, "tbsCertificate.extensions.authorityKeyIdentifier", "RFC 9925", "3.3"},
	"w_rfc9925_unsigned_issuer_alternative_name_present":  {"w_rfc9925_unsigned_issuer_alternative_name_present", Warning, "tbsCertificate.extensions.issuerAlternativeName", "RFC 9925", "3.3"},
}

func TestRuleCoverageDocument(t *testing.T) {
	draftCodes := assertRuleCodeList(t, "draft-05", Draft05RuleCodes)
	cqrpCodes := assertRuleCodeList(t, "CQRP v0.2.0", CQRP020RuleCodes)

	document, err := os.ReadFile("../doc/MTC_RULE_COVERAGE.md")
	if err != nil {
		t.Fatalf("read rule coverage document: %v", err)
	}
	body := string(document)
	codes := append(draftCodes, cqrpCodes...)
	codes = append(codes, "e_mtc_profile_artifact_mismatch", "b_mtc_rule_panic")
	for _, code := range codes {
		if count := strings.Count(body, "`"+code+"`"); count != 1 {
			t.Errorf("coverage document occurrences of %q = %d, want 1", code, count)
		}
	}

	want := expectedCoverageRecords(t)
	got := parseCoverageRecords(t, body)
	if !reflect.DeepEqual(got, want) {
		for code, wantRecord := range want {
			if gotRecord, ok := got[code]; !ok {
				t.Errorf("coverage matrix lacks %q", code)
			} else if !reflect.DeepEqual(gotRecord, wantRecord) {
				t.Errorf("coverage metadata for %q = %#v, want %#v", code, gotRecord, wantRecord)
			}
		}
		for code := range got {
			if _, ok := want[code]; !ok {
				t.Errorf("coverage matrix has unexpected code %q", code)
			}
		}
	}
	assertRequirementCoverageRows(t, body)
}

type coverageRecord struct {
	Source             string
	Section            string
	ArtifactProfile    string
	InputApplicability string
	Fields             string
	Severity           string
	Status             string
}

func expectedCoverageRecords(t *testing.T) map[string]coverageRecord {
	t.Helper()
	fields := expectationFields(t, draft05Expectations, cqrp020Expectations)
	records := make(map[string]coverageRecord, len(draft05Rules)+len(cqrp020Rules)+2)
	addRules := func(rules []Rule, cqrp bool) {
		for _, rule := range rules {
			if fields[rule.Code] == "" {
				t.Fatalf("expectation maps lack fields for %q", rule.Code)
			}
			artifactProfile := "Subscriber / MTC and CQRP subscriber"
			if cqrp {
				artifactProfile = "Subscriber / CQRP subscriber"
			}
			if reflect.DeepEqual(rule.Kinds, caKinds) {
				artifactProfile = "CA / MTC and CQRP CA"
				if cqrp {
					artifactProfile = "CA / CQRP CA"
				}
			}
			if strings.HasPrefix(rule.Code, "e_rfc9925_") || strings.HasPrefix(rule.Code, "w_rfc9925_") {
				artifactProfile = "Unsigned CA / MTC and CQRP CA"
			}
			inputApplicability := "Certificate only"
			if reflect.DeepEqual(rule.InputKinds, bothInputKinds) {
				inputApplicability = "Certificate and TBS"
			}
			records[rule.Code] = coverageRecord{
				Source:             rule.Source,
				Section:            rule.Section,
				ArtifactProfile:    artifactProfile,
				InputApplicability: inputApplicability,
				Fields:             fields[rule.Code],
				Severity:           severityFromCode(t, rule.Code),
				Status:             "implemented",
			}
		}
	}
	addRules(draft05Rules, false)
	addRules(cqrp020Rules, true)
	records["e_mtc_profile_artifact_mismatch"] = coverageRecord{
		Source:             "pkimetal profile dispatch",
		Section:            "Explicit MTC profile selection",
		ArtifactProfile:    "CA or subscriber / all four MTC profiles",
		InputApplicability: "Certificate and TBS",
		Fields:             "profile",
		Severity:           "error",
		Status:             "implemented",
	}
	records["b_mtc_rule_panic"] = coverageRecord{
		Source:             "inherited from panicking rule (`Rule.Source`)",
		Section:            "inherited from panicking rule (`Rule.Section`)",
		ArtifactProfile:    "Any registered native MTC rule",
		InputApplicability: "Rule applicability",
		Fields:             "none",
		Severity:           "bug",
		Status:             "implemented",
	}
	return records
}

func expectationFields(t *testing.T, groups ...map[string]findingExpectation) map[string]string {
	t.Helper()
	fieldSets := make(map[string]map[string]bool)
	for _, group := range groups {
		for _, expectation := range group {
			if fieldSets[expectation.Code] == nil {
				fieldSets[expectation.Code] = make(map[string]bool)
			}
			fieldSets[expectation.Code][expectation.Field] = true
			if got, want := severityName(expectation.Severity), severityFromCode(t, expectation.Code); got != want {
				t.Fatalf("expectation severity for %q = %q, want code-derived %q", expectation.Code, got, want)
			}
		}
	}
	fields := make(map[string]string, len(fieldSets))
	for code, set := range fieldSets {
		var sorted []string
		for field := range set {
			sorted = append(sorted, field)
		}
		sort.Strings(sorted)
		fields[code] = strings.Join(sorted, "; ")
	}
	return fields
}

func severityFromCode(t *testing.T, code string) string {
	t.Helper()
	if len(code) < 2 || code[1] != '_' {
		t.Fatalf("stable finding code %q lacks a severity prefix", code)
	}
	switch code[0] {
	case 'w':
		return "warning"
	case 'e':
		return "error"
	case 'b':
		return "bug"
	case 'f':
		return "fatal"
	default:
		t.Fatalf("stable finding code %q has an unknown severity prefix", code)
		return ""
	}
}

func severityName(severity Severity) string {
	switch severity {
	case Warning:
		return "warning"
	case Error:
		return "error"
	case Bug:
		return "bug"
	case Fatal:
		return "fatal"
	default:
		return ""
	}
}

func parseCoverageRecords(t *testing.T, body string) map[string]coverageRecord {
	t.Helper()
	records := make(map[string]coverageRecord)
	for lineNumber, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) != 10 {
			t.Errorf("stable coverage row %d has %d columns, want 8: %s", lineNumber+1, len(columns)-2, line)
			continue
		}
		code := strings.Trim(strings.TrimSpace(columns[1]), "`")
		if _, exists := records[code]; exists {
			t.Errorf("stable coverage row %d duplicates %q", lineNumber+1, code)
			continue
		}
		records[code] = coverageRecord{
			Source:             strings.TrimSpace(columns[2]),
			Section:            strings.TrimSpace(columns[3]),
			ArtifactProfile:    strings.TrimSpace(columns[4]),
			InputApplicability: strings.TrimSpace(columns[5]),
			Fields:             normalizeFieldSet(strings.TrimSpace(columns[6])),
			Severity:           strings.TrimSpace(columns[7]),
			Status:             strings.TrimSpace(columns[8]),
		}
	}
	return records
}

func normalizeFieldSet(fields string) string {
	if fields == "none" {
		return fields
	}
	parts := strings.Split(fields, ";")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func assertRequirementCoverageRows(t *testing.T, body string) {
	t.Helper()
	const heading = "## Requirement-level coverage without finding codes"
	start := strings.Index(body, heading)
	if start < 0 {
		t.Fatal("coverage document lacks requirement-level coverage section")
	}
	seenStatuses := make(map[string]bool)
	rows := 0
	for lineNumber, line := range strings.Split(body[start:], "\n") {
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "| Requirement ") || strings.HasPrefix(line, "| ---") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) != 10 {
			t.Errorf("requirement coverage row %d has %d columns, want 8: %s", lineNumber+1, len(columns)-2, line)
			continue
		}
		rows++
		for column := 1; column <= 8; column++ {
			if strings.TrimSpace(columns[column]) == "" {
				t.Errorf("requirement coverage row %d has blank column %d", lineNumber+1, column)
			}
		}
		if field := strings.TrimSpace(columns[6]); field != "n/a" {
			t.Errorf("requirement coverage row %d has Field(s) %q, want n/a", lineNumber+1, field)
		}
		seenStatuses[strings.TrimSpace(columns[8])] = true
	}
	if rows == 0 {
		t.Error("requirement coverage table is empty")
	}
	wantStatuses := map[string]bool{"delegated": true, "not applicable": true, "not locally decidable": true}
	if !reflect.DeepEqual(seenStatuses, wantStatuses) {
		t.Errorf("requirement coverage statuses = %v, want %v", seenStatuses, wantStatuses)
	}
}

func TestExperimentalDeploymentDocumentation(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(contents)
	}

	readme := read("../README.md")
	const deploymentMarker = "Deployment scope: experimental fork only"
	if count := strings.Count(readme, deploymentMarker); count != 1 {
		t.Errorf("README deployment marker occurrences = %d, want 1", count)
	}
	dockerSection := markdownSection(t, readme, "## Docker containers")
	for _, url := range []string{
		"https://github.com/orgs/pkimetal/packages?repo_name=pkimetal",
		"https://github.com/pkimetal/pkimetal/pkgs/container/pkimetal",
		"https://github.com/pkimetal/pkimetal/pkgs/container/pkimetal-dev",
	} {
		if !strings.Contains(dockerSection, url) {
			t.Errorf("README Docker section lacks upstream link %q", url)
		}
	}
	publicSection := markdownSection(t, readme, "## Public instances")
	for _, url := range []string{"https://pkimet.al/", "https://dev.pkimet.al/"} {
		if !strings.Contains(publicSection, url) {
			t.Errorf("README Public instances section lacks upstream link %q", url)
		}
	}

	openapi := read("../doc/openapi.yaml")
	for _, upstream := range []string{"https://pkimet.al", "https://dev.pkimet.al"} {
		if strings.Contains(openapi, upstream) {
			t.Errorf("OpenAPI advertises upstream server %s for this fork", upstream)
		}
	}
	if !strings.Contains(openapi, "description: Experimental local fork deployment") {
		t.Error("OpenAPI lacks an experimental local deployment server description")
	}
}

func markdownSection(t *testing.T, document, heading string) string {
	t.Helper()
	start := strings.Index(document, heading)
	if start < 0 {
		t.Fatalf("document lacks heading %q", heading)
	}
	body := document[start+len(heading):]
	if end := strings.Index(body, "\n## "); end >= 0 {
		body = body[:end]
	}
	return body
}

type openAPISchema struct {
	Ref        string                   `yaml:"$ref"`
	Type       string                   `yaml:"type"`
	Required   []string                 `yaml:"required"`
	Properties map[string]openAPISchema `yaml:"properties"`
	AllOf      []openAPISchema          `yaml:"allOf"`
	AnyOf      []openAPISchema          `yaml:"anyOf"`
	OneOf      []openAPISchema          `yaml:"oneOf"`
}

type openAPIExample struct {
	Value any `yaml:"value"`
}

type openAPIMediaType struct {
	Schema   openAPISchema             `yaml:"schema"`
	Examples map[string]openAPIExample `yaml:"examples"`
}

type openAPIRequestBody struct {
	Content map[string]openAPIMediaType `yaml:"content"`
}

func TestOpenAPIEndpointInputAliases(t *testing.T) {
	contents, err := os.ReadFile("../doc/openapi.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI document: %v", err)
	}
	var spec struct {
		Paths map[string]struct {
			Post struct {
				RequestBody openAPISchema `yaml:"requestBody"`
			} `yaml:"post"`
		} `yaml:"paths"`
		Components struct {
			RequestBodies map[string]openAPIRequestBody `yaml:"requestBodies"`
			Schemas       map[string]openAPISchema      `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(contents, &spec); err != nil {
		t.Fatalf("parse OpenAPI document: %v", err)
	}

	tests := []struct {
		path        string
		requestBody string
		schema      string
		alias       string
		binaryMedia string
	}{
		{"/lintcert", "CertificateLintRequestBody", "CertificateLintRequest", "b64cert", "application/pkix-cert"},
		{"/linttbscert", "TBSCertificateLintRequestBody", "TBSCertificateLintRequest", "b64tbscert", "application/octet-stream"},
		{"/lintcrl", "CRLLintRequestBody", "CRLLintRequest", "b64crl", ""},
		{"/linttbscrl", "TBSCRLLintRequestBody", "TBSCRLLintRequest", "b64tbscrl", ""},
		{"/lintocsp", "OCSPLintRequestBody", "OCSPLintRequest", "b64ocsp", ""},
		{"/linttbsocsp", "TBSOCSPLintRequestBody", "TBSOCSPLintRequest", "b64tbsocsp", ""},
	}
	allAliases := []string{"b64cert", "b64tbscert", "b64crl", "b64tbscrl", "b64ocsp", "b64tbsocsp"}
	for _, tc := range tests {
		t.Run(tc.schema, func(t *testing.T) {
			if got, want := spec.Paths[tc.path].Post.RequestBody.Ref, "#/components/requestBodies/"+tc.requestBody; got != want {
				t.Errorf("%s request body ref = %q, want %q", tc.path, got, want)
			}
			form := spec.Components.RequestBodies[tc.requestBody].Content["application/x-www-form-urlencoded"]
			if got, want := form.Schema.Ref, "#/components/schemas/"+tc.schema; got != want {
				t.Errorf("form schema ref = %q, want %q", got, want)
			}
			schema := spec.Components.Schemas[tc.schema]
			if len(schema.AllOf) != 2 || schema.AllOf[0].Ref != "#/components/schemas/LintRequestOptions" {
				t.Fatalf("%s common options composition = %#v", tc.schema, schema.AllOf)
			}
			input := schema.AllOf[1]
			for _, property := range []string{"b64input", tc.alias} {
				if _, ok := input.Properties[property]; !ok {
					t.Errorf("%s lacks property %q", tc.schema, property)
				}
			}
			for _, alias := range allAliases {
				if alias != tc.alias {
					if _, ok := input.Properties[alias]; ok {
						t.Errorf("%s documents wrong endpoint alias %q", tc.schema, alias)
					}
				}
			}
			if len(input.AnyOf) != 2 || len(input.OneOf) != 0 {
				t.Errorf("%s input choice uses anyOf=%#v oneOf=%#v", tc.schema, input.AnyOf, input.OneOf)
			} else {
				gotRequired := []string{strings.Join(input.AnyOf[0].Required, ","), strings.Join(input.AnyOf[1].Required, ",")}
				sort.Strings(gotRequired)
				wantRequired := []string{"b64input", tc.alias}
				sort.Strings(wantRequired)
				if !reflect.DeepEqual(gotRequired, wantRequired) {
					t.Errorf("%s anyOf requirements = %v, want %v", tc.schema, gotRequired, wantRequired)
				}
			}
			if len(form.Examples) == 0 {
				t.Errorf("%s form media type has no alias examples", tc.requestBody)
			}
			for name, example := range form.Examples {
				value, ok := example.Value.(map[string]any)
				if !ok {
					t.Errorf("form example %q value = %#v, want object", name, example.Value)
					continue
				}
				if _, ok := value[tc.alias]; !ok {
					t.Errorf("form example %q lacks endpoint alias %q", name, tc.alias)
				}
				if _, ok := value["b64input"]; ok {
					t.Errorf("form example %q should demonstrate alias rather than b64input", name)
				}
				for _, alias := range allAliases {
					if alias != tc.alias {
						if _, ok := value[alias]; ok {
							t.Errorf("form example %q uses wrong endpoint alias %q", name, alias)
						}
					}
				}
			}
			if tc.binaryMedia != "" {
				binaryExamples := spec.Components.RequestBodies[tc.requestBody].Content[tc.binaryMedia].Examples
				if len(binaryExamples) == 0 {
					t.Errorf("%s binary media type has no descriptive example", tc.requestBody)
				}
				for name, example := range binaryExamples {
					if example.Value != nil {
						t.Errorf("binary example %q fabricates value %#v", name, example.Value)
					}
				}
			}
		})
	}

	const exactFinding = "[draft-ietf-plants-merkle-tree-certs-05 §6.2] MTCProof is malformed"
	if !strings.Contains(string(contents), `Finding: "`+exactFinding+`"`) {
		t.Errorf("OpenAPI lacks exact malformed-proof wire finding %q", exactFinding)
	}
	rest, err := os.ReadFile("../doc/REST_API.md")
	if err != nil {
		t.Fatalf("read REST API document: %v", err)
	}
	if !strings.Contains(string(rest), `"Finding": "`+exactFinding+`"`) {
		t.Errorf("REST API lacks exact malformed-proof wire finding %q", exactFinding)
	}
}

func assertRuleCodeList(t *testing.T, name string, list func() []string) []string {
	t.Helper()
	first := list()
	if len(first) == 0 {
		t.Fatalf("%s rule code list is empty", name)
	}
	if !sort.StringsAreSorted(first) {
		t.Errorf("%s rule codes are not sorted: %q", name, first)
	}
	for i, code := range first {
		if code == "" {
			t.Errorf("%s rule code %d is blank", name, i)
		}
		if i > 0 && code == first[i-1] {
			t.Errorf("%s rule code %q is duplicated", name, code)
		}
	}
	want := append([]string(nil), first...)
	first[0] = "caller mutation"
	if got := list(); !reflect.DeepEqual(got, want) {
		t.Errorf("%s rule code list shares caller-mutable storage: got %q, want %q", name, got, want)
	}
	return want
}

func TestDraft05ValidArtifactsHaveNoFindings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		kind  InputKind
	}{
		{"subscriber certificate", mtctest.Certificate(mtctest.ValidSubscriberTemplate()), InputCertificate},
		{"subscriber TBS", mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), InputTBSCertificate},
		{"CA certificate", mtctest.Certificate(mtctest.ValidCATemplate()), InputCertificate},
		{"unsigned CA certificate", mtctest.Certificate(mtctest.ValidUnsignedCATemplate()), InputCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, tc.input, tc.kind)
			assertFindings(t, LintDraft05(artifact))
		})
	}
}

func TestDraft05CARules(t *testing.T) {
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64)
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   string
	}{
		{"subject is not CA ID", func(x *mtctest.Template) {
			x.Subject = mtctest.ValidSubscriberTemplate().Subject
			x.Issuer = mtctest.ValidCAIDNameDER()
		}, "e_mtc_ca_subject_not_ca_id"},
		{"MTC CA extension not critical", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDMTC_CA, Value: mtctest.ValidCAExtensionDER()})
		}, "e_mtc_ca_extension_not_critical"},
		{"MTC CA extension malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: []byte{0x30, 0x80, 0, 0}})
		}, "f_mtc_ca_extension_malformed"},
		{"MTC CA extension duplicated", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDMTC_CA, Critical: true, Value: mtctest.ValidCAExtensionDER()})
		}, "f_mtc_ca_extension_malformed"},
		{"minimum serial negative", replaceCARange(big.NewInt(-1), big.NewInt(10)), "e_mtc_ca_serial_range_invalid"},
		{"maximum serial negative", replaceCARange(big.NewInt(0), big.NewInt(-1)), "e_mtc_ca_serial_range_invalid"},
		{"maximum serial too large", replaceCARange(big.NewInt(1), tooLarge), "e_mtc_ca_serial_range_invalid"},
		{"serial range reversed", replaceCARange(big.NewInt(10), big.NewInt(9)), "e_mtc_ca_serial_range_invalid"},
		{"key usage missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDKeyUsage) }, "e_mtc_ca_key_usage_missing"},
		{"key cert sign missing", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(false)})
		}, "e_mtc_ca_key_cert_sign_missing"},
		{"key usage malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: []byte{0x03, 0x01, 0x08}})
		}, "e_mtc_ca_key_cert_sign_missing"},
		{"basic constraints missing", func(x *mtctest.Template) { mtctest.RemoveExtension(x, mtctest.OIDBasicConstraints) }, "e_mtc_ca_basic_constraints_missing"},
		{"basic constraints not CA", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(false)})
		}, "e_mtc_ca_basic_constraints_not_ca"},
		{"basic constraints malformed", func(x *mtctest.Template) {
			mtctest.ReplaceExtension(x, mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: []byte{0x30, 0x01, 0x01}})
		}, "e_mtc_ca_basic_constraints_not_ca"},
		{"SKI is not CA ID", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER([]byte("wrong"))})
		}, "w_mtc_ca_ski_not_ca_id"},
		{"structurally self-issued", func(x *mtctest.Template) { x.Issuer = append([]byte(nil), x.Subject...) }, "w_mtc_ca_self_issued"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact), tc.want)
		})
	}
}

func TestLintDraft05ForKindEvaluatesExplicitCAWithoutMutation(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	mtctest.RemoveExtension(&tpl, mtctest.OIDMTC_CA)
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	if artifact.Kind != ArtifactUnknown {
		t.Fatalf("autodetected kind = %v, want unknown", artifact.Kind)
	}
	assertFindings(t, LintDraft05(artifact))

	originalKind := artifact.Kind
	originalRaw := append([]byte(nil), artifact.Raw...)
	originalTBS := append([]byte(nil), artifact.RawTBS...)
	originalSubject := append([]byte(nil), artifact.SubjectRaw...)
	originalSerial := new(big.Int).Set(artifact.SerialNumber)
	originalExtensions := cloneExtensions(artifact.Extensions)

	findings := LintDraft05ForKind(artifact, ArtifactCA)
	assertFindings(t, findings, "e_mtc_ca_extension_missing")
	if artifact.Kind != originalKind || !bytes.Equal(artifact.Raw, originalRaw) ||
		!bytes.Equal(artifact.RawTBS, originalTBS) || !bytes.Equal(artifact.SubjectRaw, originalSubject) ||
		artifact.SerialNumber.Cmp(originalSerial) != 0 || !reflect.DeepEqual(artifact.Extensions, originalExtensions) {
		t.Fatalf("LintDraft05ForKind mutated caller artifact: %#v", artifact)
	}
}

func TestLintDraft05ForKindHandlesNilAndUnsupportedKind(t *testing.T) {
	if got := LintDraft05ForKind(nil, ArtifactCA); got != nil {
		t.Fatalf("nil artifact findings = %#v", got)
	}
	artifact := parseArtifact(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), InputCertificate)
	if got := LintDraft05ForKind(artifact, ArtifactUnknown); got != nil {
		t.Fatalf("unsupported expected kind findings = %#v", got)
	}
	if artifact.Kind != ArtifactSubscriber {
		t.Fatalf("unsupported expected kind mutated artifact kind to %v", artifact.Kind)
	}
}

func TestLintDraft05ForKindRebuildsSubscriberProofState(t *testing.T) {
	validProof := mtctest.ProofBytes(mtctest.ValidProof())
	tests := []struct {
		name     string
		template mtctest.Template
		want     []string
	}{
		{
			name:     "unknown with valid proof",
			template: explicitUnknownSubscriberTemplate(validProof),
			want:     []string{"signature_algorithm_oid_inner", "e_mtc_subscriber_issuer_not_ca_id"},
		},
		{
			name:     "unknown with malformed proof",
			template: explicitUnknownSubscriberTemplate(mtctest.MalformedProofBytes()),
			want:     []string{"signature_algorithm_oid_inner", "e_mtc_subscriber_issuer_not_ca_id", "f_mtc_proof_malformed"},
		},
		{
			name:     "CA with valid proof",
			template: explicitCASubscriberTemplate(validProof),
			want:     nil,
		},
		{
			name:     "CA with malformed proof",
			template: explicitCASubscriberTemplate(mtctest.MalformedProofBytes()),
			want:     []string{"f_mtc_proof_malformed"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := parseArtifact(t, mtctest.Certificate(tc.template), InputCertificate)
			if artifact.Kind == ArtifactSubscriber || artifact.Proof != nil || artifact.ProofParseError != nil {
				t.Fatalf("precondition kind/proof/error = %v/%#v/%v", artifact.Kind, artifact.Proof, artifact.ProofParseError)
			}
			findings := lintForKindWithoutMutation(t, artifact, ArtifactSubscriber)
			assertFindings(t, findings, tc.want...)
		})
	}
}

func TestLintDraft05ForKindRunsSubscriberProofSemanticRules(t *testing.T) {
	tpl := explicitCASubscriberTemplate(mtctest.ProofBytes(mtctest.Proof{Start: 4, End: 9}))
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	findings := lintForKindWithoutMutation(t, artifact, ArtifactSubscriber)
	assertFindings(t, findings, "e_mtc_proof_subtree_invalid")
}

func TestLintDraft05ForKindDoesNotParseProofForTBS(t *testing.T) {
	tpl := explicitCASubscriberTemplate(mtctest.MalformedProofBytes())
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), InputTBSCertificate)
	findings := lintForKindWithoutMutation(t, artifact, ArtifactSubscriber)
	assertFindings(t, findings)
}

func TestDraft05CASerialRangeBoundaries(t *testing.T) {
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
	for _, tc := range []struct {
		name     string
		min, max *big.Int
	}{
		{"zero range", big.NewInt(0), big.NewInt(0)},
		{"zero through maximum", big.NewInt(0), max},
		{"positive singleton", big.NewInt(1), big.NewInt(1)},
		{"maximum singleton", max, max},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			replaceCARange(tc.min, tc.max)(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact))
		})
	}
}

func TestDraft05KeyUsageNamedBitListCanonicality(t *testing.T) {
	for _, tc := range []struct {
		name        string
		value       []byte
		wantFinding bool
	}{
		{"single keyCertSign bit", []byte{0x03, 0x02, 0x02, 0x04}, false},
		{"multiple first-octet bits", []byte{0x03, 0x02, 0x02, 0x84}, false},
		{"multiple octets", []byte{0x03, 0x03, 0x07, 0x04, 0x80}, false},
		{"trailing zero octet", []byte{0x03, 0x03, 0x00, 0x04, 0x00}, true},
		{"nonminimal unused count", []byte{0x03, 0x02, 0x00, 0x04}, true},
		{"nonzero unused bits", []byte{0x03, 0x02, 0x03, 0x04}, true},
		{"invalid unused count", []byte{0x03, 0x01, 0x08}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			mtctest.ReplaceExtension(&tpl, mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: tc.value})
			findings := LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate))
			if tc.wantFinding {
				assertFindings(t, findings, "e_mtc_ca_key_cert_sign_missing")
			} else {
				assertFindings(t, findings)
			}
		})
	}
}

func TestDraft05ValidSKIEncodesCAID(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
		ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER(mtctest.ValidCAID()),
	})
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	assertFindings(t, LintDraft05(artifact))
}

func TestDraft05SKIWarningRequiresParsedSubjectCAID(t *testing.T) {
	tpl := mtctest.ValidCATemplate()
	tpl.Subject = mtctest.ValidSubscriberTemplate().Subject
	tpl.Issuer = mtctest.ValidCAIDNameDER()
	tpl.Extensions = append(tpl.Extensions, mtctest.Extension{
		ID: mtctest.OIDSubjectKeyID, Value: mtctest.SubjectKeyIdentifierDER([]byte("wrong")),
	})
	findings := LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate))
	assertFindings(t, findings, "e_mtc_ca_subject_not_ca_id")
}

func TestDraft05DuplicateCAExtensionContentChecksAreOrderIndependent(t *testing.T) {
	goodKeyUsage := mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(true)}
	badKeyUsage := mtctest.Extension{ID: mtctest.OIDKeyUsage, Critical: true, Value: mtctest.KeyUsageDER(false)}
	goodBasicConstraints := mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(true)}
	badBasicConstraints := mtctest.Extension{ID: mtctest.OIDBasicConstraints, Critical: true, Value: mtctest.BasicConstraintsDER(false)}
	for _, tc := range []struct {
		name       string
		oid        asn1.ObjectIdentifier
		extensions []mtctest.Extension
	}{
		{"key usage good then bad", mtctest.OIDKeyUsage, []mtctest.Extension{goodKeyUsage, badKeyUsage}},
		{"key usage bad then good", mtctest.OIDKeyUsage, []mtctest.Extension{badKeyUsage, goodKeyUsage}},
		{"basic constraints good then bad", mtctest.OIDBasicConstraints, []mtctest.Extension{goodBasicConstraints, badBasicConstraints}},
		{"basic constraints bad then good", mtctest.OIDBasicConstraints, []mtctest.Extension{badBasicConstraints, goodBasicConstraints}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCATemplate()
			mtctest.RemoveExtension(&tpl, tc.oid)
			tpl.Extensions = append(tpl.Extensions, tc.extensions...)
			findings := LintDraft05(parseArtifact(t, mtctest.Certificate(tpl), InputCertificate))
			assertFindings(t, findings)
		})
	}
}

func TestDraft05SubscriberRules(t *testing.T) {
	tooLarge := new(big.Int).Lsh(big.NewInt(1), 64)
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   []string
	}{
		{"inner signature algorithm OID", func(x *mtctest.Template) { x.TBSSignature.OID = mtctest.OIDSHA256 }, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_oid_inner"}},
		{"outer signature algorithm OID", func(x *mtctest.Template) { x.OuterSignature.OID = mtctest.OIDSHA256 }, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_oid_outer"}},
		{"inner signature parameters", func(x *mtctest.Template) {
			x.TBSSignature.ParametersPresent, x.TBSSignature.Parameters = true, []byte{0x05, 0x00}
		}, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_parameters_present_inner"}},
		{"outer signature parameters", func(x *mtctest.Template) {
			x.OuterSignature.ParametersPresent, x.OuterSignature.Parameters = true, []byte{0x05, 0x00}
		}, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_parameters_present_outer"}},
		{"inner and outer signature mismatch", func(x *mtctest.Template) {
			x.OuterSignature.ParametersPresent, x.OuterSignature.Parameters = true, []byte{0x05, 0x00}
		}, []string{"e_mtc_cert_signature_algorithm_mismatch", "signature_algorithm_parameters_present_outer"}},
		{"signature unused bits", func(x *mtctest.Template) { x.SignatureUnused = 1 }, []string{"e_mtc_signature_value_unused_bits"}},
		{"issuer is not CA ID", func(x *mtctest.Template) { x.Issuer = x.Subject }, []string{"e_mtc_subscriber_issuer_not_ca_id"}},
		{"serial zero", func(x *mtctest.Template) { x.Serial = big.NewInt(0) }, []string{"e_mtc_serial_non_positive"}},
		{"serial negative", func(x *mtctest.Template) { x.Serial = big.NewInt(-1) }, []string{"e_mtc_serial_non_positive"}},
		{"serial too large", func(x *mtctest.Template) { x.Serial = tooLarge }, []string{"e_mtc_serial_too_large"}},
		{"zero log number", func(x *mtctest.Template) { x.Serial = big.NewInt(7) }, []string{"e_mtc_serial_log_number_zero"}},
		{"malformed proof", func(x *mtctest.Template) { x.Signature = mtctest.MalformedProofBytes() }, []string{"f_mtc_proof_malformed"}},
		{"proof range empty", withProof(func(p *mtctest.Proof) { p.Start, p.End = 7, 7 }), []string{"e_mtc_proof_range_invalid"}},
		{"proof range reversed", withProof(func(p *mtctest.Proof) { p.Start, p.End = 8, 7 }), []string{"e_mtc_proof_range_invalid"}},
		{"proof subtree invalid", withProof(func(p *mtctest.Proof) { p.Start, p.End = 4, 9 }), []string{"e_mtc_proof_subtree_invalid"}},
		{"proof index outside range", func(x *mtctest.Template) {
			x.Serial = new(big.Int).SetUint64((1 << 48) | 9)
			withProof(func(p *mtctest.Proof) { p.Start, p.End = 0, 8 })(x)
		}, []string{"e_mtc_proof_index_outside_range"}},
		{"proof extensions out of order", withProof(func(p *mtctest.Proof) {
			p.Extensions = []mtctest.ProofExtension{{Type: 2}, {Type: 1}}
		}), []string{"e_mtc_proof_extensions_order"}},
		{"proof extensions duplicate", withProof(func(p *mtctest.Proof) {
			p.Extensions = []mtctest.ProofExtension{{Type: 1}, {Type: 1}}
		}), []string{"e_mtc_proof_extensions_duplicate"}},
		{"cosigner ID empty", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{Signature: []byte{1}}}
		}), []string{"e_mtc_proof_cosigner_id_empty"}},
		{"cosigners out of length order", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("aa")}, {CosignerID: []byte("b")}}
		}), []string{"e_mtc_proof_cosigner_order"}},
		{"cosigners out of lexical order", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("b")}, {CosignerID: []byte("a")}}
		}), []string{"e_mtc_proof_cosigner_order"}},
		{"cosigner duplicate", withProof(func(p *mtctest.Proof) {
			p.Signatures = []mtctest.ProofSignature{{CosignerID: []byte("a")}, {CosignerID: []byte("a")}}
		}), []string{"e_mtc_proof_cosigner_duplicate"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidSubscriberTemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact), tc.want...)
		})
	}
}

func TestDraft05ProofUint48RangeIsCheckedWithoutCascades(t *testing.T) {
	artifact := parseArtifact(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), InputCertificate)
	artifact.Proof.End = 1 << 48
	assertFindings(t, LintDraft05(artifact), "e_mtc_proof_range_invalid")
}

func TestDraft05TBSDoesNotRunOuterOrProofRules(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDSHA256, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}
	tpl.Signature = mtctest.MalformedProofBytes()
	tpl.SignatureUnused = 1
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), InputTBSCertificate)
	assertFindings(t, LintDraft05(artifact))
}

func TestDraft05RFC9925UnsignedCARules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*mtctest.Template)
		want   string
	}{
		{"algorithm mismatch", func(x *mtctest.Template) { x.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDMLDSA65} }, "e_rfc9925_unsigned_algorithm_mismatch"},
		{"parameters present", func(x *mtctest.Template) {
			x.TBSSignature.ParametersPresent, x.TBSSignature.Parameters = true, []byte{0x05, 0x00}
		}, "e_rfc9925_unsigned_parameters_present"},
		{"signature not empty", func(x *mtctest.Template) { x.Signature = []byte{1} }, "e_rfc9925_unsigned_signature_not_empty"},
		{"issuer unique ID present", func(x *mtctest.Template) { x.IssuerUniqueID = []byte{0x80}; x.IssuerUniqueIDUnused = 7 }, "e_rfc9925_unsigned_issuer_unique_id_present"},
		{"authority key identifier present", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDAuthorityKeyID, Value: []byte{0x30, 0}})
		}, "w_rfc9925_unsigned_authority_key_identifier_present"},
		{"issuer alternative name present", func(x *mtctest.Template) {
			x.Extensions = append(x.Extensions, mtctest.Extension{ID: mtctest.OIDIssuerAltName, Value: []byte{0x30, 0}})
		}, "w_rfc9925_unsigned_issuer_alternative_name_present"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidUnsignedCATemplate()
			tc.mutate(&tpl)
			artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
			assertFindings(t, LintDraft05(artifact), tc.want)
		})
	}
}

func TestDraft05UnsignedRulesApplyToTBSWhenDecidable(t *testing.T) {
	tpl := mtctest.ValidUnsignedCATemplate()
	tpl.TBSSignature.ParametersPresent = true
	tpl.TBSSignature.Parameters = []byte{0x05, 0x00}
	tpl.IssuerUniqueID = []byte{0x80}
	tpl.IssuerUniqueIDUnused = 7
	artifact := parseArtifact(t, mtctest.TBSCertificate(tpl), InputTBSCertificate)
	assertFindings(t, LintDraft05(artifact),
		"e_rfc9925_unsigned_issuer_unique_id_present",
		"e_rfc9925_unsigned_parameters_present",
	)
}

func TestDraft05UnsignedRulesDoNotApplyToSubscribers(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDUnsigned}
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDUnsigned}
	tpl.Signature = nil
	artifact := parseArtifact(t, mtctest.Certificate(tpl), InputCertificate)
	assertFindings(t, LintDraft05(artifact), "signature_algorithm_oid_inner", "f_mtc_proof_malformed")
}

func replaceCARange(min, max *big.Int) func(*mtctest.Template) {
	return func(tpl *mtctest.Template) {
		mtctest.ReplaceExtension(tpl, mtctest.Extension{
			ID:       mtctest.OIDMTC_CA,
			Critical: true,
			Value: mtctest.CAExtensionDER(
				mtctest.Algorithm{OID: mtctest.OIDSHA256},
				mtctest.Algorithm{OID: mtctest.OIDMLDSA65},
				min, max,
			),
		})
	}
}

func withProof(mutate func(*mtctest.Proof)) func(*mtctest.Template) {
	return func(tpl *mtctest.Template) {
		proof := mtctest.ValidProof()
		mutate(&proof)
		tpl.Signature = mtctest.ProofBytes(proof)
	}
}

func parseArtifact(t *testing.T, input []byte, kind InputKind) *Artifact {
	t.Helper()
	artifact, err := Parse(input, kind)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func cloneExtensions(extensions []Extension) []Extension {
	cloned := make([]Extension, len(extensions))
	for i, extension := range extensions {
		cloned[i] = extension
		cloned[i].Raw = append([]byte(nil), extension.Raw...)
		cloned[i].ID = append(asn1.ObjectIdentifier(nil), extension.ID...)
		cloned[i].Value = append([]byte(nil), extension.Value...)
	}
	return cloned
}

func explicitUnknownSubscriberTemplate(signature []byte) mtctest.Template {
	tpl := mtctest.ValidCATemplate()
	mtctest.RemoveExtension(&tpl, mtctest.OIDMTC_CA)
	tpl.Serial = new(big.Int).SetUint64((1 << 48) | 7)
	tpl.Signature = append([]byte(nil), signature...)
	return tpl
}

func explicitCASubscriberTemplate(signature []byte) mtctest.Template {
	tpl := mtctest.ValidCATemplate()
	tpl.Serial = new(big.Int).SetUint64((1 << 48) | 7)
	tpl.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDMTCProof}
	tpl.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDMTCProof}
	tpl.Issuer = mtctest.ValidCAIDNameDER()
	tpl.Signature = append([]byte(nil), signature...)
	return tpl
}

func lintForKindWithoutMutation(t *testing.T, artifact *Artifact, expected ArtifactKind) []Finding {
	t.Helper()
	originalKind := artifact.Kind
	originalProof := artifact.Proof
	originalProofError := artifact.ProofParseError
	originalSignature := append([]byte(nil), artifact.SignatureValue...)
	originalExtensions := cloneExtensions(artifact.Extensions)

	findings := LintDraft05ForKind(artifact, expected)
	if artifact.Kind != originalKind || artifact.Proof != originalProof || artifact.ProofParseError != originalProofError ||
		!bytes.Equal(artifact.SignatureValue, originalSignature) || !reflect.DeepEqual(artifact.Extensions, originalExtensions) {
		t.Fatalf("LintDraft05ForKind mutated caller artifact: %#v", artifact)
	}
	return findings
}

func assertFindings(t *testing.T, findings []Finding, expectationIDs ...string) {
	t.Helper()
	want := make([]findingExpectation, len(expectationIDs))
	for i, id := range expectationIDs {
		expectation, ok := draft05Expectations[id]
		if !ok {
			t.Fatalf("unknown finding expectation %q", id)
		}
		want[i] = expectation
	}
	sort.SliceStable(want, func(i, j int) bool { return want[i].Code < want[j].Code })

	got := make([]findingExpectation, len(findings))
	for i, finding := range findings {
		got[i] = findingExpectation{
			Code: finding.Code, Severity: finding.Severity, Field: finding.Field,
			Source: finding.Source, Section: finding.Section,
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding tuples = %#v, want %#v; findings = %#v", got, want, findings)
	}
}
