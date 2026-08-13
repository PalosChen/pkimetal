package mtc

import (
	"encoding/asn1"
	"net/url"
	"sort"
	"strings"
)

const (
	mtcTlogSource  = "C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105"
	mtcTlogSection = "Parameters"
)

var mtcTlogRuleCodes = []string{
	"e_cqrp_ca_mtc_tlog_extension_missing",
	"e_mtc_tlog_extension_critical",
	"e_mtc_tlog_extension_duplicate",
	"e_mtc_tlog_extension_malformed",
	"e_mtc_tlog_log_hash_not_sha256",
	"e_mtc_tlog_prefix_url_invalid",
}

// MTCTlogRuleCodes returns the stable finding codes for the certificate-local
// portion of the pinned C2SP mtc-tlog profile.
func MTCTlogRuleCodes() []string {
	codes := append([]string(nil), mtcTlogRuleCodes...)
	sort.Strings(codes)
	return codes
}

// LintMTCTlogConditionalForKind evaluates the opt-in mtc-tlog profile. A
// generic MTC CA without the extension does not opt in and receives no result.
func LintMTCTlogConditionalForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	return lintMTCTlogForKind(artifact, expected, false)
}

// LintMTCTlogRequiredForKind evaluates mtc-tlog as a mandatory CQRP CA
// profile component.
func LintMTCTlogRequiredForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	return lintMTCTlogForKind(artifact, expected, true)
}

func lintMTCTlogForKind(artifact *Artifact, expected ArtifactKind, required bool) []Finding {
	if artifact == nil || expected != ArtifactCA {
		return nil
	}
	local := *artifact
	local.Kind = ArtifactCA
	extensionCount := countExtensions(&local, OIDMTCTlogPrefixURL)
	if !required && extensionCount == 0 {
		return nil
	}

	rules := make([]Rule, 0, 6)
	if required {
		rules = append(rules, Rule{
			Code:       "e_cqrp_ca_mtc_tlog_extension_missing",
			Source:     cqrp020Source,
			Section:    "4.6.1",
			Kinds:      caKinds,
			InputKinds: bothInputKinds,
			Evaluate: func(a *Artifact) *Finding {
				if countExtensions(a, OIDMTCTlogPrefixURL) == 0 {
					return errorFinding("tbsCertificate.extensions.mtcTlogPrefixURL", "CQRP CA mtc-tlog prefix URL extension is missing")
				}
				return nil
			},
		})
	}
	rules = append(rules, commonMTCTlogRules()...)
	return runRules(&local, rules)
}

func commonMTCTlogRules() []Rule {
	return []Rule{
		mtcTlogRule("e_mtc_tlog_extension_duplicate", func(a *Artifact) *Finding {
			if countExtensions(a, OIDMTCTlogPrefixURL) > 1 {
				return errorFinding("tbsCertificate.extensions.mtcTlogPrefixURL", "mtc-tlog prefix URL extension is duplicated")
			}
			return nil
		}),
		mtcTlogRule("e_mtc_tlog_extension_critical", func(a *Artifact) *Finding {
			for _, extension := range matchingExtensions(a, OIDMTCTlogPrefixURL) {
				if extension.Critical {
					return errorFinding("tbsCertificate.extensions.mtcTlogPrefixURL", "mtc-tlog prefix URL extension is critical")
				}
			}
			return nil
		}),
		mtcTlogRule("e_mtc_tlog_extension_malformed", func(a *Artifact) *Finding {
			extensions := matchingExtensions(a, OIDMTCTlogPrefixURL)
			if len(extensions) != 1 {
				return nil
			}
			if _, ok := parseMTCTlogPrefixURL(extensions[0].Value); !ok {
				return errorFinding("tbsCertificate.extensions.mtcTlogPrefixURL", "mtc-tlog prefix URL extension is not an exact DER IA5String")
			}
			return nil
		}),
		mtcTlogRule("e_mtc_tlog_prefix_url_invalid", func(a *Artifact) *Finding {
			extensions := matchingExtensions(a, OIDMTCTlogPrefixURL)
			if len(extensions) != 1 {
				return nil
			}
			prefix, ok := parseMTCTlogPrefixURL(extensions[0].Value)
			if ok && !validMTCTlogPrefixURL(prefix) {
				return errorFinding("tbsCertificate.extensions.mtcTlogPrefixURL", "mtc-tlog prefix URL is not a usable absolute HTTP or HTTPS URL")
			}
			return nil
		}),
		mtcTlogRule("e_mtc_tlog_log_hash_not_sha256", func(a *Artifact) *Finding {
			if a.CAParameters != nil && !a.CAParameters.LogHash.Algorithm.Equal(OIDSHA256) {
				return errorFinding("tbsCertificate.extensions.mtcCertificationAuthority.logHash", "mtc-tlog CA log hash algorithm is not SHA-256")
			}
			return nil
		}),
	}
}

func mtcTlogRule(code string, evaluate func(*Artifact) *Finding) Rule {
	return Rule{Code: code, Source: mtcTlogSource, Section: mtcTlogSection, Kinds: caKinds, InputKinds: bothInputKinds, Evaluate: evaluate}
}

func parseMTCTlogPrefixURL(input []byte) (string, bool) {
	value, err := parseExactDER(input)
	if err != nil || expectDER(value, classUniversal, asn1.TagIA5String, false, "mtcTlogPrefixURL") != nil {
		return "", false
	}
	for _, character := range value.contents {
		if character > 0x7f {
			return "", false
		}
	}
	return string(value.contents), true
}

func validMTCTlogPrefixURL(input string) bool {
	parsed, err := url.Parse(input)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}
