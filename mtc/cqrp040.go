package mtc

import "sort"

const cqrp040Source = "CQRP v0.4.0"

// LintCQRP040 evaluates the current CQRP v0.4.0 profile. The v0.3 evaluator
// remains available for historical artifacts and compatibility callers.
func LintCQRP040(artifact *Artifact) []Finding {
	return LintCQRP040ForKind(artifact, artifactKind(artifact))
}

// LintCQRP040ForKind evaluates CQRP v0.4.0 in an explicit profile context.
func LintCQRP040ForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	if artifact == nil || expected != ArtifactCA && expected != ArtifactSubscriber {
		return nil
	}
	findings := LintCQRP030ForKind(artifact, expected)
	filtered := findings[:0]
	for _, finding := range findings {
		// v0.4.0 trusts logs 1 through 5. v0.3.0's rule only reports values
		// above 4, so discard the newly permitted log 5 finding.
		if finding.Code == "e_cqrp_subscriber_log_number_not_trusted" && expected == ArtifactSubscriber {
			logNumber, _, ok := SplitSerial(artifact.SerialNumber)
			if ok && logNumber == 5 {
				continue
			}
		}
		if finding.Source == cqrp030Source {
			finding.Source = cqrp040Source
		}
		filtered = append(filtered, finding)
	}
	if expected == ArtifactCA {
		if finding := cqrp040CaKeyUsageFinding(artifact); finding != nil {
			filtered = append(filtered, *finding)
		}
		if finding := cqrp040CaKeyCertSignFinding(artifact); finding != nil {
			filtered = append(filtered, *finding)
		}
	}
	sortFindings(filtered)
	return filtered
}

// CQRP040RuleCodes returns the v0.4.0 rule codes, including the v0.4-specific
// CA cRLSign requirement.
func CQRP040RuleCodes() []string {
	codes := append([]string(nil), CQRP030RuleCodes()...)
	codes = append(codes, "e_cqrp_ca_key_usage_missing_crl_sign", "e_cqrp_ca_key_usage_missing_key_cert_sign")
	sort.Strings(codes)
	return codes
}

func cqrp040CaKeyCertSignFinding(artifact *Artifact) *Finding {
	extensions := matchingExtensions(artifact, oidKeyUsage)
	if len(extensions) != 1 {
		return nil
	}
	usage, ok := parseKeyUsage(extensions[0].Value)
	if ok && usage&0x0400 == 0 {
		return &Finding{Code: "e_cqrp_ca_key_usage_missing_key_cert_sign", Field: "tbsCertificate.extensions.keyUsage", Message: "CA key usage does not include keyCertSign", Source: cqrp040Source, Section: "2.4.3.1", Severity: Error}
	}
	return nil
}

func cqrp040CaKeyUsageFinding(artifact *Artifact) *Finding {
	extensions := matchingExtensions(artifact, oidKeyUsage)
	if len(extensions) == 0 {
		return &Finding{Code: "e_cqrp_ca_key_usage_missing_crl_sign", Field: "tbsCertificate.extensions.keyUsage", Message: "CA key usage extension is missing; cRLSign is required", Source: cqrp040Source, Section: "2.4.3.1", Severity: Error}
	}
	if len(extensions) != 1 {
		return nil
	}
	usage, ok := parseKeyUsage(extensions[0].Value)
	if !ok || usage&0x0200 == 0 {
		return &Finding{Code: "e_cqrp_ca_key_usage_missing_crl_sign", Field: "tbsCertificate.extensions.keyUsage", Message: "CA key usage is malformed or does not include cRLSign", Source: cqrp040Source, Section: "2.4.3.1", Severity: Error}
	}
	return nil
}

func artifactKind(artifact *Artifact) ArtifactKind {
	if artifact == nil {
		return ArtifactUnknown
	}
	return artifact.Kind
}
