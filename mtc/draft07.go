package mtc

const draft07Source = "draft-ietf-plants-merkle-tree-certs-07"
const trustAnchor06Source = "draft-ietf-tls-trust-anchor-ids-06"

var draft07Rules = append(buildDraftRules("07"), Rule{
	Code: "e_mtc_log_id_too_long", Source: draft07Source, Section: "5.2 and 7.2; TAI-06 4",
	Kinds: subscriberKinds, InputKinds: bothInputKinds, Evaluate: func(a *Artifact) *Finding {
		logNumber, _, ok := SplitSerial(a.SerialNumber)
		if !ok || len(a.IssuerCAID) == 0 {
			return nil
		}
		// Log ID is CA ID followed by zero and the canonical base-128 N component.
		length := len(a.IssuerCAID) + 2
		for n := logNumber; n >= 128; n >>= 7 {
			length++
		}
		if length > 32 {
			return errorFinding("tbsCertificate.issuer,serialNumber", "Serial-derived Log ID exceeds the TAI-06 32-byte limit")
		}
		return nil
	},
})

func LintDraft07ForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	return lintModernDraftForKind(artifact, expected, "07", draft07Source, draft07Rules)
}
