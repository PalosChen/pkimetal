package mtc

const draft06Source = "draft-ietf-plants-merkle-tree-certs-06"
const trustAnchor05Source = "draft-ietf-tls-trust-anchor-ids-05"

var draft06Rules = buildDraftRules("06")

func LintDraft06ForKind(artifact *Artifact, expected ArtifactKind) []Finding {
	if artifact == nil || expected != ArtifactCA && expected != ArtifactSubscriber {
		return nil
	}
	local := *artifact
	local.Kind = expected
	if expected == ArtifactSubscriber && local.InputKind == InputCertificate {
		local.Proof, local.ProofParseError = ParseProofForRevision(local.SignatureValue, "06")
		if local.RevisionError != nil {
			local.Proof = nil
			local.ProofParseError = local.RevisionError
		}
	}
	findings := runRules(&local, draft06Rules)
	findings = append(findings, runRules(&local, []Rule{
		{Code: "e_mtc_serial_index_outside_wire_domain", Source: draft06Source, Section: "5.2 and 6.2", Kinds: subscriberKinds, InputKinds: bothInputKinds, Evaluate: func(a *Artifact) *Finding {
			_, index, ok := SplitSerial(a.SerialNumber)
			if ok && index == maxUint48 {
				return errorFinding("tbsCertificate.serialNumber", "Entry index exceeds the maximum issuance-log index 2^48-2")
			}
			return nil
		}},
		{Code: "e_mtc_entry_too_large", Source: draft06Source, Section: "5.2.1", Kinds: subscriberKinds, InputKinds: bothInputKinds, Evaluate: func(a *Artifact) *Finding {
			if size, ok := certificateLogEntrySize(a); ok && size > 65535 {
				return errorFinding("tbsCertificate", "Reconstructed MTCLogEntry exceeds 65535 bytes")
			}
			return nil
		}},
	})...)
	if artifact.Kind != expected {
		findings = append(findings, Finding{Code: "e_mtc_profile_artifact_mismatch", Field: "profile", Message: "Selected draft-06 profile does not match artifact kind", Source: draft06Source, Section: "5.5 and 6.2", Severity: Error})
	}
	if artifact.Revision != "06" || artifact.RevisionError != nil {
		findings = append(findings, Finding{Code: "e_mtc_profile_revision_mismatch", Field: "profile", Message: "Selected draft-06 profile requires unambiguous draft-06 identity", Source: draft06Source, Section: "5.1 and 5.5", Severity: Error})
	}
	sortFindings(findings)
	return findings
}

func certificateLogEntrySize(a *Artifact) (int, bool) {
	root, _, err := parseDER(a.RawTBS)
	if err != nil {
		return 0, false
	}
	contents := root.contents
	size := 4 // vector16 extensions length and entry type
	if a.InputKind == InputCertificate {
		if !proofAvailable(a) {
			return 0, false
		}
		for _, ext := range a.Proof.Extensions {
			size += 4 + len(ext.Data)
		}
	}
	field := 0
	for len(contents) > 0 {
		value, err := takeDER(&contents, "TBS field")
		if err != nil {
			return 0, false
		}
		if field == 0 && value.class == classContext && value.tag == 0 {
			size += len(value.raw)
			continue
		}
		// Serial and signature are omitted; SPKI becomes its algorithm and SHA-256 OCTET STRING.
		if field == 5 {
			size += len(a.SubjectPublicKey.Algorithm.Raw) + 34
		} else if field != 0 && field != 1 {
			size += len(value.raw)
		}
		field++
	}
	return size, true
}
