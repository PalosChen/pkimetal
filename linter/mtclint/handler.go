package mtclint

import (
	"context"
	"fmt"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

type MTCLint struct{}

func init() {
	(&linter.Linter{
		Name:         "mtclint",
		Version:      "draft-05",
		Url:          "https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-05",
		Unsupported:  unsupportedProfiles(linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER),
		NumInstances: config.Config.Linter.Mtclint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &MTCLint{} },
	}).Register()
}

func (l *MTCLint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil
}

func (l *MTCLint) StopInstance(_ *linter.LinterInstance) {}

func (l *MTCLint) HandleRequest(_ context.Context, _ *linter.LinterInstance, req *linter.LintingRequest) []linter.LintingResult {
	if req == nil {
		return nil
	}

	expected, profileName, ok := expectedKind(req.ProfileId)
	if !ok {
		return nil
	}

	var results []linter.LintingResult
	if req.MTCArtifact == nil || req.MTCArtifact.Kind != expected {
		results = append(results, linter.LintingResult{
			Finding:  fmt.Sprintf("Selected profile %q expects %s artifact; actual artifact kind is %s", profileName, artifactKindName(expected), actualArtifactKindName(req.MTCArtifact)),
			Field:    "profile",
			Code:     "e_mtc_profile_artifact_mismatch",
			Severity: linter.SEVERITY_ERROR,
		})
	}

	return append(results, convertFindings(mtc.LintDraft05ForKind(req.MTCArtifact, expected))...)
}

func (l *MTCLint) ProcessResult(result linter.LintingResult) linter.LintingResult {
	return result
}

func expectedKind(profile linter.ProfileId) (mtc.ArtifactKind, string, bool) {
	switch profile {
	case linter.MTC_CA:
		return mtc.ArtifactCA, "mtc_ca", true
	case linter.MTC_SUBSCRIBER:
		return mtc.ArtifactSubscriber, "mtc_subscriber", true
	case linter.CQRP_MTC_CA:
		return mtc.ArtifactCA, "cqrp_mtc_ca", true
	case linter.CQRP_MTC_SUBSCRIBER:
		return mtc.ArtifactSubscriber, "cqrp_mtc_subscriber", true
	default:
		return mtc.ArtifactUnknown, "", false
	}
}

func actualArtifactKindName(artifact *mtc.Artifact) string {
	if artifact == nil || artifact.Kind == mtc.ArtifactUnknown {
		return "unrecognized"
	}
	return artifactKindName(artifact.Kind)
}

func artifactKindName(kind mtc.ArtifactKind) string {
	switch kind {
	case mtc.ArtifactCA:
		return "ca"
	case mtc.ArtifactSubscriber:
		return "subscriber"
	default:
		return fmt.Sprintf("unrecognized (%d)", kind)
	}
}

func unsupportedProfiles(supported ...linter.ProfileId) []linter.ProfileId {
	supportedSet := make(map[linter.ProfileId]struct{}, len(supported))
	for _, profile := range supported {
		supportedSet[profile] = struct{}{}
	}
	unsupported := make([]linter.ProfileId, 0, len(linter.AllProfiles)-len(supportedSet))
	for profile := linter.ProfileId(0); profile < linter.ProfileId(len(linter.AllProfiles)); profile++ {
		if _, ok := supportedSet[profile]; !ok {
			unsupported = append(unsupported, profile)
		}
	}
	return unsupported
}

func convertFindings(findings []mtc.Finding) []linter.LintingResult {
	if len(findings) == 0 {
		return nil
	}
	results := make([]linter.LintingResult, 0, len(findings))
	for _, finding := range findings {
		results = append(results, linter.LintingResult{
			Finding:  fmt.Sprintf("[%s §%s] %s", finding.Source, finding.Section, finding.Message),
			Field:    finding.Field,
			Code:     finding.Code,
			Severity: severity(finding.Severity),
		})
	}
	return results
}

func severity(value mtc.Severity) linter.SeverityLevel {
	switch value {
	case mtc.Warning:
		return linter.SEVERITY_WARNING
	case mtc.Error:
		return linter.SEVERITY_ERROR
	case mtc.Bug:
		return linter.SEVERITY_BUG
	case mtc.Fatal:
		return linter.SEVERITY_FATAL
	default:
		return linter.SEVERITY_BUG
	}
}
