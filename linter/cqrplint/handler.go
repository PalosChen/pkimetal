package cqrplint

import (
	"context"
	"fmt"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

type CQRPLint struct{}

func init() {
	(&linter.Linter{
		Name:         "cqrplint",
		Version:      "v0.2.0",
		Url:          "../../doc/superpowers/specs/2026-08-11-mtc-pkimetal-design.md#source-baselines",
		Unsupported:  unsupportedProfiles(linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER),
		NumInstances: config.Config.Linter.Cqrplint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &CQRPLint{} },
	}).Register()
}

func (l *CQRPLint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil
}

func (l *CQRPLint) StopInstance(_ *linter.LinterInstance) {}

func (l *CQRPLint) HandleRequest(_ context.Context, _ *linter.LinterInstance, req *linter.LintingRequest) []linter.LintingResult {
	if req == nil || req.MTCArtifact == nil {
		return nil
	}

	var expected mtc.ArtifactKind
	switch req.ProfileId {
	case linter.CQRP_MTC_CA:
		expected = mtc.ArtifactCA
	case linter.CQRP_MTC_SUBSCRIBER:
		expected = mtc.ArtifactSubscriber
	default:
		return nil
	}
	return convertFindings(mtc.LintCQRP020ForKind(req.MTCArtifact, expected))
}

func (l *CQRPLint) ProcessResult(result linter.LintingResult) linter.LintingResult {
	return result
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
