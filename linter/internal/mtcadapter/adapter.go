package mtcadapter

import (
	"fmt"
	"slices"

	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

func UnsupportedProfiles(supported ...linter.ProfileId) []linter.ProfileId {
	supportedSet := make(map[linter.ProfileId]struct{}, len(supported))
	for _, profile := range supported {
		supportedSet[profile] = struct{}{}
	}
	unsupported := make([]linter.ProfileId, 0, len(linter.AllProfiles)-len(supportedSet))
	for profile := range linter.AllProfiles {
		if _, ok := supportedSet[profile]; !ok {
			unsupported = append(unsupported, profile)
		}
	}
	slices.Sort(unsupported)
	return unsupported
}

func ConvertFindings(findings []mtc.Finding) []linter.LintingResult {
	if len(findings) == 0 {
		return nil
	}
	results := make([]linter.LintingResult, 0, len(findings))
	for _, finding := range findings {
		results = append(results, linter.LintingResult{
			Finding:  fmt.Sprintf("[%s §%s] %s", finding.Source, finding.Section, finding.Message),
			Field:    finding.Field,
			Code:     finding.Code,
			Severity: ConvertSeverity(finding.Severity),
		})
	}
	return results
}

func ConvertSeverity(severity mtc.Severity) linter.SeverityLevel {
	switch severity {
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
