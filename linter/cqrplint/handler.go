package cqrplint

import (
	"context"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/linter/internal/mtcadapter"
	"github.com/pkimetal/pkimetal/mtc"
)

type CQRPLint struct{}

func init() {
	(&linter.Linter{
		Name:         "cqrplint",
		Version:      "v0.2.0",
		Url:          "https://github.com/pkimetal/pkimetal/blob/main/doc/superpowers/specs/2026-08-11-mtc-pkimetal-design.md#source-baselines",
		Supported:    []linter.ProfileId{linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER},
		Unsupported:  mtcadapter.UnsupportedProfiles(linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER),
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
	results := mtcadapter.ConvertFindings(mtc.LintCQRP020ForKind(req.MTCArtifact, expected))
	if req.ProfileId == linter.CQRP_MTC_SUBSCRIBER {
		results = append(results, mtcadapter.ConvertFindings(mtc.LintCABFTLSSubscriberForKind(req.MTCArtifact, expected))...)
	}
	return results
}

func (l *CQRPLint) ProcessResult(result linter.LintingResult) linter.LintingResult {
	return result
}
