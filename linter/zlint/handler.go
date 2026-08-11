package zlint

import (
	"context"
	"fmt"
	"slices"

	"github.com/pkimetal/pkimetal/config"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/logger"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"go.uber.org/zap"

	"golang.org/x/crypto/ocsp"
)

type Zlint struct{}

var (
	defaultRegistry                lint.Registry
	cabforumTLSSubordinateRegistry lint.Registry
	cabforumTLSLeafRegistry        lint.Registry
	cabforumTLSArlRegistry         lint.Registry
	notCabforumRegistry            lint.Registry
	mtcNonCABFRegistry             lint.Registry
	cqrpMTCLeafRegistry            lint.Registry
)

func zlintApplicable(req *linter.LintingRequest) (bool, string) {
	if req == nil {
		return false, ""
	}
	if linter.IsMTCProfile(req.ProfileId) && req.Cert == nil {
		return false, "zcrypto could not safely parse this MTC artifact"
	}
	return true, ""
}

func init() {
	// Register zlint.
	(&linter.Linter{
		Name:         "zlint",
		Version:      linter.GetPackageVersion("github.com/zmap/zlint"),
		Url:          "https://github.com/zmap/zlint",
		Supported:    []linter.ProfileId{linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA, linter.CQRP_MTC_SUBSCRIBER},
		Unsupported:  nil,
		Applicable:   zlintApplicable,
		NumInstances: config.Config.Linter.Zlint.NumGoroutines,
		Interface:    func() linter.LinterInterface { return &Zlint{} },
	}).Register()

	defaultRegistry = lint.GlobalRegistry()

	// RFC5280's "MUST mark this extension as critical" for Name Constraints in intermediate certificates is superseded by the TLS BRs' "MAY be marked non‐critical".
	var err error
	if cabforumTLSSubordinateRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeNames: []string{"e_ext_name_constraints_not_critical"},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for BR/EVG TLS Server subordinate certificates", zap.Error(err))
	}

	// RFC5280's "SHOULD be present" for SKI in end-entity certificates is superseded by the TLS BRs' "NOT RECOMMENDED".
	if cabforumTLSLeafRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeNames: []string{"w_ext_subject_key_identifier_missing_sub_cert"},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for BR/EVG TLS Server leaf certificates", zap.Error(err))
	}

	if cabforumTLSArlRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		IncludeNames: defaultRegistry.Names(),
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for BR TLS Server authority revocation lists", zap.Error(err))
	}
	arlConfig, err := lint.NewConfigFromString(`
[e_crl_next_update_invalid]
SubscriberCRL = false
`)
	if err != nil {
		logger.Logger.Fatal("Failed to configure zlint CRL nextUpdate lint for BR TLS Server authority revocation lists", zap.Error(err))
	}
	cabforumTLSArlRegistry.SetConfiguration(arlConfig)

	// Filter out CABForum lints for non-CABForum profiles.
	if notCabforumRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeSources: []lint.LintSource{
			lint.CABFBaselineRequirements,
			lint.CABFEVGuidelines,
			lint.CABFSMIMEBaselineRequirements,
		},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for disabling CABForum lints", zap.Error(err))
	}

	if mtcNonCABFRegistry, err = defaultRegistry.Filter(lint.FilterOptions{
		ExcludeSources: []lint.LintSource{
			lint.CABFBaselineRequirements,
			lint.CABFEVGuidelines,
			lint.CABFSMIMEBaselineRequirements,
			lint.CABFCSBaselineRequirements,
		},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for MTC certificates", zap.Error(err))
	}

	if cqrpMTCLeafRegistry, err = cabforumTLSLeafRegistry.Filter(lint.FilterOptions{
		ExcludeNames: []string{
			"e_signature_algorithm_not_supported",
			"e_public_key_type_not_allowed",
			"e_algorithm_identifier_improper_encoding",
			"w_ct_sct_policy_count_unsatisfied",
		},
	}); err != nil {
		logger.Logger.Fatal("Failed to configure filtered zlint registry for CQRP MTC subscriber certificates", zap.Error(err))
	}
}

func (l *Zlint) StartInstance() (useHandleRequest bool, directory, cmd string, args []string) {
	return true, "", "", nil // zlint is run in Goroutine(s) in the pkimetal process, so there are no external backends.
}

func (l *Zlint) StopInstance(lin *linter.LinterInstance) {
}

func lintCert(lreq *linter.LintingRequest, registry *lint.Registry) []linter.LintingResult {
	var lres []linter.LintingResult
	zlintResultSet := zlint.LintCertificateEx(lreq.Cert, *registry)
	for k, v := range zlintResultSet.Results {
		certificateLint := defaultRegistry.CertificateLints().ByName(k)
		lresult := linter.LintingResult{
			Finding: certificateLint.Description,
			Code:    certificateLint.Name,
		}
		switch v.Status {
		case lint.Notice:
			lresult.Severity = linter.SEVERITY_NOTICE
		case lint.Warn:
			lresult.Severity = linter.SEVERITY_WARNING
		case lint.Error:
			lresult.Severity = linter.SEVERITY_ERROR
		case lint.Fatal:
			lresult.Severity = linter.SEVERITY_FATAL
		default:
			continue
		}
		lres = append(lres, lresult)
	}
	return lres
}

func lintCRL(lreq *linter.LintingRequest, registry *lint.Registry) []linter.LintingResult {
	var lres []linter.LintingResult
	if crl, err := x509.ParseRevocationList(lreq.DecodedInput); err != nil {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_FATAL,
			Finding:  fmt.Sprintf("Could not parse CRL: %v", err),
		})
	} else {
		zlintResultSet := zlint.LintRevocationListEx(crl, *registry)
		for k, v := range zlintResultSet.Results {
			crlLint := defaultRegistry.RevocationListLints().ByName(k)
			lresult := linter.LintingResult{
				Finding: crlLint.Description,
				Code:    crlLint.Name,
			}
			switch v.Status {
			case lint.Notice:
				lresult.Severity = linter.SEVERITY_NOTICE
			case lint.Warn:
				lresult.Severity = linter.SEVERITY_WARNING
			case lint.Error:
				lresult.Severity = linter.SEVERITY_ERROR
			case lint.Fatal:
				lresult.Severity = linter.SEVERITY_FATAL
			default:
				continue
			}
			lres = append(lres, lresult)
		}
	}
	return lres
}

func lintOCSPResponse(lreq *linter.LintingRequest, registry *lint.Registry) []linter.LintingResult {
	var lres []linter.LintingResult
	if ocspResponse, err := ocsp.ParseResponse(lreq.DecodedInput, nil); err != nil {
		lres = append(lres, linter.LintingResult{
			Severity: linter.SEVERITY_FATAL,
			Finding:  fmt.Sprintf("Could not parse OCSP Response: %v", err),
		})
	} else {
		zlintResultSet := zlint.LintOcspResponseEx(ocspResponse, *registry)
		for k, v := range zlintResultSet.Results {
			ocspResponseLint := defaultRegistry.OcspResponseLints().ByName(k)
			lresult := linter.LintingResult{
				Finding: ocspResponseLint.Description,
				Code:    ocspResponseLint.Name,
			}
			switch v.Status {
			case lint.Notice:
				lresult.Severity = linter.SEVERITY_NOTICE
			case lint.Warn:
				lresult.Severity = linter.SEVERITY_WARNING
			case lint.Error:
				lresult.Severity = linter.SEVERITY_ERROR
			case lint.Fatal:
				lresult.Severity = linter.SEVERITY_FATAL
			default:
				continue
			}
			lres = append(lres, lresult)
		}
	}
	return lres
}

func registryForProfile(profile linter.ProfileId) lint.Registry {
	switch profile {
	case linter.CQRP_MTC_SUBSCRIBER:
		return cqrpMTCLeafRegistry
	case linter.MTC_CA, linter.MTC_SUBSCRIBER, linter.CQRP_MTC_CA:
		return mtcNonCABFRegistry
	}

	if slices.Contains(linter.TbrTevgLeafProfileIDs, profile) {
		return cabforumTLSLeafRegistry
	} else if slices.Contains(linter.TbrTevgCertificateProfileIDs, profile) {
		return cabforumTLSSubordinateRegistry
	} else if slices.Contains(linter.TbrArlProfileIDs, profile) {
		return cabforumTLSArlRegistry
	} else if slices.Contains(linter.NonCabforumProfileIDs, profile) {
		return notCabforumRegistry
	} else {
		return defaultRegistry
	}
}

func (l *Zlint) HandleRequest(ctx context.Context, lin *linter.LinterInstance, lreq *linter.LintingRequest) []linter.LintingResult {
	if lreq == nil || (linter.IsMTCProfile(lreq.ProfileId) && lreq.Cert == nil) {
		return nil
	}

	registry := registryForProfile(lreq.ProfileId)

	if slices.Contains(linter.OcspProfileIDs, lreq.ProfileId) {
		return lintOCSPResponse(lreq, &registry)
	} else if slices.Contains(linter.CrlProfileIDs, lreq.ProfileId) {
		return lintCRL(lreq, &registry)
	} else {
		return lintCert(lreq, &registry)
	}
}

func (l *Zlint) ProcessResult(lresult linter.LintingResult) linter.LintingResult {
	return lresult
}
