package request

import (
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
	"github.com/pkimetal/pkimetal/utils"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"
)

type tbsCertificatePartial struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
}

func (ri *RequestInfo) parseCertificateInput() (cert *x509.Certificate, err error) {
	if ri.b64Input == nil {
		return nil, fmt.Errorf("no certificate provided")
	}

	var inputKind mtc.InputKind
	switch ri.endpoint {
	case ENDPOINT_LINTTBSCERT:
		inputKind = mtc.InputTBSCertificate
		ri.decodedInput, err = utils.DecodePEMOrBase64(ri.b64Input, "TBS CERTIFICATE")
		if err != nil {
			ri.decodedInput, err = utils.DecodePEMOrBase64(ri.b64Input, "CERTIFICATE")
		}
	case ENDPOINT_LINTCERT:
		inputKind = mtc.InputCertificate
		ri.decodedInput, err = utils.DecodePEMOrBase64(ri.b64Input, "CERTIFICATE")
	default:
		return nil, fmt.Errorf("invalid endpoint for certificate input")
	}
	if err != nil {
		return nil, err
	}

	processed, cert, artifact, legacyErr, err := parseCertificateBytesWithLegacyError(ri.decodedInput, inputKind, x509.ParseCertificate)
	ri.mtcArtifact = artifact
	ri.legacyCertErr = legacyErr
	if processed != nil {
		ri.decodedInput = processed
		// Preserve the existing normalized representation for linter fanout.
		ri.b64Input = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: processed,
		})
	}
	return
}

func parseCertificateBytes(decoded []byte, inputKind mtc.InputKind, parseLegacy func([]byte) (*x509.Certificate, error)) (processed []byte, cert *x509.Certificate, artifact *mtc.Artifact, err error) {
	processed, cert, artifact, _, err = parseCertificateBytesWithLegacyError(decoded, inputKind, parseLegacy)
	return
}

func parseCertificateBytesWithLegacyError(decoded []byte, inputKind mtc.InputKind, parseLegacy func([]byte) (*x509.Certificate, error)) (processed []byte, cert *x509.Certificate, artifact *mtc.Artifact, legacyErr error, err error) {
	artifact, mtcErr := mtc.Parse(decoded, inputKind)
	if mtcErr == nil {
		legacyInput := append([]byte(nil), decoded...)
		if inputKind == mtc.InputTBSCertificate {
			if legacyInput, err = makeDummyCertificateBytes(decoded); err != nil {
				return decoded, nil, artifact, err, nil
			}
		}
		if legacyCert, parseErr := parseLegacyCertificate(legacyInput, parseLegacy); parseErr == nil {
			cert = legacyCert
		} else {
			legacyErr = parseErr
		}
		return decoded, cert, artifact, legacyErr, nil
	}

	processed = decoded
	if inputKind == mtc.InputTBSCertificate {
		if processed, err = makeDummyCertificateBytes(decoded); err != nil {
			return nil, nil, nil, nil, err
		}
	} else if inputKind != mtc.InputCertificate {
		return nil, nil, nil, nil, fmt.Errorf("unsupported certificate input kind %d", inputKind)
	}

	cert, err = parseLegacyCertificate(processed, parseLegacy)
	return processed, cert, nil, nil, err
}

func (ri *RequestInfo) deferredCertificateInputError(profileName string) error {
	if ri.legacyCertErr == nil {
		return nil
	}
	for profileID, profile := range linter.AllProfiles {
		if profile.Name == profileName && linter.IsMTCProfile(profileID) {
			return nil
		}
	}
	return ri.legacyCertErr
}

func parseLegacyCertificate(input []byte, parseLegacy func([]byte) (*x509.Certificate, error)) (cert *x509.Certificate, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Recovered from panic while parsing certificate: %v", r)
		}
	}()
	return parseLegacy(input)
}

func (ri *RequestInfo) makeDummyCertificate() error {
	var err error
	ri.decodedInput, err = makeDummyCertificateBytes(ri.decodedInput)
	return err
}

func makeDummyCertificateBytes(decoded []byte) ([]byte, error) {
	// Decode enough of the TBSCertificate to discover the signature algorithm.
	var tbs tbsCertificatePartial
	var err error
	if _, err = asn1.Unmarshal(decoded, &tbs); err != nil {
		return nil, err
	}

	// Wrap the TBSCertificate in a dummy signature.
	return dummySign(decoded, tbs.SignatureAlgorithm)
}
