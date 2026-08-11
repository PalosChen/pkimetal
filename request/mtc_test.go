package request

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
	"github.com/zmap/zcrypto/x509"
)

func TestMTCProfileMetadataAndClassification(t *testing.T) {
	tests := []struct {
		id          linter.ProfileId
		name        string
		source      string
		description string
	}{
		{linter.MTC_CA, "mtc_ca", "draft-ietf-plants-merkle-tree-certs-05", "MTC Certification Authority Certificate"},
		{linter.MTC_SUBSCRIBER, "mtc_subscriber", "draft-ietf-plants-merkle-tree-certs-05", "MTC Subscriber Certificate"},
		{linter.CQRP_MTC_CA, "cqrp_mtc_ca", "CQRP v0.2.0", "CQRP MTC CA Cosigning Certificate"},
		{linter.CQRP_MTC_SUBSCRIBER, "cqrp_mtc_subscriber", "CQRP v0.2.0", "CQRP MTC Subscriber TLS Certificate"},
	}

	if linter.MTC_CA != linter.BIMIGROUP_LEAF_VERIFIEDMARK_PRECERTIFICATE+1 {
		t.Fatalf("MTC profile IDs were not appended: MTC_CA = %d", linter.MTC_CA)
	}
	for i, tc := range tests {
		if tc.id != linter.MTC_CA+linter.ProfileId(i) {
			t.Fatalf("profile %s ID = %d, want %d", tc.name, tc.id, linter.MTC_CA+linter.ProfileId(i))
		}
		if got := linter.AllProfiles[tc.id]; got.Name != tc.name || got.Source != tc.source || got.Description != tc.description {
			t.Errorf("profile %s metadata = %#v", tc.name, got)
		}
		if slices.Contains(linter.NonCertificateProfileIDs, tc.id) || slices.Contains(linter.CrlProfileIDs, tc.id) || slices.Contains(linter.OcspProfileIDs, tc.id) {
			t.Errorf("profile %s classified as a non-certificate profile", tc.name)
		}
	}
}

func TestParseCertificateBytesRecognizedMTCRetainsLegacyCertificateWhenAvailable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		decoded   []byte
		inputKind mtc.InputKind
		wantKind  mtc.ArtifactKind
	}{
		{"certificate CA", mtctest.Certificate(mtctest.ValidCATemplate()), mtc.InputCertificate, mtc.ArtifactCA},
		{"certificate subscriber", mtctest.Certificate(mtctest.ValidSubscriberTemplate()), mtc.InputCertificate, mtc.ArtifactSubscriber},
		{"TBS CA", mtctest.TBSCertificate(mtctest.ValidCATemplate()), mtc.InputTBSCertificate, mtc.ArtifactCA},
		{"TBS subscriber", mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), mtc.InputTBSCertificate, mtc.ArtifactSubscriber},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantCert := &x509.Certificate{}
			calls := 0
			processed, cert, artifact, err := parseCertificateBytes(tc.decoded, tc.inputKind, func(input []byte) (*x509.Certificate, error) {
				calls++
				if tc.inputKind == mtc.InputCertificate && !bytes.Equal(input, tc.decoded) {
					t.Fatal("legacy parser received modified complete certificate")
				}
				if tc.inputKind == mtc.InputTBSCertificate && bytes.Equal(input, tc.decoded) {
					t.Fatal("legacy parser received an unwrapped TBS certificate")
				}
				return wantCert, nil
			})
			if err != nil {
				t.Fatalf("parseCertificateBytes() error = %v", err)
			}
			if calls != 1 || cert != wantCert {
				t.Fatalf("legacy calls/certificate = %d/%#v", calls, cert)
			}
			if artifact == nil || artifact.Kind != tc.wantKind {
				t.Fatalf("artifact = %#v, want kind %v", artifact, tc.wantKind)
			}
			if !bytes.Equal(processed, tc.decoded) {
				t.Fatal("recognized MTC bytes were modified")
			}
			processed[0] ^= 0xff
			if artifact.Raw[0] == processed[0] {
				t.Fatal("artifact raw bytes alias the returned request bytes")
			}
		})
	}
}

func TestParseCertificateBytesRecognizedMTCIgnoresLegacyFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		decoded   []byte
		inputKind mtc.InputKind
		panic     bool
	}{
		{"certificate error", mtctest.Certificate(mtctest.ValidCATemplate()), mtc.InputCertificate, false},
		{"certificate panic", mtctest.Certificate(mtctest.ValidSubscriberTemplate()), mtc.InputCertificate, true},
		{"TBS error", mtctest.TBSCertificate(mtctest.ValidCATemplate()), mtc.InputTBSCertificate, false},
		{"TBS panic", mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), mtc.InputTBSCertificate, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			processed, cert, artifact, err := parseCertificateBytes(tc.decoded, tc.inputKind, func(input []byte) (*x509.Certificate, error) {
				calls++
				if tc.inputKind == mtc.InputTBSCertificate && bytes.Equal(input, tc.decoded) {
					t.Fatal("legacy parser received an unwrapped TBS certificate")
				}
				if tc.panic {
					panic("unsupported MTC algorithm")
				}
				return &x509.Certificate{}, errors.New("unsupported MTC algorithm")
			})
			if err != nil {
				t.Fatalf("parseCertificateBytes() error = %v", err)
			}
			if calls != 1 || cert != nil {
				t.Fatalf("legacy calls/certificate = %d/%#v", calls, cert)
			}
			if artifact == nil || (artifact.Kind != mtc.ArtifactCA && artifact.Kind != mtc.ArtifactSubscriber) {
				t.Fatalf("artifact = %#v", artifact)
			}
			if !bytes.Equal(processed, tc.decoded) {
				t.Fatal("recognized MTC bytes were modified after legacy failure")
			}
		})
	}
}

func TestParseCertificateBytesRecognizedMTCLegacyParserCannotMutateRequestBytes(t *testing.T) {
	decoded := mtctest.Certificate(mtctest.ValidCATemplate())
	want := append([]byte(nil), decoded...)

	processed, _, artifact, err := parseCertificateBytes(decoded, mtc.InputCertificate, func(input []byte) (*x509.Certificate, error) {
		input[0] ^= 0xff
		return &x509.Certificate{}, nil
	})
	if err != nil {
		t.Fatalf("parseCertificateBytes() error = %v", err)
	}
	if !bytes.Equal(decoded, want) || !bytes.Equal(processed, want) || artifact == nil || !bytes.Equal(artifact.Raw, want) {
		t.Fatal("best-effort legacy parser mutated recognized MTC bytes")
	}
}

func TestParseCertificateBytesRetainsMalformedSubscriberProof(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.Signature = mtctest.MalformedProofBytes()
	decoded := mtctest.Certificate(tpl)

	calls := 0
	processed, cert, artifact, err := parseCertificateBytes(decoded, mtc.InputCertificate, func([]byte) (*x509.Certificate, error) {
		calls++
		return nil, errors.New("unsupported ML-DSA")
	})
	if err != nil {
		t.Fatalf("parseCertificateBytes() error = %v", err)
	}
	if calls != 1 || cert != nil || artifact == nil || artifact.Kind != mtc.ArtifactSubscriber || artifact.ProofParseError == nil {
		t.Fatalf("certificate/artifact = %#v/%#v", cert, artifact)
	}
	if !bytes.Equal(processed, decoded) {
		t.Fatal("malformed-proof MTC bytes were modified")
	}
}

func TestParseCertificateBytesUnknownUsesLegacyParser(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDSHA256}
	tpl.OuterSignature = tpl.TBSSignature
	tpl.Issuer = []byte{0x30, 0x00}
	decoded := mtctest.Certificate(tpl)
	wantCert := &x509.Certificate{}
	calls := 0

	processed, cert, artifact, err := parseCertificateBytes(decoded, mtc.InputCertificate, func(input []byte) (*x509.Certificate, error) {
		calls++
		if !bytes.Equal(input, decoded) {
			t.Fatal("legacy parser received modified complete certificate")
		}
		return wantCert, nil
	})
	if err != nil {
		t.Fatalf("parseCertificateBytes() error = %v", err)
	}
	if calls != 1 || cert != wantCert || artifact != nil || !bytes.Equal(processed, decoded) {
		t.Fatalf("calls/certificate/artifact = %d/%#v/%#v", calls, cert, artifact)
	}
}

func TestParseCertificateBytesLegacyErrorAndPanic(t *testing.T) {
	input := []byte{0x30, 0x00}
	wantErr := errors.New("legacy parse failed")
	_, _, artifact, err := parseCertificateBytes(input, mtc.InputCertificate, func([]byte) (*x509.Certificate, error) {
		return nil, wantErr
	})
	if artifact != nil || !errors.Is(err, wantErr) {
		t.Fatalf("artifact/error = %#v/%v, want nil/%v", artifact, err, wantErr)
	}

	_, _, artifact, err = parseCertificateBytes(input, mtc.InputCertificate, func([]byte) (*x509.Certificate, error) {
		panic("legacy panic")
	})
	if artifact != nil || err == nil || err.Error() != "Recovered from panic while parsing certificate: legacy panic" {
		t.Fatalf("artifact/error = %#v/%v", artifact, err)
	}
}

func TestParseCertificateBytesUnknownTBSUsesLegacyDummyCertificate(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.TBSSignature = mtctest.Algorithm{OID: mtctest.OIDSHA256}
	tpl.Issuer = []byte{0x30, 0x00}
	decoded := mtctest.TBSCertificate(tpl)
	wantCert := &x509.Certificate{}

	processed, cert, artifact, err := parseCertificateBytes(decoded, mtc.InputTBSCertificate, func(input []byte) (*x509.Certificate, error) {
		if bytes.Equal(input, decoded) {
			t.Fatal("legacy parser received an unwrapped TBS certificate")
		}
		return wantCert, nil
	})
	if err != nil {
		t.Fatalf("parseCertificateBytes() error = %v", err)
	}
	if cert != wantCert || artifact != nil || bytes.Equal(processed, decoded) {
		t.Fatalf("certificate/artifact/processed = %#v/%#v/%x", cert, artifact, processed)
	}
}

func TestMTCRequestParsingAndProfileSelection(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    Endpoint
		decoded     []byte
		profileName string
		wantProfile linter.ProfileId
		wantKind    mtc.ArtifactKind
	}{
		{"auto CA", ENDPOINT_LINTCERT, mtctest.Certificate(mtctest.ValidCATemplate()), "", linter.MTC_CA, mtc.ArtifactCA},
		{"auto subscriber", ENDPOINT_LINTCERT, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), "autodetect", linter.MTC_SUBSCRIBER, mtc.ArtifactSubscriber},
		{"auto CQRP fixture remains draft", ENDPOINT_LINTCERT, mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate()), "autodetect", linter.MTC_SUBSCRIBER, mtc.ArtifactSubscriber},
		{"auto TBS subscriber", ENDPOINT_LINTTBSCERT, mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), "", linter.MTC_SUBSCRIBER, mtc.ArtifactSubscriber},
		{"explicit CQRP retained", ENDPOINT_LINTCERT, mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate()), "cqrp_mtc_subscriber", linter.CQRP_MTC_SUBSCRIBER, mtc.ArtifactSubscriber},
		{"explicit mismatch retained", ENDPOINT_LINTCERT, mtctest.Certificate(mtctest.ValidCATemplate()), "mtc_subscriber", linter.MTC_SUBSCRIBER, mtc.ArtifactCA},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ri := RequestInfo{
				endpoint: tc.endpoint,
				b64Input: []byte(base64.StdEncoding.EncodeToString(tc.decoded)),
			}
			cert, err := ri.parseCertificateInput()
			if err != nil {
				t.Fatalf("parseCertificateInput() error = %v", err)
			}
			ri.cert = cert
			if ri.mtcArtifact == nil || ri.mtcArtifact.Kind != tc.wantKind {
				t.Fatalf("MTC artifact = %#v, want kind %v", ri.mtcArtifact, tc.wantKind)
			}
			if !ri.GetProfile(tc.profileName) || ri.profileId != tc.wantProfile {
				t.Fatalf("profile = %v, want %v", ri.profileId, tc.wantProfile)
			}
			if !bytes.Equal(ri.decodedInput, tc.decoded) {
				t.Fatal("request parsing modified recognized MTC input")
			}
			block, rest := pem.Decode(ri.b64Input)
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || !bytes.Equal(block.Bytes, tc.decoded) {
				t.Fatalf("normalized input = %q", ri.b64Input)
			}
		})
	}
}

func TestAllExplicitMTCProfileNamesAreAccepted(t *testing.T) {
	for _, name := range []string{"mtc_ca", "mtc_subscriber", "cqrp_mtc_ca", "cqrp_mtc_subscriber"} {
		ri := RequestInfo{}
		if !ri.GetProfile(name) {
			t.Errorf("profile %q was rejected", name)
		}
	}
}

func TestOrdinaryCertificateStillUsesLegacyParsingAndAutodetection(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ordinary root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              stdx509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	decoded, err := stdx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ri := RequestInfo{
		endpoint: ENDPOINT_LINTCERT,
		b64Input: []byte(base64.StdEncoding.EncodeToString(decoded)),
	}
	ri.cert, err = ri.parseCertificateInput()
	if err != nil {
		t.Fatalf("parseCertificateInput() error = %v", err)
	}
	if ri.cert == nil || ri.mtcArtifact != nil {
		t.Fatalf("legacy certificate/MTC artifact = %#v/%#v", ri.cert, ri.mtcArtifact)
	}
	if !ri.GetProfile("autodetect") || ri.profileId != linter.RFC5280_ROOT {
		t.Fatalf("profile = %v, want %v", ri.profileId, linter.RFC5280_ROOT)
	}
}

func TestMalformedMTCProofPOSTSucceedsAndDispatchesArtifact(t *testing.T) {
	tpl := mtctest.ValidSubscriberTemplate()
	tpl.Signature = mtctest.MalformedProofBytes()
	decoded := mtctest.Certificate(tpl)
	request := postAndCaptureMTCRequest(t, decoded, "mtc_ca")

	if request.ProfileId != linter.MTC_CA {
		t.Fatalf("explicit mismatch profile = %v, want %v", request.ProfileId, linter.MTC_CA)
	}
	if request.MTCArtifact == nil || request.MTCArtifact.Kind != mtc.ArtifactSubscriber || request.MTCArtifact.ProofParseError == nil {
		t.Fatalf("dispatched certificate/artifact = %#v/%#v", request.Cert, request.MTCArtifact)
	}
	if !bytes.Equal(request.DecodedInput, decoded) {
		t.Fatal("POST dispatch modified malformed-proof MTC bytes")
	}
}

func TestMTCPOSTDispatchesAvailableLegacyCertificate(t *testing.T) {
	decoded := legacyCompatibleMTCCA(t)
	request := postAndCaptureMTCRequest(t, decoded, "mtc_ca")

	if request.Cert == nil || request.MTCArtifact == nil || request.MTCArtifact.Kind != mtc.ArtifactCA {
		t.Fatalf("dispatched certificate/artifact = %#v/%#v", request.Cert, request.MTCArtifact)
	}
	if !bytes.Equal(request.DecodedInput, decoded) || !bytes.Equal(request.Cert.Raw, decoded) {
		t.Fatal("POST dispatch did not retain the original complete certificate bytes")
	}
}

func legacyCompatibleMTCCA(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	sha256WithRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	nullParameters := []byte{0x05, 0x00}
	tpl := mtctest.ValidCATemplate()
	tpl.TBSSignature = mtctest.Algorithm{OID: sha256WithRSA, ParametersPresent: true, Parameters: nullParameters}
	tpl.OuterSignature = tpl.TBSSignature
	tpl.SPKIAlgorithm = mtctest.Algorithm{OID: mtctest.OIDRSAEncryption, ParametersPresent: true, Parameters: nullParameters}
	tpl.SubjectPublicKey = stdx509.MarshalPKCS1PublicKey(&key.PublicKey)
	tpl.Signature = []byte{0x01}
	return mtctest.Certificate(tpl)
}

func postAndCaptureMTCRequest(t *testing.T, decoded []byte, profile string) linter.LintingRequest {
	t.Helper()

	originalLinters := linter.Linters
	t.Cleanup(func() { linter.Linters = originalLinters })
	reqChannel := make(chan linter.LintingRequest, 1)
	linter.Linters = linter.LinterSlice{{
		Name:         "capture",
		NumInstances: 1,
		ReqChannel:   reqChannel,
	}}
	dispatched := make(chan linter.LintingRequest, 1)
	go func() {
		request := <-reqChannel
		dispatched <- request
		request.RespChannel <- linter.LintingResult{
			LinterName: linter.PKIMETAL_NAME,
			Finding:    linter.PKIMETAL_ENDOFRESULTS,
		}
	}()

	form := url.Values{
		"b64cert": {base64.StdEncoding.EncodeToString(decoded)},
		"profile": {profile},
		"format":  {"json"},
	}
	listener := fasthttputil.NewInmemoryListener()
	t.Cleanup(func() { _ = listener.Close() })
	server := &fasthttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		POST(ctx, ENDPOINTSTRING_LINTCERT)
	}}
	go func() { _ = server.Serve(listener) }()
	client := &fasthttp.Client{Dial: func(string) (net.Conn, error) { return listener.Dial() }}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	t.Cleanup(func() {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	})
	req.SetRequestURI("http://pkimetal.test/lintcert")
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString(form.Encode())
	if err := client.DoTimeout(req, resp, 5*time.Second); err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode(), resp.Body())
	}
	return <-dispatched
}
