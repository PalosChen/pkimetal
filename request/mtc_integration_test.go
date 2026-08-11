package request

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/linter"
	_ "github.com/pkimetal/pkimetal/linter/cqrplint"
	_ "github.com/pkimetal/pkimetal/linter/mtclint"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

type mtcHTTPTestServer struct {
	t               *testing.T
	client          *fasthttp.Client
	server          *fasthttp.Server
	listener        *fasthttputil.InmemoryListener
	serverDone      chan struct{}
	originalLinters linter.LinterSlice
	dispatchers     []*linter.Linter
	dispatchWG      sync.WaitGroup
	closeOnce       sync.Once
}

type mtcHTTPResponse struct {
	status      int
	contentType string
	body        []byte
	results     []LintResult
}

func newMTCHTTPTestServer(t *testing.T) *mtcHTTPTestServer {
	t.Helper()

	h := &mtcHTTPTestServer{
		t:               t,
		listener:        fasthttputil.NewInmemoryListener(),
		serverDone:      make(chan struct{}),
		originalLinters: linter.Linters,
	}
	for _, name := range []string{"mtclint", "cqrplint"} {
		registered := registeredLinter(t, name)
		lin := &linter.Linter{
			Name:         registered.Name,
			Version:      registered.Version,
			Url:          registered.Url,
			Supported:    append([]linter.ProfileId(nil), registered.Supported...),
			Unsupported:  append([]linter.ProfileId(nil), registered.Unsupported...),
			Applicable:   registered.Applicable,
			NumInstances: 1,
			ReqChannel:   make(chan linter.LintingRequest, 16),
			Interface:    registered.Interface,
		}
		h.dispatchers = append(h.dispatchers, lin)
		h.dispatchWG.Add(1)
		go h.dispatch(lin)
	}
	linter.Linters = h.dispatchers

	h.server = &fasthttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		POST(ctx, strings.TrimPrefix(string(ctx.Path()), "/"))
	}}
	go func() {
		defer close(h.serverDone)
		_ = h.server.Serve(h.listener)
	}()
	h.client = &fasthttp.Client{Dial: func(string) (net.Conn, error) { return h.listener.Dial() }}
	t.Cleanup(h.close)
	return h
}

func registeredLinter(t *testing.T, name string) *linter.Linter {
	t.Helper()
	for _, lin := range linter.Linters {
		if lin.Name == name {
			if lin.Interface == nil {
				t.Fatalf("registered %s linter has no implementation", name)
			}
			return lin
		}
	}
	t.Fatalf("linter %s is not registered", name)
	return nil
}

func (h *mtcHTTPTestServer) dispatch(lin *linter.Linter) {
	defer h.dispatchWG.Done()
	handler := lin.Interface()
	for req := range lin.ReqChannel {
		for _, result := range handler.HandleRequest(context.Background(), nil, &req) {
			result.LinterName = lin.Name
			req.RespChannel <- result
		}
		req.RespChannel <- linter.LintingResult{
			LinterName: lin.Name,
			Finding:    fmt.Sprintf("Queued: 0s; Runtime: 0s; Version: %s", linter.VersionString(lin.Version)),
			Severity:   linter.SEVERITY_META,
		}
		req.RespChannel <- linter.LintingResult{
			LinterName: linter.PKIMETAL_NAME,
			Finding:    linter.PKIMETAL_ENDOFRESULTS,
			Severity:   linter.SEVERITY_META,
		}
	}
}

func (h *mtcHTTPTestServer) close() {
	h.closeOnce.Do(func() {
		_ = h.server.Shutdown()
		_ = h.listener.Close()
		<-h.serverDone
		for _, lin := range h.dispatchers {
			close(lin.ReqChannel)
		}
		h.dispatchWG.Wait()
		linter.Linters = h.originalLinters
	})
}

func (h *mtcHTTPTestServer) post(path, profile, contentType string, body []byte) mtcHTTPResponse {
	h.t.Helper()
	query := url.Values{"format": {"json"}}
	if profile != "" {
		query.Set("profile", profile)
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://pkimetal.test" + path + "?" + query.Encode())
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType(contentType)
	req.SetBody(body)
	if err := h.client.DoTimeout(req, resp, 5*time.Second); err != nil {
		h.t.Fatalf("POST %s failed: %v", path, err)
	}
	result := mtcHTTPResponse{
		status:      resp.StatusCode(),
		contentType: string(resp.Header.ContentType()),
		body:        append([]byte(nil), resp.Body()...),
	}
	if err := json.Unmarshal(result.body, &result.results); err != nil {
		h.t.Fatalf("decode POST %s response: %v\n%s", path, err, result.body)
	}
	return result
}

func (h *mtcHTTPTestServer) postForm(path, profile, field, value string) mtcHTTPResponse {
	h.t.Helper()
	return h.post(path, profile, "application/x-www-form-urlencoded", []byte(url.Values{field: {value}}.Encode()))
}

func TestLintCertificateAndTBSCertificateTransportMatrix(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	certificate := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	tbs := mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate())
	tests := []struct {
		name        string
		path        string
		profile     string
		contentType string
		body        []byte
	}{
		{"certificate form base64", "/lintcert", "mtc_subscriber", "application/x-www-form-urlencoded", []byte(url.Values{"b64cert": {base64.StdEncoding.EncodeToString(certificate)}}.Encode())},
		{"certificate form PEM", "/lintcert", "mtc_subscriber", "application/x-www-form-urlencoded", []byte(url.Values{"b64cert": {string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))}}.Encode())},
		{"certificate raw DER", "/lintcert", "mtc_subscriber", "application/pkix-cert", certificate},
		{"TBS form base64", "/linttbscert", "mtc_subscriber", "application/x-www-form-urlencoded", []byte(url.Values{"b64tbscert": {base64.StdEncoding.EncodeToString(tbs)}}.Encode())},
		{"TBS form PEM", "/linttbscert", "mtc_subscriber", "application/x-www-form-urlencoded", []byte(url.Values{"b64tbscert": {string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tbs}))}}.Encode())},
		{"TBS raw DER", "/linttbscert", "mtc_subscriber", "application/octet-stream", tbs},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := h.post(tc.path, tc.profile, tc.contentType, tc.body)
			assertJSONStatus(t, response, fasthttp.StatusOK)
			assertProfileMeta(t, response.results, tc.profile)
			assertLinterVersionMeta(t, response.results, "mtclint")
		})
	}
}

func TestLintCertificateAcceptsEveryExplicitMTCProfile(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	tests := []struct {
		profile string
		input   []byte
	}{
		{"mtc_ca", mtctest.Certificate(mtctest.ValidCATemplate())},
		{"mtc_subscriber", mtctest.Certificate(mtctest.ValidSubscriberTemplate())},
		{"cqrp_mtc_ca", mtctest.Certificate(mtctest.ValidCQRPCATemplate())},
		{"cqrp_mtc_subscriber", mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate())},
	}
	for _, tc := range tests {
		t.Run(tc.profile, func(t *testing.T) {
			response := h.postForm("/lintcert", tc.profile, "b64cert", base64.StdEncoding.EncodeToString(tc.input))
			assertJSONStatus(t, response, fasthttp.StatusOK)
			assertProfileMeta(t, response.results, tc.profile)
			assertLinterVersionMeta(t, response.results, "mtclint")
		})
	}
}

func TestLintCertificateAutodetectsOnlyDraftProfiles(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	tests := []struct {
		name        string
		input       []byte
		wantProfile string
	}{
		{"draft CA", mtctest.Certificate(mtctest.ValidCATemplate()), "mtc_ca"},
		{"draft subscriber", mtctest.Certificate(mtctest.ValidSubscriberTemplate()), "mtc_subscriber"},
		{"CQRP CA fixture", mtctest.Certificate(mtctest.ValidCQRPCATemplate()), "mtc_ca"},
		{"CQRP subscriber fixture", mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate()), "mtc_subscriber"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := h.postForm("/lintcert", "", "b64cert", base64.StdEncoding.EncodeToString(tc.input))
			assertJSONStatus(t, response, fasthttp.StatusOK)
			assertProfileMeta(t, response.results, tc.wantProfile)
			assertLinterVersionMeta(t, response.results, "mtclint")
			assertNoLinterVersionMeta(t, response.results, "cqrplint")
		})
	}
}

func TestLintCertificateCQRPAndDraftLinterFanout(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	cqrpTemplate := mtctest.ValidCQRPSubscriberTemplate()
	cqrpTemplate.Serial.SetInt64(9)
	cqrpTemplate.NotAfter = cqrpTemplate.NotBefore.Add(48 * 24 * time.Hour)
	cqrp := h.postForm("/lintcert", "cqrp_mtc_subscriber", "b64cert", base64.StdEncoding.EncodeToString(mtctest.Certificate(cqrpTemplate)))
	assertJSONStatus(t, cqrp, fasthttp.StatusOK)
	assertLinterVersionMeta(t, cqrp.results, "mtclint")
	assertLinterVersionMeta(t, cqrp.results, "cqrplint")
	assertFinding(t, cqrp.results, "mtclint", "e_mtc_serial_log_number_zero", "error")
	assertFinding(t, cqrp.results, "cqrplint", "e_cqrp_subscriber_validity_too_long", "error")

	draft := h.postForm("/lintcert", "mtc_subscriber", "b64cert", base64.StdEncoding.EncodeToString(mtctest.Certificate(mtctest.ValidSubscriberTemplate())))
	assertJSONStatus(t, draft, fasthttp.StatusOK)
	assertLinterVersionMeta(t, draft.results, "mtclint")
	assertNoLinterVersionMeta(t, draft.results, "cqrplint")
	assertFindingTextContains(t, draft.results, "cqrplint", "Not used [Available:true, Applicable:false]")
}

func TestLintCertificateRejectsMalformedInputs(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	tests := []struct {
		name        string
		path        string
		contentType string
		body        []byte
	}{
		{"malformed outer DER", "/lintcert", "application/pkix-cert", []byte{0x30, 0x01, 0x00}},
		{"invalid form base64", "/lintcert", "application/x-www-form-urlencoded", []byte("b64cert=%25%25%25")},
		{"invalid form PEM", "/lintcert", "application/x-www-form-urlencoded", []byte(url.Values{"b64cert": {"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"}}.Encode())},
		{"unparseable TBS", "/linttbscert", "application/octet-stream", []byte{0x30, 0x00}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := h.post(tc.path, "mtc_subscriber", tc.contentType, tc.body)
			assertJSONStatus(t, response, fasthttp.StatusBadRequest)
			assertFinding(t, response.results, "pkimetal", "", "fatal")
			assertFindingTextContains(t, response.results, "pkimetal", "Unrecognised input")
			assertNoProfileMeta(t, response.results)
		})
	}
}

func TestLintCertificateMalformedProofIsFatalFinding(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	template := mtctest.ValidSubscriberTemplate()
	template.Signature = mtctest.MalformedProofBytes()
	response := h.post("/lintcert", "mtc_subscriber", "application/pkix-cert", mtctest.Certificate(template))
	assertJSONStatus(t, response, fasthttp.StatusOK)
	assertFinding(t, response.results, "mtclint", "f_mtc_proof_malformed", "fatal")
}

func TestLintCertificateProfileArtifactMismatchIsFinding(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	tests := []struct {
		name    string
		profile string
		input   []byte
	}{
		{"CA selected for subscriber", "mtc_ca", mtctest.Certificate(mtctest.ValidSubscriberTemplate())},
		{"subscriber selected for CA", "mtc_subscriber", mtctest.Certificate(mtctest.ValidCATemplate())},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := h.post("/lintcert", tc.profile, "application/pkix-cert", tc.input)
			assertJSONStatus(t, response, fasthttp.StatusOK)
			assertFinding(t, response.results, "mtclint", "e_mtc_profile_artifact_mismatch", "error")
		})
	}
}

func TestLintTBSCertificateSkipsCompleteCertificateFindings(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	template := mtctest.ValidCQRPSubscriberTemplate()
	template.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDSHA256}
	template.SignatureUnused = 1
	proof := mtctest.ValidProof()
	proof.Signatures = []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: []byte{1}}}
	template.Signature = mtctest.ProofBytes(proof)
	response := h.post("/linttbscert", "cqrp_mtc_subscriber", "application/octet-stream", mtctest.TBSCertificate(template))
	assertJSONStatus(t, response, fasthttp.StatusOK)
	for _, code := range []string{
		"f_mtc_proof_malformed",
		"e_mtc_cert_signature_algorithm_mismatch",
		"e_mtc_signature_value_unused_bits",
		"e_cqrp_subscriber_standalone_cosignatures",
	} {
		assertNoFindingCode(t, response.results, code)
	}
	assertLinterVersionMeta(t, response.results, "mtclint")
	assertLinterVersionMeta(t, response.results, "cqrplint")
}

func TestLintCertificateJSONResultSchema(t *testing.T) {
	h := newMTCHTTPTestServer(t)
	response := h.post("/lintcert", "mtc_ca", "application/pkix-cert", mtctest.Certificate(mtctest.ValidSubscriberTemplate()))
	assertJSONStatus(t, response, fasthttp.StatusOK)
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(response.body, &raw); err != nil {
		t.Fatalf("decode raw JSON: %v", err)
	}
	allowed := map[string]bool{"Linter": true, "Finding": true, "Field": true, "Code": true, "Severity": true}
	for i, result := range raw {
		for key := range result {
			if !allowed[key] {
				t.Errorf("result %d has unexpected JSON field %q", i, key)
			}
		}
		for _, required := range []string{"Linter", "Finding", "Severity"} {
			if _, ok := result[required]; !ok {
				t.Errorf("result %d lacks JSON field %q", i, required)
			}
		}
	}
	assertFinding(t, response.results, "mtclint", "e_mtc_profile_artifact_mismatch", "error")
	assertProfileMeta(t, response.results, "mtc_ca")
	assertLinterVersionMeta(t, response.results, "mtclint")
}

func assertJSONStatus(t *testing.T, response mtcHTTPResponse, want int) {
	t.Helper()
	if response.status != want {
		t.Fatalf("status = %d, want %d; body = %s", response.status, want, response.body)
	}
	if response.contentType != "application/json; charset=UTF-8" {
		t.Errorf("content type = %q, want JSON", response.contentType)
	}
}

func assertProfileMeta(t *testing.T, results []LintResult, profile string) {
	t.Helper()
	assertFindingTextContains(t, results, linter.PKIMETAL_NAME, "Profile: "+profile+";")
}

func assertNoProfileMeta(t *testing.T, results []LintResult) {
	t.Helper()
	for _, result := range results {
		if result.Linter == linter.PKIMETAL_NAME && strings.Contains(result.Finding, "Profile:") {
			t.Errorf("unexpected profile meta result: %#v", result)
		}
	}
}

func assertLinterVersionMeta(t *testing.T, results []LintResult, name string) {
	t.Helper()
	for _, result := range results {
		if result.Linter == name && result.Severity == "meta" && strings.Contains(result.Finding, "Version:") {
			return
		}
	}
	t.Errorf("missing version meta for %s in %#v", name, results)
}

func assertNoLinterVersionMeta(t *testing.T, results []LintResult, name string) {
	t.Helper()
	for _, result := range results {
		if result.Linter == name && result.Severity == "meta" && strings.Contains(result.Finding, "Version:") {
			t.Errorf("unexpected version meta for %s: %#v", name, result)
		}
	}
}

func assertFinding(t *testing.T, results []LintResult, name, code, severity string) {
	t.Helper()
	for _, result := range results {
		if result.Linter == name && result.Code == code && result.Severity == severity {
			return
		}
	}
	t.Errorf("missing %s finding %q with severity %s in %#v", name, code, severity, results)
}

func assertNoFindingCode(t *testing.T, results []LintResult, code string) {
	t.Helper()
	for _, result := range results {
		if result.Code == code {
			t.Errorf("unexpected finding %s: %#v", code, result)
		}
	}
}

func assertFindingTextContains(t *testing.T, results []LintResult, name, text string) {
	t.Helper()
	for _, result := range results {
		if result.Linter == name && strings.Contains(result.Finding, text) {
			return
		}
	}
	t.Errorf("missing %s finding containing %q in %#v", name, text, results)
}
