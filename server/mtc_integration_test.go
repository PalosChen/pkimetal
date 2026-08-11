package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	"github.com/pkimetal/pkimetal/request"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

type mtcHTTPTestServer struct {
	client     *fasthttp.Client
	server     *fasthttp.Server
	listener   *fasthttputil.InmemoryListener
	serverDone chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
	closeOnce  sync.Once
}

type mtcHTTPRequest struct {
	method      string
	path        string
	profile     string
	format      string
	severity    string
	contentType string
	body        []byte
}

type mtcHTTPResponse struct {
	status      int
	contentType string
	cors        string
	body        []byte
	results     []request.LintResult
}

func TestMTCCertificateEndpoints(t *testing.T) {
	h := newMTCHTTPTestServer(t)

	t.Run("transport matrix", func(t *testing.T) { testMTCTransportMatrix(t, h) })
	t.Run("explicit profiles", func(t *testing.T) { testMTCExplicitProfiles(t, h) })
	t.Run("draft autodetection", func(t *testing.T) { testMTCDraftAutodetection(t, h) })
	t.Run("linter fanout", func(t *testing.T) { testMTCLinterFanout(t, h) })
	t.Run("error formats", func(t *testing.T) { testMTCErrorFormats(t, h) })
	t.Run("error matrix", func(t *testing.T) { testMTCErrorMatrix(t, h) })
	t.Run("invalid endpoint", func(t *testing.T) { testMTCInvalidEndpoint(t, h) })
	t.Run("success formats", func(t *testing.T) { testMTCSuccessFormats(t, h) })
	t.Run("method and path routing", func(t *testing.T) { testMTCMethodAndPathRouting(t, h) })
	t.Run("malformed proof", func(t *testing.T) { testMTCMalformedProof(t, h) })
	t.Run("profile mismatch", func(t *testing.T) { testMTCProfileMismatch(t, h) })
	t.Run("TBS exclusions", func(t *testing.T) { testMTCTBSExclusions(t, h) })
	t.Run("JSON schema", func(t *testing.T) { testMTCJSONSchema(t, h) })
}

func newMTCHTTPTestServer(t *testing.T) *mtcHTTPTestServer {
	t.Helper()
	assertRegisteredNativeLinters(t)

	ctx, cancel := context.WithCancel(context.Background())
	linter.StartLinters(ctx)
	h := &mtcHTTPTestServer{
		listener:   fasthttputil.NewInmemoryListener(),
		serverDone: make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
	h.server = &fasthttp.Server{Handler: webHandler, CloseOnShutdown: true}
	go func() {
		defer close(h.serverDone)
		_ = h.server.Serve(h.listener)
	}()
	h.client = &fasthttp.Client{Dial: func(string) (net.Conn, error) { return h.listener.Dial() }}
	t.Cleanup(func() { h.close(t) })
	return h
}

func assertRegisteredNativeLinters(t *testing.T) {
	t.Helper()
	for _, name := range []string{"mtclint", "cqrplint"} {
		count := 0
		for _, lin := range linter.Linters {
			if lin.Name == name && lin.Interface != nil && lin.NumInstances == 1 {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("usable %s registrations = %d, want 1", name, count)
		}
	}
}

func (h *mtcHTTPTestServer) close(t *testing.T) {
	t.Helper()
	h.closeOnce.Do(func() {
		if err := h.server.Shutdown(); err != nil {
			t.Errorf("shut down HTTP server: %v", err)
		}
		_ = h.listener.Close()
		select {
		case <-h.serverDone:
		case <-time.After(5 * time.Second):
			t.Error("HTTP server did not stop")
		}

		h.cancel()
		linter.StopLinters(h.ctx)
		lintersDone := make(chan struct{})
		go func() {
			linter.ShutdownWG.Wait()
			close(lintersDone)
		}()
		select {
		case <-lintersDone:
		case <-time.After(5 * time.Second):
			t.Error("linter server loops did not stop")
		}
	})
}

func (h *mtcHTTPTestServer) do(t *testing.T, spec mtcHTTPRequest) mtcHTTPResponse {
	t.Helper()
	query := url.Values{}
	if spec.profile != "" {
		query.Set("profile", spec.profile)
	}
	if spec.format != "" {
		query.Set("format", spec.format)
	}
	if spec.severity != "" {
		query.Set("severity", spec.severity)
	}
	requestURI := "http://pkimetal.test" + spec.path
	if encoded := query.Encode(); encoded != "" {
		requestURI += "?" + encoded
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(requestURI)
	req.Header.SetMethod(spec.method)
	if spec.contentType != "" {
		req.Header.SetContentType(spec.contentType)
	}
	req.SetBody(spec.body)
	if err := h.client.DoTimeout(req, resp, 5*time.Second); err != nil {
		t.Fatalf("%s %s failed: %v", spec.method, spec.path, err)
	}
	return mtcHTTPResponse{
		status:      resp.StatusCode(),
		contentType: string(resp.Header.ContentType()),
		cors:        string(resp.Header.Peek("Access-Control-Allow-Origin")),
		body:        append([]byte(nil), resp.Body()...),
	}
}

func (h *mtcHTTPTestServer) post(t *testing.T, spec mtcHTTPRequest) mtcHTTPResponse {
	t.Helper()
	spec.method = fasthttp.MethodPost
	response := h.do(t, spec)
	if response.cors != "*" {
		t.Fatalf("CORS header = %q, want *", response.cors)
	}
	return response
}

func (h *mtcHTTPTestServer) postJSON(t *testing.T, spec mtcHTTPRequest) mtcHTTPResponse {
	t.Helper()
	spec.format = "json"
	response := h.post(t, spec)
	if err := json.Unmarshal(response.body, &response.results); err != nil {
		t.Fatalf("decode POST %s response: %v\n%s", spec.path, err, response.body)
	}
	return response
}

func testMTCTransportMatrix(t *testing.T, h *mtcHTTPTestServer) {
	certificate := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	tbs := mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate())
	tests := []struct {
		name string
		spec mtcHTTPRequest
	}{
		{"certificate form base64", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/x-www-form-urlencoded", body: []byte(url.Values{"b64cert": {base64.StdEncoding.EncodeToString(certificate)}}.Encode())}},
		{"certificate form PEM", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/x-www-form-urlencoded", body: []byte(url.Values{"b64cert": {string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))}}.Encode())}},
		{"certificate raw DER", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/pkix-cert", body: certificate}},
		{"TBS form base64", mtcHTTPRequest{path: "/linttbscert", profile: "mtc_subscriber", contentType: "application/x-www-form-urlencoded", body: []byte(url.Values{"b64tbscert": {base64.StdEncoding.EncodeToString(tbs)}}.Encode())}},
		{"TBS form PEM", mtcHTTPRequest{path: "/linttbscert", profile: "mtc_subscriber", contentType: "application/x-www-form-urlencoded", body: []byte(url.Values{"b64tbscert": {string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tbs}))}}.Encode())}},
		{"TBS raw DER", mtcHTTPRequest{path: "/linttbscert", profile: "mtc_subscriber", contentType: "application/octet-stream", body: tbs}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := h.postJSON(t, tc.spec)
			assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
			assertProfileMeta(t, response.results, tc.spec.profile)
			assertLinterVersionMetaOnce(t, response.results, "mtclint")
			assertNoFatalOrBug(t, response.results)
		})
	}
}

func testMTCExplicitProfiles(t *testing.T, h *mtcHTTPTestServer) {
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
			response := h.postJSON(t, mtcHTTPRequest{path: "/lintcert", profile: tc.profile, contentType: "application/pkix-cert", body: tc.input})
			assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
			assertProfileMeta(t, response.results, tc.profile)
			assertLinterVersionMetaOnce(t, response.results, "mtclint")
			assertNoFatalOrBug(t, response.results)
		})
	}
}

func testMTCDraftAutodetection(t *testing.T, h *mtcHTTPTestServer) {
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
			response := h.postJSON(t, mtcHTTPRequest{path: "/lintcert", contentType: "application/pkix-cert", body: tc.input})
			assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
			assertProfileMeta(t, response.results, tc.wantProfile)
			assertLinterVersionMetaOnce(t, response.results, "mtclint")
			assertNoLinterVersionMeta(t, response.results, "cqrplint")
			assertNoFatalOrBug(t, response.results)
		})
	}
}

func testMTCLinterFanout(t *testing.T, h *mtcHTTPTestServer) {
	cqrpTemplate := mtctest.ValidCQRPSubscriberTemplate()
	cqrpTemplate.Serial.SetInt64(9)
	cqrpTemplate.NotAfter = cqrpTemplate.NotBefore.Add(48 * 24 * time.Hour)
	cqrp := h.postJSON(t, mtcHTTPRequest{path: "/lintcert", profile: "cqrp_mtc_subscriber", contentType: "application/pkix-cert", body: mtctest.Certificate(cqrpTemplate)})
	assertStatusAndContentType(t, cqrp, fasthttp.StatusOK, "application/json; charset=UTF-8")
	assertLinterVersionMetaOnce(t, cqrp.results, "mtclint")
	assertLinterVersionMetaOnce(t, cqrp.results, "cqrplint")
	assertFinding(t, cqrp.results, "mtclint", "e_mtc_serial_log_number_zero", "error")
	assertFinding(t, cqrp.results, "cqrplint", "e_cqrp_subscriber_validity_too_long", "error")

	draft := h.postJSON(t, mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/pkix-cert", body: mtctest.Certificate(mtctest.ValidSubscriberTemplate())})
	assertStatusAndContentType(t, draft, fasthttp.StatusOK, "application/json; charset=UTF-8")
	assertLinterVersionMetaOnce(t, draft.results, "mtclint")
	assertNoLinterVersionMeta(t, draft.results, "cqrplint")
	assertFindingTextContains(t, draft.results, "cqrplint", "Not used [Available:true, Applicable:false]")
	assertNoFatalOrBug(t, draft.results)
}

func testMTCErrorFormats(t *testing.T, h *mtcHTTPTestServer) {
	for _, tc := range []struct {
		format      string
		contentType string
		bodyParts   []string
	}{
		{"json", "application/json; charset=UTF-8", []string{`"Linter":"pkimetal"`, `"Finding":"Unrecognised input"`, `"Severity":"fatal"`}},
		{"html", "text/html; charset=UTF-8", []string{"pkimetal", "FATAL", "Unrecognised input"}},
		{"text", "text/plain; charset=UTF-8", []string{"pkimetal\tFATAL\tUnrecognised input\n"}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			response := h.post(t, mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", format: tc.format, contentType: "application/pkix-cert", body: []byte{0x30, 0x01, 0x00}})
			assertStatusAndContentType(t, response, fasthttp.StatusBadRequest, tc.contentType)
			for _, part := range tc.bodyParts {
				if !strings.Contains(string(response.body), part) {
					t.Errorf("%s response lacks %q: %s", tc.format, part, response.body)
				}
			}
		})
	}
}

func testMTCErrorMatrix(t *testing.T, h *mtcHTTPTestServer) {
	certificate := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	tbs := mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate())
	tests := []struct {
		name        string
		spec        mtcHTTPRequest
		wantFinding string
	}{
		{"empty body", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/pkix-cert"}, "Empty request body"},
		{"missing form input", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/x-www-form-urlencoded", body: []byte("other=value")}, "Unrecognised input"},
		{"unsupported content type", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "text/plain", body: certificate}, "Unrecognised input"},
		{"endpoint-mismatched content type", mtcHTTPRequest{path: "/linttbscert", profile: "mtc_subscriber", contentType: "application/pkix-cert", body: tbs}, "Unrecognised input"},
		{"invalid profile", mtcHTTPRequest{path: "/lintcert", profile: "not-a-profile", contentType: "application/pkix-cert", body: certificate}, "Unrecognised profile"},
		{"invalid severity", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", severity: "catastrophic", contentType: "application/pkix-cert", body: certificate}, "Unrecognised severity"},
		{"invalid base64", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/x-www-form-urlencoded", body: []byte("b64cert=%25%25%25")}, "Unrecognised input"},
		{"invalid PEM", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/x-www-form-urlencoded", body: []byte(url.Values{"b64cert": {"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"}}.Encode())}, "Unrecognised input"},
		{"malformed outer DER", mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/pkix-cert", body: []byte{0x30, 0x01, 0x00}}, "Unrecognised input"},
		{"unparseable TBS", mtcHTTPRequest{path: "/linttbscert", profile: "mtc_subscriber", contentType: "application/octet-stream", body: []byte{0x30, 0x00}}, "Unrecognised input"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := h.postJSON(t, tc.spec)
			assertStatusAndContentType(t, response, fasthttp.StatusBadRequest, "application/json; charset=UTF-8")
			if len(response.results) != 1 {
				t.Fatalf("results = %d, want 1: %#v", len(response.results), response.results)
			}
			assertFinding(t, response.results, "pkimetal", "", "fatal")
			assertFindingTextContains(t, response.results, "pkimetal", tc.wantFinding)
			assertNoProfileMeta(t, response.results)
		})
	}

	t.Run("invalid format", func(t *testing.T) {
		response := h.post(t, mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", format: "yaml", contentType: "application/pkix-cert", body: certificate})
		if response.status != fasthttp.StatusBadRequest {
			t.Fatalf("status = %d, want %d", response.status, fasthttp.StatusBadRequest)
		}
		if len(response.body) != 0 || response.contentType != "text/plain; charset=utf-8" {
			t.Errorf("invalid format response content type/body = %q/%q", response.contentType, response.body)
		}
	})
}

func testMTCInvalidEndpoint(t *testing.T, h *mtcHTTPTestServer) {
	response := h.post(t, mtcHTTPRequest{path: "/not-an-endpoint", contentType: "application/octet-stream", body: []byte("input")})
	if response.status != fasthttp.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %s", response.status, fasthttp.StatusNotFound, response.body)
	}
	if len(response.body) != 0 {
		t.Errorf("body = %q, want empty", response.body)
	}
}

func testMTCSuccessFormats(t *testing.T, h *mtcHTTPTestServer) {
	certificate := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	for _, tc := range []struct {
		format      string
		contentType string
		bodyParts   []string
	}{
		{"json", "application/json; charset=UTF-8", []string{`"Linter":"pkimetal"`, "Profile: mtc_subscriber;", `"Linter":"mtclint"`}},
		{"html", "text/html; charset=UTF-8", []string{"Profile: mtc_subscriber;", "mtclint"}},
		{"text", "text/plain; charset=UTF-8", []string{"Profile: mtc_subscriber;", "mtclint"}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			response := h.post(t, mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", format: tc.format, contentType: "application/pkix-cert", body: certificate})
			assertStatusAndContentType(t, response, fasthttp.StatusOK, tc.contentType)
			for _, part := range tc.bodyParts {
				if !strings.Contains(string(response.body), part) {
					t.Errorf("%s response lacks %q: %s", tc.format, part, response.body)
				}
			}
			upperBody := strings.ToUpper(string(response.body))
			if strings.Contains(upperBody, "FATAL") || strings.Contains(upperBody, "BUG") {
				t.Errorf("%s success response contains fatal/bug result: %s", tc.format, response.body)
			}
		})
	}
}

func testMTCMethodAndPathRouting(t *testing.T, h *mtcHTTPTestServer) {
	certificate := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	t.Run("POST path is case insensitive", func(t *testing.T) {
		response := h.postJSON(t, mtcHTTPRequest{path: "/LINTCERT", profile: "mtc_subscriber", contentType: "application/pkix-cert", body: certificate})
		assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
		assertProfileMeta(t, response.results, "mtc_subscriber")
		assertNoFatalOrBug(t, response.results)
	})
	t.Run("GET serves endpoint page", func(t *testing.T) {
		response := h.do(t, mtcHTTPRequest{method: fasthttp.MethodGet, path: "/lintcert"})
		if response.status != fasthttp.StatusOK || !strings.HasPrefix(response.contentType, "text/html") {
			t.Errorf("GET status/content type = %d/%q", response.status, response.contentType)
		}
	})
	t.Run("unsupported method", func(t *testing.T) {
		response := h.do(t, mtcHTTPRequest{method: fasthttp.MethodPut, path: "/lintcert"})
		if response.status != fasthttp.StatusMethodNotAllowed {
			t.Errorf("PUT status = %d, want %d", response.status, fasthttp.StatusMethodNotAllowed)
		}
	})
}

func testMTCMalformedProof(t *testing.T, h *mtcHTTPTestServer) {
	template := mtctest.ValidSubscriberTemplate()
	template.Signature = mtctest.MalformedProofBytes()
	response := h.postJSON(t, mtcHTTPRequest{path: "/lintcert", profile: "mtc_subscriber", contentType: "application/pkix-cert", body: mtctest.Certificate(template)})
	assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
	assertFinding(t, response.results, "mtclint", "f_mtc_proof_malformed", "fatal")
}

func testMTCProfileMismatch(t *testing.T, h *mtcHTTPTestServer) {
	for _, tc := range []struct {
		name    string
		profile string
		input   []byte
	}{
		{"CA selected for subscriber", "mtc_ca", mtctest.Certificate(mtctest.ValidSubscriberTemplate())},
		{"subscriber selected for CA", "mtc_subscriber", mtctest.Certificate(mtctest.ValidCATemplate())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.postJSON(t, mtcHTTPRequest{path: "/lintcert", profile: tc.profile, contentType: "application/pkix-cert", body: tc.input})
			assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
			assertFinding(t, response.results, "mtclint", "e_mtc_profile_artifact_mismatch", "error")
		})
	}
}

func testMTCTBSExclusions(t *testing.T, h *mtcHTTPTestServer) {
	template := mtctest.ValidCQRPSubscriberTemplate()
	template.OuterSignature = mtctest.Algorithm{OID: mtctest.OIDSHA256}
	template.SignatureUnused = 1
	proof := mtctest.ValidProof()
	proof.Signatures = []mtctest.ProofSignature{{CosignerID: []byte{1}, Signature: []byte{1}}}
	template.Signature = mtctest.ProofBytes(proof)
	response := h.postJSON(t, mtcHTTPRequest{path: "/linttbscert", profile: "cqrp_mtc_subscriber", contentType: "application/octet-stream", body: mtctest.TBSCertificate(template)})
	assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
	for _, code := range []string{
		"f_mtc_proof_malformed",
		"e_mtc_cert_signature_algorithm_mismatch",
		"e_mtc_signature_value_unused_bits",
		"e_cqrp_subscriber_standalone_cosignatures",
	} {
		assertNoFindingCode(t, response.results, code)
	}
	assertLinterVersionMetaOnce(t, response.results, "mtclint")
	assertLinterVersionMetaOnce(t, response.results, "cqrplint")
	assertNoFatalOrBug(t, response.results)
}

func testMTCJSONSchema(t *testing.T, h *mtcHTTPTestServer) {
	response := h.postJSON(t, mtcHTTPRequest{path: "/lintcert", profile: "mtc_ca", contentType: "application/pkix-cert", body: mtctest.Certificate(mtctest.ValidSubscriberTemplate())})
	assertStatusAndContentType(t, response, fasthttp.StatusOK, "application/json; charset=UTF-8")
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
	assertLinterVersionMetaOnce(t, response.results, "mtclint")
}

func assertStatusAndContentType(t *testing.T, response mtcHTTPResponse, wantStatus int, wantContentType string) {
	t.Helper()
	if response.status != wantStatus {
		t.Fatalf("status = %d, want %d; body = %s", response.status, wantStatus, response.body)
	}
	if response.contentType != wantContentType {
		t.Errorf("content type = %q, want %q", response.contentType, wantContentType)
	}
}

func assertProfileMeta(t *testing.T, results []request.LintResult, profile string) {
	t.Helper()
	assertFindingTextContains(t, results, linter.PKIMETAL_NAME, "Profile: "+profile+";")
}

func assertNoProfileMeta(t *testing.T, results []request.LintResult) {
	t.Helper()
	for _, result := range results {
		if result.Linter == linter.PKIMETAL_NAME && strings.Contains(result.Finding, "Profile:") {
			t.Errorf("unexpected profile meta result: %#v", result)
		}
	}
}

func assertLinterVersionMetaOnce(t *testing.T, results []request.LintResult, name string) {
	t.Helper()
	count := 0
	for _, result := range results {
		if result.Linter == name && result.Severity == "meta" && strings.Contains(result.Finding, "Version:") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("version meta results for %s = %d, want 1 in %#v", name, count, results)
	}
}

func assertNoLinterVersionMeta(t *testing.T, results []request.LintResult, name string) {
	t.Helper()
	for _, result := range results {
		if result.Linter == name && result.Severity == "meta" && strings.Contains(result.Finding, "Version:") {
			t.Errorf("unexpected version meta for %s: %#v", name, result)
		}
	}
}

func assertFinding(t *testing.T, results []request.LintResult, name, code, severity string) {
	t.Helper()
	for _, result := range results {
		if result.Linter == name && result.Code == code && result.Severity == severity {
			return
		}
	}
	t.Errorf("missing %s finding %q with severity %s in %#v", name, code, severity, results)
}

func assertNoFindingCode(t *testing.T, results []request.LintResult, code string) {
	t.Helper()
	for _, result := range results {
		if result.Code == code {
			t.Errorf("unexpected finding %s: %#v", code, result)
		}
	}
}

func assertFindingTextContains(t *testing.T, results []request.LintResult, name, text string) {
	t.Helper()
	for _, result := range results {
		if result.Linter == name && strings.Contains(result.Finding, text) {
			return
		}
	}
	t.Errorf("missing %s finding containing %q in %#v", name, text, results)
}

func assertNoFatalOrBug(t *testing.T, results []request.LintResult) {
	t.Helper()
	for _, result := range results {
		if result.Severity == "fatal" || result.Severity == "bug" {
			t.Errorf("unexpected %s result: %#v", result.Severity, result)
		}
	}
}
