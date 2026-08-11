package request

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/linter"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func TestPOSTQueuesOnlyAvailableApplicableLinters(t *testing.T) {
	profile := linter.MTC_SUBSCRIBER
	compatible, compatibleReceived, compatibleStop := dispatchTestLinter("compatible", []linter.ProfileId{profile}, nil)
	incompatible, incompatibleReceived, incompatibleStop := dispatchTestLinter("incompatible", nil, func(*linter.LintingRequest) (bool, string) {
		t.Fatal("unsupported linter applicability callback was called")
		return true, ""
	})
	parserGated, parserGatedReceived, parserGatedStop := dispatchTestLinter("parser-gated", []linter.ProfileId{profile}, func(req *linter.LintingRequest) (bool, string) {
		if req.MTCArtifact == nil {
			t.Fatal("MTC artifact was not dispatched to applicability callback")
		}
		return false, "zcrypto could not safely parse this MTC artifact"
	})
	defer compatibleStop()
	defer incompatibleStop()
	defer parserGatedStop()
	unavailable := &linter.Linter{Name: "unavailable", Supported: []linter.ProfileId{profile}}

	originalLinters := linter.Linters
	t.Cleanup(func() { linter.Linters = originalLinters })
	linter.Linters = linter.LinterSlice{incompatible, compatible, parserGated, unavailable}

	body := postForApplicabilityTest(t, mtctest.Certificate(mtctest.ValidSubscriberTemplate()), "mtc_subscriber")

	if !received(compatibleReceived) {
		t.Fatal("compatible linter was not queued")
	}
	if received(incompatibleReceived) {
		t.Fatal("linter without positive MTC support was queued")
	}
	if received(parserGatedReceived) {
		t.Fatal("parser-incompatible linter was queued")
	}

	var results []LintResult
	if err := json.Unmarshal(body, &results); err != nil {
		t.Fatalf("decode POST response: %v\n%s", err, body)
	}
	assertMetaFinding(t, results, "incompatible: Not used [Available:true, Applicable:false] [Reason:MTC profile is not explicitly supported]")
	assertMetaFinding(t, results, "parser-gated: Not used [Available:true, Applicable:false] [Reason:zcrypto could not safely parse this MTC artifact]")
	assertMetaFinding(t, results, "unavailable: Not used [Available:false, Applicable:true]")
}

func postForApplicabilityTest(t *testing.T, decoded []byte, profile string) []byte {
	t.Helper()
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
	req.SetBodyString(url.Values{
		"b64cert": {base64.StdEncoding.EncodeToString(decoded)},
		"profile": {profile},
		"format":  {"json"},
	}.Encode())
	if err := client.DoTimeout(req, resp, 5*time.Second); err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode(), resp.Body())
	}
	return append([]byte(nil), resp.Body()...)
}

func dispatchTestLinter(name string, supported []linter.ProfileId, applicable func(*linter.LintingRequest) (bool, string)) (*linter.Linter, <-chan struct{}, func()) {
	reqChannel := make(chan linter.LintingRequest, 1)
	received := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range reqChannel {
			received <- struct{}{}
			req.RespChannel <- linter.LintingResult{LinterName: linter.PKIMETAL_NAME, Finding: linter.PKIMETAL_ENDOFRESULTS}
		}
	}()
	return &linter.Linter{
			Name:         name,
			Supported:    supported,
			Applicable:   applicable,
			NumInstances: 1,
			ReqChannel:   reqChannel,
		}, received, func() {
			close(reqChannel)
			wg.Wait()
		}
}

func received(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func assertMetaFinding(t *testing.T, results []LintResult, want string) {
	t.Helper()
	for _, result := range results {
		if result.Finding == want {
			return
		}
	}
	t.Fatalf("missing finding %q in %s", want, fmt.Sprint(results))
}
