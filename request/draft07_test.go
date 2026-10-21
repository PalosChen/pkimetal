package request

import (
	"github.com/pkimetal/pkimetal/internal/mtctest"
	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
	"github.com/zmap/zcrypto/x509"
	"testing"
)

func TestDraft07RequestAutodetection(t *testing.T) {
	for _, tpl := range []mtctest.Template{mtctest.ValidDraft07CATemplate(), mtctest.ValidDraft07SubscriberTemplate()} {
		for _, kind := range []mtc.InputKind{mtc.InputCertificate, mtc.InputTBSCertificate} {
			der := mtctest.Certificate(tpl)
			if kind == mtc.InputTBSCertificate {
				der = mtctest.TBSCertificate(tpl)
			}
			_, cert, a, err := parseCertificateBytes(der, kind, x509.ParseCertificate)
			if err != nil {
				t.Fatal(err)
			}
			ri := &RequestInfo{mtcArtifact: a, cert: cert, endpoint: ENDPOINT_LINTCERT}
			want := linter.ProfileId(112)
			if a.Kind == mtc.ArtifactCA {
				want = 111
			}
			if !ri.GetProfile("autodetect") || ri.profileId != want {
				t.Fatalf("profile=%v want=%v", ri.profileId, want)
			}
		}
	}
	tpl := mtctest.ValidDraft07CATemplate()
	tpl.Subject = mtctest.ValidDraft06CATemplate().Subject
	a, err := mtc.Parse(mtctest.Certificate(tpl), mtc.InputCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if (&RequestInfo{mtcArtifact: a, endpoint: ENDPOINT_LINTCERT}).GetProfile("autodetect") {
		t.Fatal("mixed OIDs autodetected")
	}
}
