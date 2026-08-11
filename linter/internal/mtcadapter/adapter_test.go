package mtcadapter

import (
	"reflect"
	"testing"

	"github.com/pkimetal/pkimetal/linter"
	"github.com/pkimetal/pkimetal/mtc"
)

func TestUnsupportedProfilesReturnsSortedComplement(t *testing.T) {
	supported := []linter.ProfileId{
		linter.MTC_CA,
		linter.MTC_SUBSCRIBER,
		linter.CQRP_MTC_CA,
		linter.CQRP_MTC_SUBSCRIBER,
	}
	var want []linter.ProfileId
	for profile := linter.ProfileId(0); profile < linter.ProfileId(len(linter.AllProfiles)); profile++ {
		if profile < linter.MTC_CA || profile > linter.CQRP_MTC_SUBSCRIBER {
			want = append(want, profile)
		}
	}
	if got := UnsupportedProfiles(supported...); !reflect.DeepEqual(got, want) {
		t.Fatalf("UnsupportedProfiles() = %#v, want %#v", got, want)
	}
}

func TestConvertFindingsPreservesDeterministicTuples(t *testing.T) {
	findings := []mtc.Finding{
		{Code: "w_code", Field: "warning.field", Source: "Source A", Section: "1.2", Message: "warning message", Severity: mtc.Warning},
		{Code: "e_code", Field: "error.field", Source: "Source B", Section: "2.3", Message: "error message", Severity: mtc.Error},
		{Code: "b_code", Field: "bug.field", Source: "Source C", Section: "3.4", Message: "bug message", Severity: mtc.Bug},
		{Code: "f_code", Field: "fatal.field", Source: "Source D", Section: "4.5", Message: "fatal message", Severity: mtc.Fatal},
	}
	want := []linter.LintingResult{
		{Code: "w_code", Field: "warning.field", Finding: "[Source A §1.2] warning message", Severity: linter.SEVERITY_WARNING},
		{Code: "e_code", Field: "error.field", Finding: "[Source B §2.3] error message", Severity: linter.SEVERITY_ERROR},
		{Code: "b_code", Field: "bug.field", Finding: "[Source C §3.4] bug message", Severity: linter.SEVERITY_BUG},
		{Code: "f_code", Field: "fatal.field", Finding: "[Source D §4.5] fatal message", Severity: linter.SEVERITY_FATAL},
	}
	first := ConvertFindings(findings)
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("ConvertFindings() =\n%#v\nwant\n%#v", first, want)
	}
	if second := ConvertFindings(findings); !reflect.DeepEqual(second, first) {
		t.Fatalf("conversion changed between calls:\n%#v\n%#v", first, second)
	}
}

func TestConvertSeverityUnknownFallsBackToBug(t *testing.T) {
	if got := ConvertSeverity(mtc.Severity(255)); got != linter.SEVERITY_BUG {
		t.Fatalf("ConvertSeverity(unknown) = %v, want BUG", got)
	}
}
