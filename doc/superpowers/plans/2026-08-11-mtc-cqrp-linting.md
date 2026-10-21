# MTC and CQRP Linting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add native, offline linting for draft-ietf-plants-merkle-tree-certs-05 MTC CA and subscriber certificates, plus a separate CQRP v0.2.0 policy layer, to a pkimetal fork.

**Architecture:** Parse MTC DER and TLS-encoded proof data into a parser-owned `mtc.Artifact` before invoking zcrypto, then route that artifact through explicit draft-05 and CQRP rule registries. Keep generic linters enabled only when their parser and rule set are compatible with the selected MTC profile; CQRP extends, rather than replaces, the draft-05 rules.

**Tech Stack:** Go 1.26, standard-library `encoding/asn1`, existing pkimetal request/linter framework, zcrypto/zlint for compatible legacy checks, table-driven tests, Go fuzz tests, Docker.

---

## File Map

- Create `mtc/artifact.go`: public parser-owned input model, input kinds, artifact kinds, and parse errors.
- Create `mtc/oid.go`: draft-05, X.509, ML-DSA, EKU, policy, IAN, and SCT OIDs.
- Create `mtc/der.go`: strict DER sequence/field reader and AlgorithmIdentifier parameter-presence tracking.
- Create `mtc/certificate.go`: complete Certificate and TBSCertificate decoding, extension decoding, CA-ID recognition, and MTC classification.
- Create `mtc/ca_extension.go`: strict MTCCertificationAuthority decoding and serial-range model.
- Create `mtc/proof.go`: exact TLS presentation-language decoder for MTCProof.
- Create `mtc/subtree.go`: draft-05 subtree alignment and serial decomposition helpers.
- Create `mtc/finding.go`: shared finding, severity, rule, and registry types.
- Create `mtc/draft05.go`: draft-05 CA/subscriber rule registry and evaluation.
- Create `mtc/cqrp020.go`: CQRP v0.2.0 CA/subscriber rule registry and evaluation.
- Create `internal/mtctest/builder.go`: deterministic DER/TLS fixture builders used only by tests.
- Create `internal/mtctest/cmd/fixtures/main.go`: reproducible writer for generated test corpus files.
- Create `mtc/testdata/*.pem`: checked-in CA, standalone, landmark-relative, and CQRP interoperability corpus.
- Create `linter/mtclint/handler.go`: native pkimetal adapter for draft-05 findings.
- Create `linter/cqrplint/handler.go`: native pkimetal adapter for CQRP findings.
- Modify `linter/linter.go`: carry `*mtc.Artifact` and declare explicit supported profiles.
- Modify `linter/profile.go`: register four MTC profiles and their linter groups.
- Modify `request/post.go`, `request/certificate.go`, `request/autodetect.go`: parse MTC first, retain best-effort zcrypto parsing, and draft-only autodetection.
- Modify `linter/zlint/handler.go`: add MTC-compatible registries with named conflict exclusions.
- Modify `config/config.go`, `main.go`: configure and register the two native linters.
- Create `doc/MTC_RULE_COVERAGE.md`: normative-rule coverage and offline limitations.
- Modify `README.md`, `doc/REST_API.md`, `doc/openapi.yaml`: expose profiles, behavior, and response semantics.
- Create `.github/workflows/test.yml`: race, vet, build, and parser seed-corpus CI checks.

### Task 1: Strict MTC Certificate Envelope Parser

**Files:**
- Create: `mtc/artifact.go`
- Create: `mtc/oid.go`
- Create: `mtc/der.go`
- Create: `mtc/certificate.go`
- Create: `mtc/ca_extension.go`
- Create: `mtc/certificate_test.go`
- Create: `internal/mtctest/builder.go`
- Create: `internal/mtctest/cmd/fixtures/main.go`
- Create: `mtc/testdata/draft05-ca.pem`
- Create: `mtc/testdata/draft05-standalone.pem`
- Create: `mtc/testdata/draft05-landmark.pem`
- Create: `mtc/testdata/draft05-subscriber-tbs.pem`
- Create: `mtc/testdata/cqrp-subscriber.pem`

- [ ] **Step 1: Write failing complete-certificate and TBS parser tests**

Add deterministic builders for an MTC-shaped TBS and complete certificate, then assert that unknown ML-DSA SPKI and `id-alg-mtcProof` parse without zcrypto. Include cases for outer trailing bytes, absent versus NULL AlgorithmIdentifier parameters, non-zero signature BIT STRING unused bits, mismatched inner/outer signature AlgorithmIdentifiers, malformed DER lengths, a malformed MTC CA extension, and decoded `logHash`, `sigAlg`, `minSerial`, and `maxSerial` values.

```go
func TestParseCertificateWithoutKnownPublicKeyAlgorithm(t *testing.T) {
	der := mtctest.Certificate(mtctest.ValidSubscriberTemplate())
	got, err := mtc.Parse(der, mtc.InputCertificate)
	if err != nil { t.Fatal(err) }
	if got.Kind != mtc.ArtifactSubscriber { t.Fatalf("kind = %v", got.Kind) }
	if !got.TBSSignature.Algorithm.Equal(mtc.OIDMTCProof) { t.Fatal("wrong TBS signature OID") }
	if got.TBSSignature.ParametersPresent { t.Fatal("MTCProof parameters are present") }
	if !got.SubjectPublicKey.Algorithm.Algorithm.Equal(mtctest.OIDMLDSA44) { t.Fatal("wrong SPKI OID") }
}

func TestParseTBSCertificateHasNoOuterEnvelope(t *testing.T) {
	got, err := mtc.Parse(mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), mtc.InputTBSCertificate)
	if err != nil { t.Fatal(err) }
	if got.OuterSignature != nil { t.Fatal("TBS input has an outer signature") }
	if got.Proof != nil { t.Fatal("TBS input has a proof") }
}
```

- [ ] **Step 2: Run the parser tests and verify the package is absent**

Run: `go test ./mtc -run 'TestParse(CertificateWithoutKnownPublicKeyAlgorithm|TBSCertificateHasNoOuterEnvelope)' -count=1`

Expected: FAIL because package `mtc` and `internal/mtctest` do not exist.

- [ ] **Step 3: Implement the parser-owned model and strict envelope decoding**

Use these public types so later request and linter tasks share one stable contract:

```go
type InputKind uint8
const (
	InputCertificate InputKind = iota + 1
	InputTBSCertificate
)

type ArtifactKind uint8
const (
	ArtifactUnknown ArtifactKind = iota
	ArtifactCA
	ArtifactSubscriber
)

type AlgorithmIdentifier struct {
	Raw               []byte
	Algorithm         asn1.ObjectIdentifier
	ParametersPresent bool
	Parameters        asn1.RawValue
}

type SubjectPublicKeyInfo struct {
	Raw              []byte
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey []byte
	UnusedBits       int
}

type Extension struct {
	Raw      []byte
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

type EntryExtension struct { Type uint16; Data []byte }
type MTCSignature struct { CosignerID, Signature []byte }
type Proof struct {
	Extensions     []EntryExtension
	Start, End     uint64
	InclusionProof []byte
	Signatures     []MTCSignature
}

type Artifact struct {
	InputKind        InputKind
	Kind             ArtifactKind
	Raw              []byte
	RawTBS           []byte
	SerialNumber     *big.Int
	TBSSignature     AlgorithmIdentifier
	OuterSignature   *AlgorithmIdentifier
	SignatureValue   []byte
	SignatureUnused  int
	IssuerRaw        []byte
	SubjectRaw       []byte
	NotBefore        time.Time
	NotAfter         time.Time
	IssuerUniqueIDPresent bool
	SubjectUniqueIDPresent bool
	SubjectPublicKey SubjectPublicKeyInfo
	Extensions       []Extension
	SubjectCAID      []byte
	IssuerCAID       []byte
	CAParameters     *CertificationAuthority
	CAExtensionError error
	Proof            *Proof
	ProofParseError  error
}

type CertificationAuthority struct {
	LogHash              AlgorithmIdentifier
	SignatureAlgorithm   AlgorithmIdentifier
	MinSerial, MaxSerial *big.Int
}

func Parse(input []byte, kind InputKind) (*Artifact, error)
func ParseCAIDName(input []byte) ([]byte, error)
func ParseCertificationAuthorityExtension(input []byte) (*CertificationAuthority, error)
```

`Parse` must consume exactly one DER value, reject indefinite/non-minimal lengths and trailing bytes, preserve raw AlgorithmIdentifier encodings, decode the TBS fields without interpreting the public key, and classify CA whenever the MTC CA extension OID is present so malformed CA-ID or extension contents remain lintable. Decode a valid CA extension into `CertificationAuthority`; retain an extension-specific parse error on the artifact after the certificate/TBS envelope is recognized. A complete input must decode the outer AlgorithmIdentifier and BIT STRING; a TBS input must leave those fields nil/empty.

Have `mtctest.WriteGeneratedFixtures("mtc/testdata")` write the CA, CQRP subscriber, and subscriber TBS files. The fixture command is:

```go
package main

import (
	"log"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

func main() {
	if err := mtctest.WriteGeneratedFixtures("mtc/testdata"); err != nil {
		log.Fatal(err)
	}
}
```

Run it from the repository root with `go run ./internal/mtctest/cmd/fixtures`. Source the independently encoded standalone and landmark files from the sibling implementation's `../docs/scripts/standalone.pem` and `../docs/scripts/landmark.pem`, preserving their bytes in the checked-in corpus. An interoperability test always reads the checked-in files; when the sibling files exist locally, it also asserts they still match. CI must not depend on paths outside this repository.

- [ ] **Step 4: Run and format the parser implementation**

Run: `cp ../docs/scripts/standalone.pem mtc/testdata/draft05-standalone.pem && cp ../docs/scripts/landmark.pem mtc/testdata/draft05-landmark.pem && go run ./internal/mtctest/cmd/fixtures && gofmt -w mtc internal/mtctest && go test ./mtc -count=1`

Expected: PASS, including malformed DER and unknown-public-key cases.

- [ ] **Step 5: Commit the parser boundary**

```bash
git add mtc internal/mtctest
git commit -m "feat: parse MTC certificate envelopes"
```

### Task 2: MTCProof and Subtree Parsing

**Files:**
- Create: `mtc/proof.go`
- Create: `mtc/subtree.go`
- Create: `mtc/proof_test.go`
- Create: `mtc/subtree_test.go`
- Modify: `mtc/certificate.go`
- Modify: `internal/mtctest/builder.go`

- [ ] **Step 1: Write failing TLS-vector and subtree tests**

Cover zero-length vectors, truncated uint48/vector prefixes, leftover bytes, ordered/duplicate cosigner IDs, extension ordering, serial decomposition, and the exact draft-05 subtree formula.

```go
func TestValidSubtree(t *testing.T) {
	for _, tc := range []struct{ start, end uint64; want bool }{
		{0, 1, true}, {4, 8, true}, {8, 13, true},
		{4, 9, false}, {5, 8, false}, {8, 8, false},
	} {
		if got := mtc.ValidSubtree(tc.start, tc.end); got != tc.want {
			t.Errorf("ValidSubtree(%d, %d) = %t, want %t", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestSplitSerial(t *testing.T) {
	logNumber, index, ok := mtc.SplitSerial(new(big.Int).SetUint64((7 << 48) | 42))
	if !ok || logNumber != 7 || index != 42 {
		t.Fatalf("SplitSerial = (%d, %d, %t)", logNumber, index, ok)
	}
}
```

- [ ] **Step 2: Verify the proof tests fail**

Run: `go test ./mtc -run 'Test(ParseProof|ValidSubtree|SplitSerial)' -count=1`

Expected: FAIL with undefined proof/subtree functions.

- [ ] **Step 3: Implement exact TLS decoding and arithmetic helpers**

Use the proof types already defined in `mtc/artifact.go` and add this decoder entry point:

```go
func ParseProof(input []byte) (*Proof, error)

func ValidSubtree(start, end uint64) bool {
	if start >= end || end > (1<<48)-1 { return false }
	width := end - start
	ceil := uint64(1) << bits.Len64(width-1)
	return start%ceil == 0
}

func SplitSerial(n *big.Int) (uint16, uint64, bool) {
	if n == nil || n.Sign() <= 0 || n.BitLen() > 64 { return 0, 0, false }
	v := n.Uint64()
	logNumber := uint16(v >> 48)
	return logNumber, v & ((1 << 48) - 1), true
}
```

`ParseProof` must read `extensions<0..2^16-1>`, two uint48 values, `inclusion_proof<0..2^16-1>`, and `signatures<0..2^16-1>`. Within the signature vector, decode the one-byte-length TrustAnchorID and `signature<0..65535>`; retain a zero-length ID for its dedicated semantic rule. Return typed parse errors for truncation and trailing bytes. Decode syntactically complete extension and signature elements even when ordering or uniqueness is wrong so dedicated semantic rules can return stable codes. `certificate.go` invokes it only for complete MTC subscriber certificates and stores the error for conversion to one fatal finding.

- [ ] **Step 4: Run proof, subtree, and parser tests**

Run: `gofmt -w mtc internal/mtctest && go test ./mtc -count=1`

Expected: PASS.

- [ ] **Step 5: Commit proof decoding**

```bash
git add mtc internal/mtctest
git commit -m "feat: decode draft-05 MTC proofs"
```

### Task 3: Draft-05 Rule Registry

**Files:**
- Create: `mtc/finding.go`
- Create: `mtc/finding_test.go`
- Create: `mtc/draft05.go`
- Create: `mtc/draft05_test.go`
- Modify: `internal/mtctest/builder.go`

- [ ] **Step 1: Write failing table-driven rule tests**

Each mutation must assert one stable code and severity. Cover CA-ID Name shape, critical MTC CA extension, serial range and log number, inner/outer MTCProof identifiers, absent parameters, outer mismatch, BIT STRING alignment, proof subtree/index, entry-extension order/duplicates, cosigner order/duplicates, CA keyUsage/basicConstraints, CA SKI recommendation, and structural self-issued recommendation.

```go
func TestDraft05SubscriberRules(t *testing.T) {
	for _, tc := range []struct {
		name string; mutate func(*mtctest.Template); code string; severity mtc.Severity
	}{
		{"zero log number", func(x *mtctest.Template) { x.Serial = big.NewInt(9) }, "e_mtc_serial_log_number_zero", mtc.Error},
		{"misaligned subtree", func(x *mtctest.Template) { x.Proof.Start, x.Proof.End = 4, 9 }, "e_mtc_proof_subtree_invalid", mtc.Error},
		{"index outside", func(x *mtctest.Template) { x.Serial = new(big.Int).SetUint64((1 << 48) | 9); x.Proof.Start, x.Proof.End = 0, 8 }, "e_mtc_proof_index_outside_range", mtc.Error},
		{"unordered cosigners", mtctest.UnorderCosigners, "e_mtc_proof_cosigner_order", mtc.Error},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidSubscriberTemplate(); tc.mutate(&tpl)
			artifact := mtctest.MustParse(t, mtctest.Certificate(tpl), mtc.InputCertificate)
			assertFinding(t, mtc.LintDraft05(artifact), tc.code, tc.severity)
		})
	}
}
```

- [ ] **Step 2: Verify the draft registry tests fail**

Run: `go test ./mtc -run TestDraft05 -count=1`

Expected: FAIL because `LintDraft05` and finding types are undefined.

- [ ] **Step 3: Implement explicit applicability and all offline draft rules**

Use this registry contract and return findings sorted by code:

```go
type Severity uint8
const (
	Warning Severity = iota + 1
	Error
	Bug
	Fatal
)
type Finding struct {
	Code, Field, Message string
	Source, Section     string
	Severity            Severity
}
type Rule struct {
	Code, Source, Section string
	Kinds []ArtifactKind
	InputKinds []InputKind
	Evaluate func(*Artifact) *Finding
}

func LintDraft05(a *Artifact) []Finding { return runRules(a, draft05Rules) }
```

`runRules` must isolate every evaluator with `defer/recover`; an unexpected panic becomes `b_mtc_rule_panic` with `Bug` severity and identifies the failed rule in the message, while remaining rules continue. Add a unit test with one deliberately panicking test rule followed by one normal rule and assert both the bug finding and normal finding are returned.

Register these codes: `e_mtc_signature_algorithm_oid`, `e_mtc_signature_algorithm_parameters_present`, `e_mtc_cert_signature_algorithm_mismatch`, `e_mtc_signature_value_unused_bits`, `e_mtc_ca_subject_not_ca_id`, `e_mtc_ca_extension_missing`, `e_mtc_ca_extension_not_critical`, `f_mtc_ca_extension_malformed`, `e_mtc_ca_serial_range_invalid`, `e_mtc_ca_key_usage_missing`, `e_mtc_ca_key_cert_sign_missing`, `e_mtc_ca_basic_constraints_missing`, `e_mtc_ca_basic_constraints_not_ca`, `w_mtc_ca_ski_not_ca_id`, `w_mtc_ca_self_issued`, `e_mtc_subscriber_issuer_not_ca_id`, `e_mtc_serial_non_positive`, `e_mtc_serial_too_large`, `e_mtc_serial_log_number_zero`, `f_mtc_proof_malformed`, `e_mtc_proof_range_invalid`, `e_mtc_proof_subtree_invalid`, `e_mtc_proof_index_outside_range`, `e_mtc_proof_extensions_order`, `e_mtc_proof_extensions_duplicate`, `e_mtc_proof_cosigner_id_empty`, `e_mtc_proof_cosigner_order`, and `e_mtc_proof_cosigner_duplicate`.

Decode a zero-length `TrustAnchorID` as a structurally bounded vector and let the semantic rule return `e_mtc_proof_cosigner_id_empty`. Truncation, invalid vector bounds, and trailing bytes remain `f_mtc_proof_malformed` because subsequent proof fields cannot be trusted.

When an MTC CA uses RFC 9925 `id-alg-unsigned` (`1.3.6.1.5.5.7.6.36`), also register conditional checks `e_rfc9925_unsigned_algorithm_mismatch`, `e_rfc9925_unsigned_parameters_present`, `e_rfc9925_unsigned_signature_not_empty`, `e_rfc9925_unsigned_issuer_unique_id_present`, `w_rfc9925_unsigned_authority_key_identifier_present`, and `w_rfc9925_unsigned_issuer_alternative_name_present`. These implement RFC 9925 Sections 3.1-3.3. The self-issued recommendation warning applies to a structurally self-issued CA using a real signature algorithm, not to an RFC 9925 unsigned representation.

Outer-envelope and proof rules apply only to `InputCertificate`. TBS input must not emit missing-proof or missing-outer-signature findings. Do not infer hash size, verify proof hashes/signatures, or compare log-entry fields unavailable in the input.

- [ ] **Step 4: Run draft rule tests and package coverage**

Run: `gofmt -w mtc internal/mtctest && go test ./mtc -coverprofile=/tmp/mtc-cover.out -count=1`

Expected: PASS and at least 85% statement coverage for package `mtc`.

- [ ] **Step 5: Commit draft-05 rules**

```bash
git add mtc internal/mtctest
git commit -m "feat: lint draft-05 MTC structure"
```

### Task 4: CQRP v0.2.0 Rule Registry

**Files:**
- Create: `mtc/cqrp020.go`
- Create: `mtc/cqrp020_test.go`
- Modify: `mtc/oid.go`
- Modify: `internal/mtctest/builder.go`

- [ ] **Step 1: Write failing CQRP CA and subscriber tests**

Use exact AlgorithmIdentifier DER for ML-DSA-44 (`300b0609608648016503040311`) and ML-DSA-65/87 OIDs, and mutations for every certificate-local rule. Include a warning case for an IAN directoryName that uses attributes other than O/CN and a warning case for a non-DV reserved BR policy.

```go
func TestCQRPSubscriberRules(t *testing.T) {
	for _, tc := range []struct{ name string; mutate func(*mtctest.Template); code string }{
		{"48 days", mtctest.SetValidity(48*24*time.Hour), "e_cqrp_subscriber_validity_too_long"},
		{"ML-DSA NULL parameters", mtctest.SetSPKINULLParameters, "e_cqrp_subscriber_mldsa_parameters_present"},
		{"nonempty DV subject", mtctest.SetDVSubjectCN, "e_cqrp_subscriber_dv_subject_not_empty"},
		{"missing policies", mtctest.RemoveCertificatePolicies, "e_cqrp_subscriber_policies_missing"},
		{"extra EKU", mtctest.AddClientAuthEKU, "e_cqrp_subscriber_eku_only_server_auth"},
		{"critical IAN", mtctest.MakeIANCritical, "e_cqrp_subscriber_ian_critical"},
		{"SCT present", mtctest.AddSCTList, "e_cqrp_subscriber_sct_present"},
		{"one standalone signature", mtctest.KeepOneSignature, "e_cqrp_subscriber_standalone_cosignatures"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tpl := mtctest.ValidCQRPSubscriberTemplate(); tc.mutate(&tpl)
			assertCode(t, mtc.LintCQRP020(mtctest.MustParse(t, mtctest.Certificate(tpl), mtc.InputCertificate)), tc.code)
		})
	}
}
```

- [ ] **Step 2: Verify CQRP tests fail**

Run: `go test ./mtc -run TestCQRP -count=1`

Expected: FAIL because `LintCQRP020` is undefined.

- [ ] **Step 3: Implement the independent CQRP policy layer**

`LintCQRP020` must run only CQRP rules; pkimetal request fan-out combines its results with mtclint's draft-05 results. Register CA codes `e_cqrp_ca_spki_algorithm`, `e_cqrp_ca_spki_parameters_present`, `e_cqrp_ca_spki_encoding`, `e_cqrp_ca_hash_mldsa`, and `e_cqrp_ca_key_usage_not_critical`. Register subscriber codes `e_cqrp_subscriber_validity_too_long`, `e_cqrp_subscriber_mldsa_parameters_present`, `e_cqrp_subscriber_mldsa_encoding`, `e_cqrp_subscriber_hash_mldsa`, `e_cqrp_subscriber_dv_subject_not_empty`, `e_cqrp_subscriber_policies_missing`, `e_cqrp_subscriber_policies_critical`, `e_cqrp_subscriber_policy_identifier`, `w_cqrp_subscriber_policy_not_dv`, `e_cqrp_subscriber_eku_missing`, `e_cqrp_subscriber_eku_critical`, `e_cqrp_subscriber_eku_only_server_auth`, `e_cqrp_subscriber_ian_critical`, `e_cqrp_subscriber_ian_form`, `w_cqrp_subscriber_ian_name_attributes`, `e_cqrp_subscriber_sct_present`, and `e_cqrp_subscriber_standalone_cosignatures`.

Traditional TLS BR public-key algorithms remain allowed for subscribers and are delegated to the compatible TLS BR registry. ML-DSA-44/65/87 require absent parameters and exact encoding; HashML-DSA is rejected. The allowed reserved BR policy OIDs are DV `2.23.140.1.2.1`, OV `2.23.140.1.2.2`, and IV `2.23.140.1.2.3`; non-DV is allowed but receives the CQRP SHOULD warning.

```go
func LintCQRP020(a *Artifact) []Finding {
	return runRules(a, cqrp020Rules)
}

func isStandalone(p *Proof) bool { return p != nil && len(p.Signatures) != 0 }
func exactAlgorithmEncoding(got []byte, want []byte) bool { return bytes.Equal(got, want) }
```

Do not emit a finding for the conditional `cRLSign` requirement because a single certificate cannot establish whether the key signs CRLs with `nextUpdate-currentTime > 7 days`. Do not claim CA/cosigner role identity or Chrome-recognized independence from certificate bytes.

- [ ] **Step 4: Run both policy suites**

Run: `gofmt -w mtc internal/mtctest && go test ./mtc -run 'Test(Draft05|CQRP)' -count=1`

Expected: PASS with no duplicate codes across a single registry.

- [ ] **Step 5: Commit CQRP rules**

```bash
git add mtc internal/mtctest
git commit -m "feat: lint CQRP v0.2.0 certificate policy"
```

### Task 5: Profiles, Request Parsing, and Autodetection

**Files:**
- Modify: `linter/profile.go`
- Modify: `linter/linter.go`
- Modify: `request/post.go`
- Modify: `request/certificate.go`
- Modify: `request/autodetect.go`
- Create: `request/mtc_test.go`

- [ ] **Step 1: Write failing request-routing tests**

Assert explicit `mtc_ca`, `mtc_subscriber`, `cqrp_mtc_ca`, and `cqrp_mtc_subscriber` profiles; autodetect only the two draft profiles; successful requests when zcrypto cannot understand ML-DSA; profile-kind mismatch remains a lintable HTTP 200 request; and unchanged handling for ordinary X.509 certificates.

```go
func TestMTCProfileAutodetectionNeverSelectsCQRP(t *testing.T) {
	ri := parseCertificateRequest(t, mtctest.Certificate(mtctest.ValidCQRPSubscriberTemplate()), "autodetect")
	if ri.profileId != linter.MTC_SUBSCRIBER { t.Fatalf("profile = %v", ri.profileId) }
}

func TestExplicitMTCProfileDoesNotRequireZcrypto(t *testing.T) {
	ri := parseCertificateRequestWithLegacyParser(
		t,
		mtctest.Certificate(mtctest.ValidSubscriberTemplate()),
		"mtc_subscriber",
		func([]byte) (*x509.Certificate, error) { return nil, errors.New("unsupported ML-DSA") },
	)
	if ri.mtcArtifact == nil { t.Fatal("MTC artifact is nil") }
	if ri.cert != nil { t.Fatal("zcrypto certificate unexpectedly present") }
}
```

- [ ] **Step 2: Verify request tests fail**

Run: `go test ./request -run TestMTC -count=1`

Expected: FAIL with undefined MTC profiles/accessors.

- [ ] **Step 3: Add four profiles and parse-before-zcrypto routing**

Append four IDs and profile records:

```go
MTC_CA
MTC_SUBSCRIBER
CQRP_MTC_CA
CQRP_MTC_SUBSCRIBER

MTC_CA:              {Name: "mtc_ca", Source: "draft-ietf-plants-merkle-tree-certs-05", Description: "MTC Certification Authority Certificate"},
MTC_SUBSCRIBER:      {Name: "mtc_subscriber", Source: "draft-ietf-plants-merkle-tree-certs-05", Description: "MTC Subscriber Certificate"},
CQRP_MTC_CA:         {Name: "cqrp_mtc_ca", Source: "CQRP v0.2.0", Description: "CQRP MTC CA Cosigning Certificate"},
CQRP_MTC_SUBSCRIBER: {Name: "cqrp_mtc_subscriber", Source: "CQRP v0.2.0", Description: "CQRP MTC Subscriber TLS Certificate"},
```

Add `MTCArtifact *mtc.Artifact` to `LintingRequest` and `mtcArtifact *mtc.Artifact` to `RequestInfo`. For certificate endpoints, decode base64/PEM, call `mtc.Parse` first, and only require zcrypto success when the input is not recognized as MTC. Autodetection maps `ArtifactCA` to `MTC_CA` and `ArtifactSubscriber` to `MTC_SUBSCRIBER`; explicit CQRP profiles are never inferred. Preserve an explicit CA/subscriber mismatch through dispatch so `mtclint` can emit `e_mtc_profile_artifact_mismatch` while independent parseable rules still run.

Extract the parser order into `parseCertificateBytes(decoded []byte, inputKind mtc.InputKind, parseLegacy func([]byte) (*x509.Certificate, error))`, and have production pass `x509.ParseCertificate`. The injected function is only a test seam proving recognized MTC input survives a legacy-parser error; no mutable package-global parser hook is introduced.

- [ ] **Step 4: Run request and legacy tests**

Run: `gofmt -w linter request && go test ./request ./linter/... -count=1`

Expected: PASS; ordinary request tests retain their previous behavior.

- [ ] **Step 5: Commit request integration**

```bash
git add linter/profile.go linter/linter.go request
git commit -m "feat: route MTC profiles without zcrypto dependency"
```

### Task 6: Native mtclint and cqrplint Adapters

**Files:**
- Create: `linter/mtclint/handler.go`
- Create: `linter/mtclint/handler_test.go`
- Create: `linter/cqrplint/handler.go`
- Create: `linter/cqrplint/handler_test.go`
- Modify: `config/config.go`
- Modify: `main.go`

- [ ] **Step 1: Write failing adapter tests**

Assert supported-profile lists, finding conversion including source/section metadata, TBS behavior, profile/artifact mismatch, and separation between draft and CQRP handlers.

```go
func hasCode(results []linter.LintingResult, code string) bool {
	for _, result := range results {
		if result.Code == code { return true }
	}
	return false
}

func assertHasCode(t *testing.T, results []linter.LintingResult, code string) {
	t.Helper()
	if !hasCode(results, code) { t.Errorf("missing finding %s", code) }
}

func assertLacksCode(t *testing.T, results []linter.LintingResult, code string) {
	t.Helper()
	if hasCode(results, code) { t.Errorf("unexpected finding %s", code) }
}

func TestCQRPHandlerReturnsOnlyPolicyFindings(t *testing.T) {
	tpl := mtctest.ValidCQRPSubscriberTemplate()
	tpl.Serial = big.NewInt(9)
	tpl.NotAfter = tpl.NotBefore.Add(48 * 24 * time.Hour)
	artifact := mtctest.MustParse(t, mtctest.Certificate(tpl), mtc.InputCertificate)
	req := linter.LintingRequest{MTCArtifact: artifact, ProfileId: linter.CQRP_MTC_SUBSCRIBER}
	got := (&cqrplint.CQRPLint{}).HandleRequest(context.Background(), nil, &req)
	assertHasCode(t, got, "e_cqrp_subscriber_validity_too_long")
	assertLacksCode(t, got, "e_mtc_serial_log_number_zero")
}

func TestMTCLintTBSSkipsProofRules(t *testing.T) {
	artifact := mtctest.MustParse(t, mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), mtc.InputTBSCertificate)
	req := linter.LintingRequest{MTCArtifact: artifact, ProfileId: linter.MTC_SUBSCRIBER}
	got := (&mtclint.MTCLint{}).HandleRequest(context.Background(), nil, &req)
	assertLacksCode(t, got, "f_mtc_proof_malformed")
}
```

- [ ] **Step 2: Verify adapter tests fail**

Run: `go test ./linter/mtclint ./linter/cqrplint -count=1`

Expected: FAIL because both adapter packages are absent.

- [ ] **Step 3: Implement and register in-process adapters**

Both adapters return `useHandleRequest=true`, map `mtc.Warning/Error/Bug/Fatal` to pkimetal severities, and preserve code/field while formatting source section into the finding description. `mtclint` supports all four MTC profiles, emits `e_mtc_profile_artifact_mismatch` when the selected CA/subscriber kind differs, and runs draft rules. `cqrplint` supports only CQRP profiles and runs only CQRP rules, because `mtclint` is already queued for those profiles.

```go
func (l *MTCLint) HandleRequest(_ context.Context, _ *linter.LinterInstance, req *linter.LintingRequest) []linter.LintingResult {
	return convert(mtc.LintDraft05(req.MTCArtifact))
}

func (l *CQRPLint) HandleRequest(_ context.Context, _ *linter.LinterInstance, req *linter.LintingRequest) []linter.LintingResult {
	return convert(mtc.LintCQRP020(req.MTCArtifact))
}
```

Set adapter versions to `draft-05` and `v0.2.0`, respectively, so existing per-linter meta findings expose rule-source versions. Add `Mtclint.NumGoroutines` and `Cqrplint.NumGoroutines` with default `1`, and blank imports in `main.go`.

- [ ] **Step 4: Run adapter and configuration tests**

Run: `gofmt -w linter/mtclint linter/cqrplint config main.go && go test ./linter/mtclint ./linter/cqrplint ./config -count=1`

Expected: PASS.

- [ ] **Step 5: Commit native linter registration**

```bash
git add linter/mtclint linter/cqrplint config/config.go main.go
git commit -m "feat: register native MTC and CQRP linters"
```

### Task 7: Explicit Generic-Linter Applicability and zlint Compatibility

**Files:**
- Modify: `linter/linter.go`
- Modify: `linter/profile.go`
- Modify: `linter/zlint/handler.go`
- Modify: `linter/zlint/handler_test.go`
- Modify: `request/post.go`
- Create: `linter/applicability_test.go`

- [ ] **Step 1: Write failing compatibility tests**

Assert external parser-dependent linters are not queued for any MTC profile; zlint runs for MTC profiles only when a zcrypto certificate exists; a skipped linter meta finding contains a stable reason; generic MTC uses the non-CABF registry; CQRP subscriber uses CABF leaf rules minus the exact MTC conflicts; and compatible RFC checks such as serial length remain active.

```go
func TestCQRPMTCZlintExclusions(t *testing.T) {
	for _, name := range []string{
		"e_signature_algorithm_not_supported",
		"e_public_key_type_not_allowed",
		"e_algorithm_identifier_improper_encoding",
		"w_ct_sct_policy_count_unsatisfied",
	} {
		if cqrpMTCLeafRegistry.CertificateLints().ByName(name) != nil { t.Errorf("%s was not excluded", name) }
	}
	if cqrpMTCLeafRegistry.CertificateLints().ByName("e_serial_number_longer_than_20_octets") == nil { t.Fatal("compatible serial lint was excluded") }
}
```

- [ ] **Step 2: Verify compatibility tests fail**

Run: `go test ./linter ./linter/zlint -run 'Test(MTC|CQRP)' -count=1`

Expected: FAIL because supported-profile gating and the CQRP registry are absent.

- [ ] **Step 3: Replace implicit unsupported lists with positive applicability**

Add `Supported []ProfileId` and `Applicable func(*LintingRequest) (bool, string)` to `Linter`. For an MTC profile, `Supports(profile)` requires the profile to appear in the positive `Supported` list; for every legacy profile it retains the current `Unsupported` behavior. Dispatch calls `Supports` first and `Applicable` second, and appends the returned reason to the existing `Not used [Available:..., Applicable:...]` meta finding. Mark `mtclint`, `cqrplint`, and zlint explicitly for MTC profiles; existing external linters therefore become inapplicable to MTC without changing legacy behavior. The zlint callback returns `(false, "zcrypto could not safely parse this MTC artifact")` when `req.Cert == nil` so parser incompatibility is applicability metadata, not a false certificate defect.

Create `mtcNonCABFRegistry` by excluding CABF sources and create `cqrpMTCLeafRegistry` by filtering the normal CABF leaf registry with exactly these four names: `e_signature_algorithm_not_supported`, `e_public_key_type_not_allowed`, `e_algorithm_identifier_improper_encoding`, `w_ct_sct_policy_count_unsatisfied`. Select the first for `MTC_CA`/`MTC_SUBSCRIBER` and the second for `CQRP_MTC_SUBSCRIBER`; use the non-CABF registry for `CQRP_MTC_CA`.

- [ ] **Step 4: Run all linter tests and inspect named exclusions**

Run: `gofmt -w linter && go test ./linter/... -count=1 && rg -n 'e_signature_algorithm_not_supported|e_public_key_type_not_allowed|e_algorithm_identifier_improper_encoding|w_ct_sct_policy_count_unsatisfied' linter/zlint/handler.go`

Expected: tests PASS and each exclusion appears once in the MTC compatibility list.

- [ ] **Step 5: Commit applicability filtering**

```bash
git add linter request/post.go
git commit -m "fix: isolate incompatible legacy lints from MTC profiles"
```

### Task 8: HTTP End-to-End Behavior

**Files:**
- Create: `request/mtc_integration_test.go`
- Modify: `request/post.go`
- Modify: `request/input.go`

- [ ] **Step 1: Write failing endpoint tests**

Exercise `/lintcert` and `/linttbscert` through the real fasthttp handler with PEM, form base64, `application/pkix-cert` complete-certificate bodies, and `application/octet-stream` TBS bodies. Assert all four profiles are accepted, draft autodetection works, malformed outer DER is HTTP 400, malformed proof is a JSON fatal finding, explicit CQRP selection adds the CQRP linter in addition to mtclint, profile mismatch is a JSON error finding, and TBS responses have no complete-certificate proof finding.

```go
func TestLintCertificateMalformedProofIsFinding(t *testing.T) {
	resp := postLint(t, "/lintcert", "mtc_subscriber", mtctest.CertificateWithTruncatedProof())
	if resp.StatusCode() != fasthttp.StatusOK { t.Fatalf("status = %d", resp.StatusCode()) }
	assertJSONFinding(t, resp.Body(), "mtclint", "f_mtc_proof_malformed", "fatal")
}

func TestLintTBSCertificateAcceptsMTCPreissuance(t *testing.T) {
	resp := postLint(t, "/linttbscert", "mtc_subscriber", mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()))
	if resp.StatusCode() != fasthttp.StatusOK { t.Fatalf("status = %d", resp.StatusCode()) }
	if bytes.Contains(resp.Body(), []byte("f_mtc_proof_malformed")) { t.Fatal("TBS response contains proof finding") }
}
```

- [ ] **Step 2: Verify endpoint tests fail**

Run: `go test ./request -run 'TestLint(Certificate|TBSCertificate)' -count=1`

Expected: at least the malformed-proof and TBS MTC cases fail before request integration is complete.

- [ ] **Step 3: Normalize parse-fatal versus lint-fatal behavior**

Keep invalid base64/PEM, invalid DER envelope, and an unparseable TBS as HTTP 400. Once a complete MTC certificate envelope and TBS are parseable, retain a `ProofParseError` on the artifact and let `mtclint` return `f_mtc_proof_malformed` with HTTP 200. Include the selected profile and linter names using the existing response schema; do not add a parallel endpoint.

- [ ] **Step 4: Run request integration and race tests**

Run: `gofmt -w request && go test -race ./request ./linter/... -count=1`

Expected: PASS with no race reports.

- [ ] **Step 5: Commit endpoint behavior**

```bash
git add request
git commit -m "test: cover MTC certificate endpoints end to end"
```

### Task 9: Coverage Matrix and Public Documentation

**Files:**
- Create: `doc/MTC_RULE_COVERAGE.md`
- Modify: `mtc/draft05.go`
- Modify: `mtc/draft05_test.go`
- Modify: `mtc/cqrp020.go`
- Modify: `README.md`
- Modify: `doc/REST_API.md`
- Modify: `doc/openapi.yaml`

- [ ] **Step 1: Write a documentation assertion test**

Add a small Go test in `mtc/draft05_test.go` that reads `../doc/MTC_RULE_COVERAGE.md` and asserts every registered draft and CQRP code is documented exactly once. Expose `Draft05RuleCodes()` and `CQRP020RuleCodes()` as sorted copies for this test.

```go
codes := append(mtc.Draft05RuleCodes(), mtc.CQRP020RuleCodes()...)
codes = append(codes, "e_mtc_profile_artifact_mismatch", "b_mtc_rule_panic")
for _, code := range codes {
	if count := strings.Count(string(doc), "`"+code+"`"); count != 1 {
		t.Errorf("coverage entries for %s = %d, want 1", code, count)
	}
}
```

- [ ] **Step 2: Verify the coverage assertion fails**

Run: `go test ./mtc -run TestRuleCoverageDocument -count=1`

Expected: FAIL because the coverage document does not exist.

- [ ] **Step 3: Document profiles, precedence, and limits**

Create one row per rule with source section, artifact/profile, severity, and one of the exact statuses `implemented`, `delegated`, `not applicable`, or `not locally decidable`, including the internal `b_mtc_rule_panic` result. State explicitly: CQRP overrides TLS BR only where CQRP says so; draft-05 overrides RFC 5280 only where draft-05 says so; CQRP profiles also run draft-05 rules; autodetection never chooses CQRP; TBS input cannot check proof/outer fields; offline mode cannot infer hash size from the subscriber certificate, validate inclusion roots/cosignatures, compare a log entry, establish signer roles, or query Chrome registries; the conditional CQRP `cRLSign` requirement is outside certificate-local scope.

Update REST/OpenAPI examples with all four profile strings and both existing certificate endpoints. Document the existing meta entries for selected profile, native linter versions, availability/applicability, and the explicit skip reason. In README, identify the fork as experimental draft-05 support and link the exact draft and local coverage matrix.

- [ ] **Step 4: Run docs and OpenAPI validation**

Run: `go test ./mtc -run TestRuleCoverageDocument -count=1 && npx --yes @redocly/cli lint doc/openapi.yaml`

Expected: Go test PASS and Redocly reports no OpenAPI errors. Existing upstream warnings are acceptable only if copied verbatim into the verification note.

- [ ] **Step 5: Commit public documentation**

```bash
git add README.md doc/MTC_RULE_COVERAGE.md doc/REST_API.md doc/openapi.yaml mtc
git commit -m "docs: describe MTC and CQRP lint coverage"
```

### Task 10: Fuzzing, Regression, and Container Smoke Test

**Files:**
- Create: `mtc/fuzz_test.go`
- Create: `.github/workflows/test.yml`

- [ ] **Step 1: Add parser fuzz properties**

Seed complete/TBS/proof/CA-extension/CA-ID corpora and assert no panic, bounded allocation behavior through maximum vector lengths, and stable parse classification after copying input bytes.

```go
func FuzzParseMTC(f *testing.F) {
	f.Add(mtctest.Certificate(mtctest.ValidSubscriberTemplate()), uint8(mtc.InputCertificate))
	f.Add(mtctest.TBSCertificate(mtctest.ValidSubscriberTemplate()), uint8(mtc.InputTBSCertificate))
	f.Fuzz(func(t *testing.T, input []byte, rawKind uint8) {
		kind := mtc.InputKind(rawKind%2 + 1)
		first, firstErr := mtc.Parse(input, kind)
		second, secondErr := mtc.Parse(bytes.Clone(input), kind)
		if (firstErr == nil) != (secondErr == nil) { t.Fatal("nondeterministic parse error") }
		if (first == nil) != (second == nil) { t.Fatal("nondeterministic artifact result") }
		if first != nil && second != nil {
			if first.Kind != second.Kind { t.Fatal("nondeterministic classification") }
			if !reflect.DeepEqual(mtc.LintDraft05(first), mtc.LintDraft05(second)) { t.Fatal("nondeterministic draft findings") }
			if !reflect.DeepEqual(mtc.LintCQRP020(first), mtc.LintCQRP020(second)) { t.Fatal("nondeterministic CQRP findings") }
		}
	})
}

func FuzzParseProof(f *testing.F) {
	f.Add(mtctest.ProofBytes(mtctest.ValidSubscriberTemplate().Proof))
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = mtc.ParseProof(input) })
}

func FuzzParseCAExtension(f *testing.F) {
	f.Add(mtctest.ValidCAExtensionDER())
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = mtc.ParseCertificationAuthorityExtension(input) })
}

func FuzzParseCAID(f *testing.F) {
	f.Add(mtctest.ValidCAIDNameDER())
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = mtc.ParseCAIDName(input) })
}
```

- [ ] **Step 2: Run short fuzz sessions**

Run: `go test ./mtc -run '^$' -fuzz FuzzParseMTC -fuzztime=20s && go test ./mtc -run '^$' -fuzz FuzzParseProof -fuzztime=20s && go test ./mtc -run '^$' -fuzz FuzzParseCAExtension -fuzztime=20s && go test ./mtc -run '^$' -fuzz FuzzParseCAID -fuzztime=20s`

Expected: all four complete with `PASS` and no panic or excessive-allocation failure.

- [ ] **Step 3: Add a focused Go verification workflow**

Create `.github/workflows/test.yml` for pull requests and pushes. Use `actions/checkout@v7`, `actions/setup-go@v6` with the version from `go.mod`, then run `go test -race ./...`, `go vet ./...`, `go build ./...`, and the non-fuzz seed-corpus command `go test ./mtc -run Fuzz -count=1`. Do not add a production parsing or cryptographic dependency.

```yaml
name: Go verification
on:
  push:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
          cache: true
      - run: go test -race ./...
      - run: go vet ./...
      - run: go build ./...
      - run: go test ./mtc -run Fuzz -count=1
```

- [ ] **Step 4: Run full verification and smoke the production image**

Run:

```bash
go test -race ./...
go vet ./...
go build ./...
docker build -t mtc-pkimetal:test .
```

Start the image on unused local ports and use the checked-in corpus for the endpoint smoke test:

```bash
docker run --rm -d --name mtc-pkimetal-test -p 18080:8080 -p 18081:8081 mtc-pkimetal:test
curl --fail --retry 30 --retry-delay 1 http://127.0.0.1:18081/readyz
curl --fail --data-urlencode b64cert@mtc/testdata/draft05-standalone.pem --data profile=mtc_subscriber --data format=json http://127.0.0.1:18080/lintcert
curl --fail --data-urlencode b64tbscert@mtc/testdata/draft05-subscriber-tbs.pem --data profile=mtc_subscriber --data format=json http://127.0.0.1:18080/linttbscert
docker stop mtc-pkimetal-test
```

Expected: both POSTs are HTTP 200, `mtclint` appears in complete and TBS processing, and no legacy unsupported-signature finding appears.

- [ ] **Step 5: Inspect the final diff and commit verification**

Run: `git diff --check && git status --short && git log --oneline --decorate -12`

Expected: no whitespace errors; only intended MTC/CQRP source, tests, config, CI, and docs are changed.

```bash
git add mtc .github/workflows/test.yml
git commit -m "test: fuzz and verify MTC linting"
```

## Acceptance Gate

- `go test -race ./...`, `go vet ./...`, and `go build ./...` pass.
- Complete and TBS endpoints accept valid draft-05 CA and subscriber artifacts with ML-DSA SPKI.
- `mtclint` runs on all four profiles; `cqrplint` runs only on CQRP profiles.
- Autodetection selects only `mtc_ca` or `mtc_subscriber`, never a CQRP profile.
- Malformed DER is an HTTP input error; malformed proof inside a valid MTC envelope is a stable fatal lint finding.
- Complete certificates check proof structure; TBS inputs do not report absent proof or outer signature.
- Known zlint conflicts are excluded by exact lint name, compatible checks remain active, and parser-incompatible external linters are not invoked.
- CQRP certificate-local rules are reported separately from draft-05 rules, and the documented online/operational limitations are not presented as successful checks.
- Docker image builds and both certificate endpoints pass smoke tests.
