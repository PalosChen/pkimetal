# MTC Trust Anchor and Tiled Log Linting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add certificate-local Trust Anchor ID, MTC CA algorithm, and C2SP `mtc-tlog` lint rules while preserving separate CA and Subscriber profiles.

**Architecture:** Keep the DER parser policy-neutral and add two focused native rule modules: an allocation-bounded Trust Anchor ID binary validator and an internal `mtc-tlog` CA rule set. Compose draft rules in `mtclint` and CQRP plus mandatory `mtc-tlog` rules in `cqrplint`, with no public profile or endpoint changes.

**Tech Stack:** Go, native pkimetal linter interfaces, strict internal DER parser, table-driven tests, fasthttp production lifecycle tests, Markdown coverage validation.

---

## File Structure

- Create `mtc/trust_anchor_id.go`: validate binary Trust Anchor ID / DER RELATIVE-OID contents without allocating large integers.
- Create `mtc/trust_anchor_id_test.go`: boundary and malformed-encoding unit tests.
- Create `mtc/mtc_tlog.go`: internal C2SP `mtc-tlog` rule registry, strict IA5String and URL parsing, conditional/required entry points.
- Create `mtc/mtc_tlog_test.go`: rule metadata, extension, URL, hash, kind, and input-kind tests.
- Modify `mtc/oid.go`: add the C2SP extension OID and SHA-256 OID used across native rules.
- Modify `mtc/draft05.go`: register Subscriber cosigner ID and CA algorithm compatibility rules.
- Modify `mtc/draft05_test.go`: add rule metadata and focused draft rule tests.
- Modify `mtc/cqrp020.go`: add CQRP CA `sigAlg` rules and merge mandatory `mtc-tlog` findings.
- Modify `mtc/cqrp020_test.go`: add CQRP CA algorithm and mandatory `mtc-tlog` tests.
- Modify `internal/mtctest/builder.go`: provide reusable `mtc-tlog` DER and a conforming CQRP CA template.
- Modify `internal/mtctest/cmd/fixtures/main.go`: retain deterministic fixture generation entry point.
- Create `mtc/testdata/cqrp-ca.pem`: generated conforming CQRP CA fixture.
- Modify `linter/mtclint/handler.go`: merge conditional `mtc-tlog` findings for generic `mtc_ca` only.
- Modify `linter/mtclint/handler_test.go`: verify conditional execution and no duplicate CQRP execution.
- Modify `linter/cqrplint/handler_test.go`: verify mandatory CQRP CA findings and Subscriber isolation.
- Modify `server/mtc_integration_test.go`: exercise the four profiles through the production HTTP lifecycle.
- Modify `doc/MTC_RULE_COVERAGE.md`: document every new stable finding and the fixed C2SP revision.
- Modify `README.md`: describe the certificate-local C2SP coverage and external-state boundary.
- Modify `doc/openapi.yaml`: update profile descriptions without adding API surface.
- Regenerate `doc/openapi.html` with `scripts/build_openapi_html.sh`.

### Task 1: Trust Anchor ID Binary Validator

**Files:**
- Create: `mtc/trust_anchor_id.go`
- Create: `mtc/trust_anchor_id_test.go`
- Modify: `mtc/draft05.go`
- Modify: `mtc/draft05_test.go`
- Modify: `doc/MTC_RULE_COVERAGE.md`

- [ ] **Step 1: Write failing validator and rule tests**

Add table-driven tests that call an unexported `validTrustAnchorIDBinary` and cover these exact classes:

```go
func TestValidTrustAnchorIDBinary(t *testing.T) {
    tests := []struct {
        name string
        id   []byte
        want bool
    }{
        {"example 32473.1", []byte{0x81, 0xfd, 0x59, 0x01}, true},
        {"one zero component", []byte{0x00}, true},
        {"multiple components", []byte{0x01, 0x81, 0x00, 0x7f}, true},
        {"empty", nil, false},
        {"unterminated", []byte{0x81}, false},
        {"non-minimal zero group", []byte{0x80, 0x01}, false},
        {"non-minimal zero", []byte{0x80, 0x00}, false},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            if got := validTrustAnchorIDBinary(tc.id); got != tc.want {
                t.Fatalf("validTrustAnchorIDBinary(%x) = %t, want %t", tc.id, got, tc.want)
            }
        })
    }
}
```

Add a draft rule test using a complete Subscriber proof with one malformed ID and assert exactly one `e_mtc_proof_cosigner_id_malformed`. Add companion cases for valid IDs, TBS input, CA input, and malformed proof to prove applicability and suppression.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
go test ./mtc -run 'TestValidTrustAnchorIDBinary|TestDraft05ProofCosignerIDEncoding' -count=1
```

Expected: build failure because `validTrustAnchorIDBinary` and the new finding are absent.

- [ ] **Step 3: Implement the allocation-bounded validator**

Implement a single linear scan. Reject empty input, a leading zero 7-bit group on a multi-byte component, and a final continuation byte:

```go
func validTrustAnchorIDBinary(input []byte) bool {
    if len(input) == 0 || len(input) > 255 {
        return false
    }
    componentStart := true
    for _, value := range input {
        if componentStart && value == 0x80 {
            return false
        }
        componentStart = value&0x80 == 0
    }
    return componentStart
}
```

Register `e_mtc_proof_cosigner_id_malformed` for `subscriberKinds` and `certificateInputKinds`. Only inspect signatures when `proofAvailable(a)` and skip empty IDs so the existing empty-ID rule retains ownership.

- [ ] **Step 4: Run focused and package tests**

Run:

```bash
go test ./mtc -run 'TestValidTrustAnchorIDBinary|TestDraft05ProofCosignerIDEncoding|TestRuleCoverageDocument' -count=1
go test ./mtc -count=1
```

Expected: focused behavior passes. Add the exact new coverage row before the package run so `TestRuleCoverageDocument` and the complete `mtc` package are green at commit time.

- [ ] **Step 5: Commit the validator and draft rule**

```bash
git add mtc/trust_anchor_id.go mtc/trust_anchor_id_test.go mtc/draft05.go mtc/draft05_test.go doc/MTC_RULE_COVERAGE.md
git commit -m "mtc: validate proof cosigner trust anchor IDs"
```

### Task 2: MTC CA Algorithm Consistency

**Files:**
- Modify: `mtc/oid.go`
- Modify: `mtc/draft05.go`
- Modify: `mtc/draft05_test.go`
- Modify: `internal/mtctest/builder.go`
- Modify: `doc/MTC_RULE_COVERAGE.md`

- [ ] **Step 1: Write failing CA algorithm tests**

Add table cases for CA Certificate and TBS inputs:

```go
tests := []struct {
    name string
    spki mtctest.Algorithm
    sig  mtctest.Algorithm
    want []string
}{
    {"ML-DSA-44 match", alg44, alg44, nil},
    {"ML-DSA-65 match", alg65, alg65, nil},
    {"ML-DSA-87 match", alg87, alg87, nil},
    {"ML-DSA-44 key with ML-DSA-65 signature", alg44, alg65, []string{"e_mtc_ca_signature_algorithm_key_mismatch"}},
    {"ML-DSA signature parameters", alg65, mtctest.Algorithm{OID: mtctest.OIDMLDSA65, ParametersPresent: true, Parameters: []byte{0x05, 0x00}}, []string{"e_mtc_ca_signature_algorithm_parameters_present"}},
}
```

Build each CA extension with `mtctest.CAExtensionDER`, lint it, and assert the exact finding set. Add a non-ML-DSA pair to verify the generic compatibility rule does not guess unsupported algorithm semantics.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
go test ./mtc -run TestDraft05CAAlgorithmConsistency -count=1
```

Expected: FAIL because the two new codes are not emitted.

- [ ] **Step 3: Implement ML-DSA compatibility helpers and rules**

Add shared helpers that recognize pure ML-DSA OIDs and return an algorithm level. Register:

```go
draftRule("e_mtc_ca_signature_algorithm_key_mismatch", "5.5", caKinds, bothInputKinds, evaluateCAAlgorithmCompatibility)
draftRule("e_mtc_ca_signature_algorithm_parameters_present", "5.5", caKinds, bothInputKinds, evaluateCASignatureParameters)
```

Only evaluate when `CAParameters != nil`. Report mismatch when either side is known pure ML-DSA and their OIDs differ; do not equate arbitrary SPKI and signature OIDs.

- [ ] **Step 4: Run package tests**

```bash
go test ./mtc -run 'TestDraft05CAAlgorithmConsistency|TestDraft05ValidArtifactsHaveNoFindings' -count=1
go test ./mtc -count=1
```

Expected: algorithm tests pass. Add exact coverage rows for both codes before the package run so the repository remains green.

- [ ] **Step 5: Commit CA algorithm rules**

```bash
git add mtc/oid.go mtc/draft05.go mtc/draft05_test.go internal/mtctest/builder.go doc/MTC_RULE_COVERAGE.md
git commit -m "mtc: lint CA cosigner algorithm consistency"
```

### Task 3: Internal C2SP mtc-tlog Rule Set

**Files:**
- Create: `mtc/mtc_tlog.go`
- Create: `mtc/mtc_tlog_test.go`
- Modify: `mtc/oid.go`
- Modify: `internal/mtctest/builder.go`
- Modify: `doc/MTC_RULE_COVERAGE.md`

- [ ] **Step 1: Write failing extension and URL tests**

Define `mtctest.OIDMTCTlogPrefixURL` and `mtctest.MTCTlogPrefixURLDER(string)` in test code first. Test conditional generic and required CQRP modes against:

```go
cases := []struct {
    name       string
    extensions []mtctest.Extension
    logHash    mtctest.Algorithm
    required   bool
    want       []string
}{
    {"generic missing accepted", nil, sha256, false, nil},
    {"CQRP missing rejected", nil, sha256, true, []string{"e_cqrp_ca_mtc_tlog_extension_missing"}},
    {"valid HTTPS", []mtctest.Extension{validTlogExtension("https://ca.example/mtc")}, sha256, true, nil},
    {"valid HTTP", []mtctest.Extension{validTlogExtension("http://ca.example/mtc")}, sha256, true, nil},
    {"critical", []mtctest.Extension{criticalTlogExtension()}, sha256, true, []string{"e_mtc_tlog_extension_critical"}},
    {"duplicate", twoTlogExtensions(), sha256, true, []string{"e_mtc_tlog_extension_duplicate"}},
    {"wrong DER tag", []mtctest.Extension{{ID: oid, Value: []byte{0x0c, 0x01, 'x'}}}, sha256, true, []string{"e_mtc_tlog_extension_malformed"}},
    {"relative URL", []mtctest.Extension{validTlogExtension("/mtc")}, sha256, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
    {"userinfo", []mtctest.Extension{validTlogExtension("https://user@ca.example/mtc")}, sha256, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
    {"query", []mtctest.Extension{validTlogExtension("https://ca.example/mtc?q=1")}, sha256, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
    {"fragment", []mtctest.Extension{validTlogExtension("https://ca.example/mtc#x")}, sha256, true, []string{"e_mtc_tlog_prefix_url_invalid"}},
    {"non SHA-256", []mtctest.Extension{validTlogExtension("https://ca.example/mtc")}, otherHash, false, []string{"e_mtc_tlog_log_hash_not_sha256"}},
}
```

Also verify that an opted-in CA reports
`e_mtc_tlog_ca_cosigner_not_mldsa44` unless both its SPKI and CA extension
`sigAlg` identify ML-DSA-44, as required by the C2SP Cosigners section.

Also assert Subscriber artifacts and explicit Subscriber kind contexts produce no `mtc-tlog` findings.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
go test ./mtc -run 'TestMTCTlog|TestParseMTCTlogPrefixURL' -count=1
```

Expected: build failure because the OID, rule entry points, and strict parser do not exist.

- [ ] **Step 3: Implement strict parsing and rule modes**

Add public native entry points used only by adapters:

```go
func LintMTCTlogConditionalForKind(artifact *Artifact, expected ArtifactKind) []Finding
func LintMTCTlogRequiredForKind(artifact *Artifact, expected ArtifactKind) []Finding
func MTCTlogRuleCodes() []string
```

Use a local shallow artifact copy, require `expected == ArtifactCA`, and pass a mode flag into a shared rule evaluator. Parse exactly one primitive universal IA5String with `parseExactDER`, reject bytes above `0x7f`, then use `net/url.Parse`. Accept only lower-case-insensitive `http`/`https`, a non-empty host, and empty `User`, `RawQuery`, and `Fragment`.

Set finding source to `C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105`. Use section name `Parameters` for extension/hash rules. Suppress the URL follow-on when the extension cannot be decoded uniquely. Evaluate the SHA-256 rule independently whenever CA parameters are available, because it does not depend on URL parsing.

- [ ] **Step 4: Run focused tests and race test**

```bash
go test ./mtc -run 'TestMTCTlog|TestParseMTCTlogPrefixURL' -count=1
go test -race ./mtc -run 'TestMTCTlog|TestParseMTCTlogPrefixURL' -count=1
```

Expected: PASS with no duplicate codes and deterministic sorting.

- [ ] **Step 5: Commit internal mtc-tlog rules**

```bash
git add mtc/oid.go mtc/mtc_tlog.go mtc/mtc_tlog_test.go internal/mtctest/builder.go doc/MTC_RULE_COVERAGE.md
git commit -m "mtc: add certificate-local mtc-tlog rules"
```

### Task 4: Compose Generic MTC and CQRP Profiles

**Files:**
- Modify: `mtc/cqrp020.go`
- Modify: `mtc/cqrp020_test.go`
- Modify: `linter/mtclint/handler.go`
- Modify: `linter/mtclint/handler_test.go`
- Modify: `linter/cqrplint/handler_test.go`
- Modify: `internal/mtctest/builder.go`
- Create: `mtc/testdata/cqrp-ca.pem`

- [ ] **Step 1: Write failing profile-composition tests**

Add handler tests proving:

```text
mtc_ca + no extension                 -> no mtc-tlog finding
mtc_ca + malformed extension          -> mtclint emits one malformed finding
cqrp_mtc_ca + no extension            -> cqrplint emits one missing finding
cqrp_mtc_ca + valid extension         -> no mtc-tlog finding
cqrp_mtc_ca + SHA-384                 -> one SHA-256 finding
cqrp_mtc_ca + CA sigAlg ML-DSA-65     -> CQRP CA sigAlg finding
cqrp_mtc_subscriber                   -> no CA/tlog findings
```

Assert each expected `mtc-tlog` code occurs exactly once in the combined response.

- [ ] **Step 2: Run focused tests and verify RED**

```bash
go test ./linter/mtclint ./linter/cqrplint ./mtc -run 'Test.*MTCTlog|TestCQRP020CA.*Algorithm' -count=1
```

Expected: FAIL because handlers do not compose the new rules and the CQRP baseline lacks required fields.

- [ ] **Step 3: Implement profile composition and CQRP CA algorithm rules**

In `mtclint.HandleRequest`, append conditional `mtc-tlog` findings only when `req.ProfileId == linter.MTC_CA`. Do not run them for CQRP profiles.

In `LintCQRP020ForKind`, merge `cqrp020Rules` with required `mtc-tlog` findings only when `expected == ArtifactCA`. Add CQRP rules requiring CA extension `sigAlg` OID ML-DSA-44, absent parameters, and exact `mlDSA44AlgorithmDER` encoding.

Update `ValidCQRPCATemplate` to:

```go
tpl.SPKIAlgorithm = Algorithm{OID: OIDMLDSA44}
ReplaceExtension(&tpl, Extension{
    ID: OIDMTC_CA,
    Critical: true,
    Value: CAExtensionDER(Algorithm{OID: OIDSHA256}, Algorithm{OID: OIDMLDSA44}, big.NewInt(100), big.NewInt(999)),
})
tpl.Extensions = append(tpl.Extensions, Extension{
    ID: OIDMTCTlogPrefixURL,
    Value: MTCTlogPrefixURLDER("https://ca.example/mtc"),
})
```

- [ ] **Step 4: Generate and verify the CQRP CA fixture**

Add `cqrp-ca.pem` to `WriteGeneratedFixtures`, then run:

```bash
go run ./internal/mtctest/cmd/fixtures
go test ./mtc -run 'TestGeneratedFixturesAreCurrent|TestFixtureInteroperability' -count=1
openssl x509 -in mtc/testdata/cqrp-ca.pem -noout -text
```

Expected: fixture reproducibility tests pass; OpenSSL displays both the MTC CA and C2SP extension OIDs without corrupting certificate structure.

- [ ] **Step 5: Run profile tests**

```bash
go test ./mtc ./linter/mtclint ./linter/cqrplint -count=1
go test -race -shuffle=on ./mtc ./linter/mtclint ./linter/cqrplint -count=1
```

Expected: PASS. Add exact CQRP CA `sigAlg` coverage rows before committing so the structured coverage test remains green.

- [ ] **Step 6: Commit composition and fixture changes**

```bash
git add mtc/cqrp020.go mtc/cqrp020_test.go linter/mtclint/handler.go linter/mtclint/handler_test.go linter/cqrplint/handler_test.go internal/mtctest/builder.go mtc/testdata/cqrp-ca.pem
git commit -m "cqrp: enforce certificate-local mtc-tlog profile"
```

### Task 5: Coverage, API Documentation, and HTTP Lifecycle

**Files:**
- Modify: `mtc/draft05_test.go`
- Modify: `mtc/cqrp020_test.go`
- Modify: `mtc/mtc_tlog_test.go`
- Modify: `server/mtc_integration_test.go`
- Modify: `doc/MTC_RULE_COVERAGE.md`
- Modify: `README.md`
- Modify: `doc/openapi.yaml`
- Modify: `doc/openapi.html`

- [ ] **Step 1: Write failing structured coverage and HTTP tests**

Extend the coverage test to include `MTCTlogRuleCodes()` and reject missing or duplicate codes across all native registries. Add exact metadata records for every new code.

Add production HTTP lifecycle cases posting generated CA and Subscriber inputs:

```text
cqrp-ca.pem + cqrp_mtc_ca                       -> HTTP 200, no new error code
generic CA without tlog + mtc_ca                -> HTTP 200, no missing code
generic CA without tlog + cqrp_mtc_ca           -> HTTP 200, missing code exactly once
subscriber + cqrp_mtc_subscriber                -> HTTP 200, no CA/tlog code
malformed cosigner ID + mtc_subscriber          -> HTTP 200, malformed-ID code exactly once
same malformed Subscriber TBS + mtc_subscriber  -> HTTP 200, no proof cosigner code
```

- [ ] **Step 2: Run structured tests and verify RED**

```bash
go test ./mtc -run TestRuleCoverageDocument -count=1
go test ./server -run 'TestMTCCertificateEndpoints/(explicit profiles|tlog and trust anchor rules)' -count=1
```

Expected: FAIL because coverage rows, documentation claims, and lifecycle cases are not yet satisfied.

- [ ] **Step 3: Update coverage and user-facing documentation**

For each finding, document exact source, section, artifact/profile, input applicability, field, severity, and status. Add requirement-level rows stating:

```text
Trust Anchor ID PEN ownership        registry context required       not locally decidable
mtc-tlog endpoints and checkpoints  network/log state required      not locally decidable
Chrome cosigner independence        registry/operator data required not locally decidable
```

Update README profile descriptions to state that CA and Subscriber rules differ, generic MTC uses conditional `mtc-tlog`, and CQRP CA requires it. Update OpenAPI descriptions only; do not add paths, parameters, or profile enum values.

- [ ] **Step 4: Regenerate and validate OpenAPI output**

```bash
./scripts/build_openapi_html.sh
npx --yes @redocly/cli@latest lint doc/openapi.yaml
openapi_sha="$(shasum -a 256 doc/openapi.html | awk '{print $1}')"
./scripts/build_openapi_html.sh
test "$(shasum -a 256 doc/openapi.html | awk '{print $1}')" = "$openapi_sha"
```

Expected: Redocly reports zero errors; the only accepted warning is the pre-existing localhost server warning. Re-run the generation command and require no second diff to prove reproducibility.

- [ ] **Step 5: Run HTTP, coverage, and package tests**

```bash
go test ./mtc ./linter/mtclint ./linter/cqrplint ./request ./server -count=1
go test -race -shuffle=on ./mtc ./linter/mtclint ./linter/cqrplint ./request ./server -count=1
```

Expected: PASS, including `TestRuleCoverageDocument` and production server lifecycle tests.

- [ ] **Step 6: Commit docs and integration coverage**

```bash
git add mtc/draft05_test.go mtc/cqrp020_test.go mtc/mtc_tlog_test.go server/mtc_integration_test.go doc/MTC_RULE_COVERAGE.md README.md doc/openapi.yaml doc/openapi.html
git commit -m "docs: document trust anchor and mtc-tlog coverage"
```

### Task 6: Full Verification and Independent Review

**Files:**
- Modify only files required to fix findings exposed by verification or review.

- [ ] **Step 1: Prepare the existing x509lint native source prerequisite**

Use the repository's established Makefile or pinned-module procedure to copy the six required `linter/x509lint` C/H files temporarily. Confirm the source version comes from `go.mod`; do not commit generated native files.

- [ ] **Step 2: Run complete verification**

```bash
go test ./... -count=1
go test -race -shuffle=on ./... -count=1
go vet ./...
go test ./mtc -run '^$' -fuzz=FuzzParseMTC -fuzztime=15s
go test ./mtc -run '^$' -fuzz=FuzzParseProof -fuzztime=15s
go test ./mtc -run '^$' -fuzz=FuzzParseCAExtension -fuzztime=15s
git diff --check
```

On macOS, retain the repository's documented `CGO_LDFLAGS=-liconv` workaround for full vet/build if the existing x509lint link requires it. Report this platform prerequisite rather than changing MTC code.

- [ ] **Step 3: Verify generated artifacts and clean temporary native files**

```bash
go run ./internal/mtctest/cmd/fixtures
./scripts/build_openapi_html.sh
git status --short
make clean_x509lint
git status --short
```

Expected: fixture and OpenAPI regeneration create no diff; after cleanup, only intentional tracked changes remain and no x509lint C/H workaround files are present.

- [ ] **Step 4: Request independent code review**

Review the complete range from design commit `7a43f40` to HEAD for:

- normative-source correctness;
- CA/Subscriber and Certificate/TBS applicability;
- duplicate findings across `mtclint` and `cqrplint`;
- parser resource bounds and panic safety;
- stable finding metadata and source revision claims;
- fixture consistency; and
- HTTP response compatibility.

Any finding must be reproduced with a failing test before implementation changes.

- [ ] **Step 5: Apply review fixes and repeat affected verification**

For each accepted finding, add a focused RED test, make the smallest fix, run the focused test plus all affected package/race/vet checks, and commit with a finding-specific message.

- [ ] **Step 6: Final repository check**

```bash
git log --oneline 7a43f40..HEAD
git status --short
git diff --check 7a43f40..HEAD
```

Expected: clean worktree, no temporary native files, and a review-approved commit series implementing the approved design.
