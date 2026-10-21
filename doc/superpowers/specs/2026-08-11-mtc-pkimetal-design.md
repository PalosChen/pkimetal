# MTC and CQRP Linting Design

Date: 2026-08-11

## Summary

Extend a fork of `pkimetal` with offline linting for Merkle Tree Certificates
(MTCs). The first release targets
`draft-ietf-plants-merkle-tree-certs-05` and the certificate-local requirements
from Chrome Quantum-resistant Root Program (CQRP) Policy v0.2.0.

The project retains pkimetal's REST API, web interface, unified finding format,
and existing linters. It adds two independent, in-process Go linters:

- `mtclint` checks the MTC draft.
- `cqrplint` checks CQRP policy requirements and only runs for an explicit CQRP
  profile.

Both complete certificates and to-be-signed certificates are supported through
the existing `/lintcert` and `/linttbscert` endpoints.

## Goals

- Detect certificate-local violations of MTC draft-05 without network access,
  trust-store state, log state, or cosigner public keys.
- Check both MTC CA Cosigning Certificates and MTC Subscriber Certificates.
- Check both complete Certificate structures and DER-encoded TBSCertificate
  structures.
- Keep MTC draft findings separate from CQRP findings.
- Continue running traditional X.509 linters where their rules are applicable
  to MTCs, without reporting known conflicts as failures.
- Return stable finding codes, source versions, and explicit coverage data.
- Preserve pkimetal API behavior for all existing profiles.

## Non-Goals

- Cryptographic verification of subtree inclusion proofs or cosignatures.
- Fetching issuance logs, checkpoints, landmarks, Chrome cosigner data, or
  other online state.
- Verifying that a CQRP standalone certificate contains one CA cosignature and
  one independent Chrome-recognized mirror cosignature. The offline check can
  only enforce the minimum signature count.
- Checking CRL profiles in the first release.
- Checking HSM controls, ACME behavior, log availability, landmark frequency,
  organizational independence, audits, or other operational CQRP requirements.
- Reimplementing all RFC 5280 or CA/Browser Forum TLS Baseline Requirements
  rules inside `mtclint` or `cqrplint`.

## Source Baselines

- MTC: `draft-ietf-plants-merkle-tree-certs-05`, published 2026-07-06.
- CQRP: `[Draft] Chrome Quantum-resistant Root Program Policy`, version 0.2.0,
  dated 2026-06-17.
- Unsigned CA certificates: RFC 9925.
- ML-DSA algorithm identifiers: RFC 9881.
- Traditional certificate rules: the versions embedded in the selected
  pkimetal release and its linter dependencies.

The rule implementations are versioned internally as `draft05` and `cqrp020`.
Future policy or draft updates must be implemented as an explicit version
upgrade with rule-difference tests. Rules from different versions are not
silently combined.

## Profiles

Add four explicit profiles:

| Profile | Artifact | Rule composition |
| --- | --- | --- |
| `mtc_ca` | MTC CA Cosigning Certificate | RFC 5280/RFC 9925 compatible rules + MTC draft-05 |
| `mtc_subscriber` | MTC Subscriber Certificate | Compatible RFC 5280 rules + MTC draft-05 |
| `cqrp_mtc_ca` | CQRP MTC CA Cosigning Certificate | `mtc_ca` + CQRP v0.2.0 CA rules |
| `cqrp_mtc_subscriber` | CQRP TLS Subscriber Certificate | `mtc_subscriber` + compatible TLS BR rules + CQRP v0.2.0 subscriber rules |

Autodetection selects only draft profiles. A Certificate or TBSCertificate with
`id-alg-mtcProof` is detected as `mtc_subscriber`. A certificate with the
critical `id-pe-mtcCertificationAuthority` extension is detected as `mtc_ca`.
An artifact matching both forms is malformed and produces a type-conflict
finding.

CQRP profiles are never autodetected. CQRP conformance is an asserted policy
intent, not a fact that can be inferred from certificate syntax, so callers
must select a CQRP profile explicitly.

## Architecture

### MTC-Aware Input Path

The current pkimetal request path parses every certificate with zcrypto before
dispatching it to linters. MTC support must not depend on zcrypto recognizing
`id-alg-mtcProof`, ML-DSA public keys, MTC proof bytes, or RFC 9925 unsigned
certificates.

Add a strict, read-only DER envelope parser before the generic X.509 parse. It
extracts the outer Certificate fields and raw TBSCertificate without requiring
known signature or public-key algorithms. For `/linttbscert`, it accepts the
raw TBSCertificate directly and records that outer-certificate checks are not
applicable.

The request carries both representations when available:

- the original input bytes;
- an immutable MTC artifact model built from raw DER;
- the existing zcrypto Certificate, if generic parsing succeeds; and
- the endpoint/input kind so rules can distinguish complete and TBS inputs.

A generic-parser failure does not reject an otherwise recognizable MTC input.
It instead makes generic-parser-dependent linters inapplicable. Existing
non-MTC profiles retain their current parsing behavior.

### Shared Artifact Model

The MTC artifact model exposes raw encodings as well as decoded values for:

- Certificate and TBSCertificate algorithm identifiers;
- serial number, issuer, subject, validity, SPKI, and extensions;
- CA ID distinguished names;
- `MTCCertificationAuthority` fields;
- MTCProof extensions, subtree range, inclusion-proof byte vector, and
  signatures; and
- exact byte offsets used for field-specific findings.

Parsing code is shared by both linters. Rule registration and rule evaluation
remain separate so CQRP changes cannot alter MTC draft results.

### Linter Applicability

New profiles use an explicit compatibility matrix instead of pkimetal's current
implicit rule that a linter supports every profile unless excluded.

- `mtclint` runs for all four MTC profiles.
- `cqrplint` runs only for the two CQRP profiles.
- Traditional linters run only after their MTC compatibility has been verified
  with the conformance corpus.
- Linters with stable finding codes may use a profile-specific exclusion list
  for rules that conflict with MTC or CQRP. Every exclusion records the
  superseding specification section and has a regression test.
- Linters whose findings cannot be excluded reliably are marked not applicable
  until they provide MTC support.
- No synthetic conventional certificate is substituted for the original MTC.
  Rewriting signature or SPKI fields would hide the bytes actually being
  linted.

The precedence rule is narrow: CQRP overrides the TLS BR only where CQRP
explicitly modifies it, and MTC draft-05 overrides RFC 5280 only where the
draft explicitly modifies it. All non-conflicting underlying requirements
continue to apply.

## Request Data Flow

1. Decode the transport representation (form Base64/PEM or binary body).
2. Strictly parse the DER Certificate envelope or TBSCertificate envelope.
3. Classify the MTC artifact from raw algorithm identifiers and extensions.
4. Autodetect a draft profile or validate the caller's explicit profile.
5. Build the immutable MTC artifact model.
6. Route the request using the profile compatibility matrix.
7. Run applicable linters concurrently through pkimetal's existing request
   fan-out.
8. Aggregate and sort findings in the existing response format.
9. Include meta findings that identify the selected profile, rule-source
   versions, and linters skipped as not applicable.

## MTC Draft Rule Coverage

### Common DER and Algorithm Rules

- Require canonical DER and complete input consumption with no trailing data.
- Require valid Certificate and TBSCertificate field structure.
- For Subscriber Certificates, require the inner and outer algorithm
  identifiers to use the draft-05 experimental `id-alg-mtcProof` OID and omit
  parameters.
- For complete certificates, require a byte-aligned signature BIT STRING and
  decode its contents directly as MTCProof without additional ASN.1 wrapping.

### MTC CA Cosigning Certificate Rules

- Require the subject to be the draft-05 CA ID distinguished name.
- Require the critical experimental `id-pe-mtcCertificationAuthority`
  extension and decode `logHash`, `sigAlg`, `minSerial`, and `maxSerial`.
- Require serial bounds within the ASN.1 range and `minSerial <= maxSerial`.
- Require KeyUsage with at least `keyCertSign` and BasicConstraints with
  `cA = TRUE`.
- If SubjectKeyIdentifier is present, warn when it does not encode the CA ID.
- Check RFC 9925 encoding when the certificate uses `id-alg-unsigned`.
- Warn on a structurally self-issued CA certificate where draft-05 recommends
  an unsigned trust-anchor representation. This does not claim cryptographic
  self-signature verification.

### MTC Subscriber Certificate Rules

- Require the issuer to use the CA ID distinguished-name form.
- Require a positive serial number no greater than `2^64 - 1`.
- Split the serial into a positive 16-bit log number and a 48-bit entry index.
- Strictly decode all MTCProof TLS vectors and reject truncation, overflow, and
  trailing data.
- Require `start < end`, uint48 bounds, a valid subtree, and inclusion of the
  serial-derived entry index in `[start, end)`.
- Require proof extensions to be ordered and unique as specified by draft-05.
- Require non-empty cosigner IDs, unique IDs, and draft-05 canonical ordering:
  shorter IDs first, then lexicographic order among equal lengths.
- Classify an empty signatures vector as landmark-relative and a non-empty
  signatures vector as standalone.

The Subscriber Certificate does not contain the CA's `logHash` algorithm.
Without external CA configuration, the linter can validate the
inclusion-proof vector's framing but cannot split it into hash values, validate
the expected number of hashes, derive an authoritative subtree root, or compare
that root with a trusted value. Those checks remain explicitly uncovered in
the offline release.

Similarly, the linter can validate extension encoding in both the
TBSCertificate and MTCProof, but cannot prove both came from the same external
TBSCertificateLogEntry because that log entry is not part of the request.

### TBS Behavior

`/linttbscert` runs every rule decidable from the TBSCertificate. Outer
signatureAlgorithm, signatureValue, MTCProof, and standalone/landmark-relative
rules are marked not applicable and do not produce warnings or errors.

## CQRP v0.2.0 Rule Coverage

### CA Cosigning Certificate

- Require an ML-DSA-44 SPKI OID.
- Require absent ML-DSA parameters and the exact AlgorithmIdentifier encoding
  specified by CQRP.
- Reject HashML-DSA identifiers.
- Require critical KeyUsage and `keyCertSign`.

The conditional `cRLSign` rule depends on whether this CA key issues
certificates longer than seven days. A CA certificate alone does not declare
that issuance policy, so the condition is documented as not locally
decidable rather than guessed.

### Subscriber TLS Certificate

- Require a validity period no longer than 47 days.
- Permit the TLS BR public-key algorithms plus CQRP's ML-DSA-44, ML-DSA-65,
  and ML-DSA-87 identifiers.
- For ML-DSA, require absent parameters, reject HashML-DSA, and require the
  exact AlgorithmIdentifier encoding specified by CQRP.
- Require an empty subject when the DV policy OID `2.23.140.1.2.1` is asserted.
- Require a non-critical CertificatePolicies extension and an allowed TLS BR
  policy identifier.
- Require a non-critical ExtendedKeyUsage extension containing only
  `id-kp-serverAuth`.
- If IssuerAlternativeName is present, require it to be non-critical and
  contain only the permitted cosmetic `directoryName` form.
- Reject the Signed Certificate Timestamp List extension.
- For a standalone certificate, require at least two cosignatures.

The two-signature rule does not establish signer roles or operator
independence. That needs Chrome's cosigner registry and is outside the offline
scope. A single input also cannot prove that the CA offers matching standalone
and landmark-relative certificates derived from the same log entry.

CQRP table cells that are blank and requirements carrying unresolved editorial
markers do not produce inferred rules.

## Findings and Errors

Keep pkimetal's existing response fields: linter, severity, finding, field, and
code. Rule-source versions and section references appear in linter metadata and
finding descriptions.

Stable codes use source-specific prefixes, for example:

- `e_mtc_proof_cosigner_order`
- `e_mtc_serial_log_number_zero`
- `e_cqrp_subscriber_eku_only_server_auth`

Severity mapping is deterministic:

- unsafe or incomplete parsing that prevents further checks: `fatal`;
- violation of MUST, MUST NOT, REQUIRED, or SHALL: `error`;
- violation of SHOULD, SHOULD NOT, or RECOMMENDED: `warning`;
- internal linter failure or recovered panic: `bug`.

MAY and OPTIONAL statements do not produce findings. Policy blanks, unresolved
editorial markers, and requirements that need unavailable external state are
documented in coverage, not reported as success or failure.

Transport failures such as empty input, invalid Base64/PEM, or data that cannot
be identified as a certificate return HTTP 400. Once a certificate envelope is
recognized, malformed MTC contents return HTTP 200 with a precise fatal finding
so lint clients receive actionable details. A profile/artifact mismatch is a
normal lint finding. A failure in one rule does not suppress independent rules.

## Coverage Reporting

Each response includes pkimetal meta findings for:

- selected profile;
- MTC draft version;
- CQRP version when applicable;
- each configured linter's available/applicable status; and
- a reason when a linter is skipped for MTC incompatibility.

The repository also contains a human-readable rule coverage matrix. It maps
each implemented or excluded rule to a source section, input kinds, finding
code, test case, and one of: implemented, delegated, not applicable, or not
locally decidable. Coverage must never represent an unexecuted check as passed.

## Testing

### Parser Tests

Use focused DER and TLS-vector tests for valid input and for truncation,
non-canonical length encoding, overflow, invalid BIT STRING lengths, duplicate
items, incorrect order, and trailing data.

### Rule Tests

Every MTC and CQRP rule has at least one passing and one failing table-driven
test. The expected stable code, severity, field, source version, and section are
asserted.

### API Tests

Exercise `/lintcert` and `/linttbscert` with form Base64/PEM and their binary
content types. Cover all four profiles, draft autodetection, explicit CQRP
selection, type mismatch, malformed input, and empty finding responses.

### Compatibility Tests

Maintain a corpus containing:

- independently encoded valid draft-05 CA and Subscriber artifacts;
- standalone and landmark-relative certificate pairs;
- artifacts produced by the local MTC CA implementation;
- ML-DSA-44, ML-DSA-65, and ML-DSA-87 Subscriber SPKIs;
- CQRP-compliant and single-fault CQRP-invalid samples; and
- mutations for every documented traditional-linter conflict.

The compatibility tests prove that a valid MTC does not fail solely because a
traditional linter applies a superseded rule. They also prove that compatible
RFC 5280 and TLS BR violations remain visible.

### Fuzzing and Regression

Fuzz the Certificate/TBSCertificate envelope, MTC CA extension, CA ID name, and
MTCProof parsers. Acceptance requires no panic, no unbounded allocation, no
out-of-bounds read, and deterministic findings for identical input.

Run the complete upstream pkimetal test suite to protect all existing profiles.
Build the production Docker image and smoke-test both MTC endpoints before
release.

## Repository and Delivery

The implementation lives in the sibling repository `mtc-pkimetal`, forked with
the complete pkimetal history. The upstream repository is configured as the
`upstream` remote. Development occurs on `feature/mtc-lint`.

The fork remains subject to pkimetal's GPLv3 license. The first implementation
does not add a production dependency for MTC parsing or cryptographic
verification; it uses Go code scoped to strict structural parsing and lint
evaluation.

## Acceptance Criteria

- All four profiles are listed by `/profiles` with correct linter applicability.
- Draft profiles autodetect correctly; CQRP profiles require explicit selection.
- Complete and TBS endpoints accept valid draft-05 artifacts.
- Valid draft-05 artifacts do not receive findings from known-conflicting
  traditional rules.
- Every implemented MTC/CQRP MUST violation has a stable error code and a
  negative test.
- Every implemented SHOULD violation has a stable warning code and a negative
  test.
- Coverage explicitly lists delegated and not-locally-decidable requirements.
- Malformed MTC structures cannot panic or terminate the service.
- Existing pkimetal tests pass unchanged in behavior.
- The production Docker image builds and passes endpoint smoke tests.
