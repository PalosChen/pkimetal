# MTC Trust Anchor and Tiled Log Linting Design

Date: 2026-08-13

## Summary

Extend the existing MTC and CQRP certificate linters with requirements that
are locally decidable from one CA or Subscriber Certificate. The extension
covers Trust Anchor ID encoding used by MTCProof, MTC CA algorithm consistency,
and the certificate-local portion of the C2SP `mtc-tlog` profile.

The existing four public profiles, endpoints, request parameters, and artifact
autodetection remain unchanged. CA and Subscriber rules remain distinct and
are selected by the existing immutable `ArtifactKind` classification.

## Source Baselines

- MTC: `draft-ietf-plants-merkle-tree-certs-05`, published 2026-07-06.
- Trust Anchor IDs: `draft-ietf-tls-trust-anchor-ids-04`, published 2026-04-30.
- CQRP: `[Draft] Chrome Quantum-resistant Root Program Policy`, version 0.2.0,
  dated 2026-06-17.
- C2SP `mtc-tlog`: development specification pinned to C2SP repository commit
  `3bc97b2329fee167f7ff39efbbbc316c84876105`.
- C2SP `tlog-tiles`: version 0.1.0 where referenced by `mtc-tlog`.
- ML-DSA algorithm identifiers: RFC 9881.

The C2SP development specification must not be followed from an unpinned
branch at runtime or during tests. A future upstream change requires an
explicit source-baseline update and rule-difference tests.

## Scope

This increment implements only requirements that can be decided from the
submitted Certificate or TBSCertificate. It does not fetch URLs or consume
external CA configuration, log state, cosigner keys, or Chrome registry data.

It does not add a public `mtc_tlog_ca` profile. Instead:

- `mtc_ca` applies the C2SP `mtc-tlog` extension rules conditionally when the
  opt-in extension is present. Absence is valid for a generic draft-05 CA.
- `cqrp_mtc_ca` requires the extension and applies all certificate-local
  `mtc-tlog` constraints because CQRP section 4.6.1 requires that profile.
- Subscriber profiles never inherit CA-only `mtc-tlog` extension rules.

## Rule Composition

| Rule group | `mtc_ca` | `mtc_subscriber` | `cqrp_mtc_ca` | `cqrp_mtc_subscriber` |
| --- | --- | --- | --- | --- |
| draft-05 structural rules | yes | yes | yes | yes |
| MTC CA algorithm rules | yes | no | yes | no |
| Proof cosigner Trust Anchor ID rules | no | complete certificate only | no | complete certificate only |
| `mtc-tlog` extension presence | no | no | required | no |
| Conditional `mtc-tlog` extension validation | when present | no | yes | no |
| Existing CQRP CA rules | no | no | yes | no |
| Existing CQRP Subscriber rules | no | no | no | yes |

Explicitly selecting a profile for the wrong artifact kind continues to
produce the existing profile mismatch finding. A rule set must not mutate or
reclassify the parser-owned artifact to run rules belonging to another kind.

## Trust Anchor ID Validation

MTCProof `cosigner_id` is the binary representation of a Trust Anchor ID: the
contents octets of a DER RELATIVE-OID, without its tag and length. The existing
one-byte TLS vector length already limits the value to 255 bytes.

Add a reusable, allocation-bounded validator for this binary representation.
For each non-empty cosigner ID it must reject:

- an unterminated base-128 component;
- a component that is not minimally encoded, including a leading zero group;
- a component boundary that is invalid under DER RELATIVE-OID encoding; and
- any representation that cannot be decoded without consuming all bytes.

The validator does not query IANA and does not assert that the leading PEN is
allocated to the claimed operator. Registry ownership is an external policy
check.

Add `e_mtc_proof_cosigner_id_malformed` with source
`draft-ietf-tls-trust-anchor-ids-04`, section 3, field
`signatureValue.signatures.cosigner_id`, and severity `error`. It applies only
to complete Subscriber Certificates with an available, successfully parsed
MTCProof. Existing empty, ordering, and duplicate findings remain independent.

## MTC CA Algorithm Validation

The draft-05 CA extension contains the issuance-log hash AlgorithmIdentifier
and the CA cosigner signature AlgorithmIdentifier. Add local rules without
turning the draft's SHA-256 recommendation into a generic requirement.

- `e_mtc_ca_signature_algorithm_key_mismatch` checks algorithm-specific
  compatibility between the CA extension `sigAlg` and the CA cosigner SPKI.
  ML-DSA-44, ML-DSA-65, and ML-DSA-87 must use the corresponding algorithm on
  both sides. The rule must not assume byte equality for unrelated algorithm
  families where public-key and signature OIDs may legitimately differ.
- `e_mtc_ca_signature_algorithm_parameters_present` rejects parameters on a
  pure ML-DSA CA extension `sigAlg`, as required by RFC 9881.
- CQRP CA validation requires the CA extension `sigAlg` to be ML-DSA-44 and to
  use its canonical parameter-free AlgorithmIdentifier encoding.
- Generic draft-05 CAs are not rejected merely because `logHash` is not
  SHA-256. The draft only recommends SHA-256.

Rules that require decoded CA parameters skip evaluation when the existing CA
extension malformed finding applies, so one malformed encoding does not cause
cascading or contradictory findings.

## C2SP mtc-tlog Extension Validation

The opt-in extension has OID `1.3.6.1.4.1.64829.2.1`. Its `extnValue` contains
exactly one DER IA5String whose contents are the CA prefix URL, and the X.509
extension is non-critical.

Add the following findings:

- `e_cqrp_ca_mtc_tlog_extension_missing` for a CQRP CA without the extension.
- `e_mtc_tlog_extension_duplicate` when more than one extension is present.
- `e_mtc_tlog_extension_critical` when the extension is critical.
- `e_mtc_tlog_extension_malformed` when the value is not one exact canonical
  DER IA5String or contains non-ASCII data.
- `e_mtc_tlog_prefix_url_invalid` when the IA5String is not a usable absolute
  HTTP or HTTPS URL prefix.
- `e_mtc_tlog_log_hash_not_sha256` when an opted-in CA does not use SHA-256.

A usable URL prefix has an `http` or `https` scheme and a non-empty host. It
must not contain user information, a query, or a fragment. The lint does not
resolve the host, make a network request, constrain the operator's domain or
path layout, or reject HTTP based on a preference not stated by the profile.

For generic `mtc_ca`, the duplicate, critical, malformed, URL, and hash rules
run only when the extension is present. For `cqrp_mtc_ca`, the missing rule is
also active. A malformed or duplicate extension suppresses dependent URL
checks while independent criticality checks may still be reported.

## Architecture and Data Flow

The strict MTC parser remains a structural parser rather than a policy engine.
It continues to preserve raw extensions and decoded CA parameters in the
immutable Artifact.

- Shared Trust Anchor ID and strict IA5String helpers live in the `mtc`
  package and have bounded work proportional to their small encoded inputs.
- Draft-05 CA algorithm and Subscriber cosigner ID rules join the existing
  draft rule registry.
- Internal `mtc-tlog` rules are evaluated by `mtclint` for opted-in generic CA
  artifacts and by `cqrplint` for CQRP CA artifacts.
- The CQRP handler merges CQRP and `mtc-tlog` findings through the existing
  adapter, preserving the current JSON, HTML, and text response schemas.
- Finding sorting and panic recovery continue to use the existing native rule
  runner.

No linter registration, public profile, endpoint, request field, configuration
key, or autodetection behavior changes in this increment.

## Error Handling

Malformed optional structures remain lintable whenever their outer certificate
structure is parseable. Findings should identify the narrowest field and
source section available.

Parsing failures produce one primary malformed finding. Rules depending on the
failed value do not emit speculative follow-on errors. Independent properties,
such as extension criticality, may still be reported. Unexpected panics remain
converted to the existing `b_mtc_rule_panic` finding.

## Verification

Tests must cover:

- strict CA-versus-Subscriber rule isolation for all four profiles;
- complete Certificate versus TBSCertificate applicability;
- valid, unterminated, non-minimal, multi-component, and 255-byte-boundary
  Trust Anchor ID representations;
- ML-DSA-44, ML-DSA-65, and ML-DSA-87 matching and mismatching CA algorithms;
- pure ML-DSA AlgorithmIdentifier parameter presence and exact CQRP ML-DSA-44
  encoding;
- absent, duplicate, critical, malformed, non-ASCII, invalid-URL, and valid
  `mtc-tlog` extensions;
- non-SHA-256 hash behavior for generic MTC, opted-in MTC, and CQRP CA;
- a generic MTC CA without the extension producing no `mtc-tlog` error;
- a CQRP CA without the extension producing the missing-extension error;
- CQRP Subscriber artifacts not receiving CA-only findings;
- all four existing profiles through the production HTTP lifecycle;
- stable finding metadata and complete rule-coverage documentation; and
- deterministic behavior under unit, shuffled, race, vet, fuzz-seed, and diff
  checks.

Fixtures that represent conforming CQRP CAs must be updated to include the
required `mtc-tlog` extension, SHA-256 log hash, and ML-DSA-44 CA extension
signature algorithm. Generated documentation must remain reproducible.

## Deferred Work

The following requirements need additional inputs or network state and remain
outside this certificate-lint increment:

- Merkle inclusion and consistency proof cryptographic verification;
- cosignature verification and signer-role classification;
- Chrome cosigner registry status and operator independence;
- issuance-log checkpoint, tile, entry bundle, landmark, cache, and retention
  checks;
- witness and mirror protocol conformance;
- Trust Anchor ID PEN ownership checks;
- Trust Anchor ID X.509 extension linting while its standard OID remains TBD;
- CertificatePropertyList, certificate-chain-with-properties, TLS
  `trust_anchors`, DNS, and ACME negotiation checks; and
- CQRP CRL and operational availability requirements.

These capabilities should be designed as context-aware or online audit inputs,
not as hard failures on the existing single-certificate endpoints.
