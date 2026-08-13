# MTC and CQRP rule coverage

This fork implements experimental Merkle Tree Certificate (MTC) linting against
[draft-ietf-plants-merkle-tree-certs-05](https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-05),
the unsigned-certificate requirements in [RFC 9925](https://www.rfc-editor.org/rfc/rfc9925.html),
and a user-supplied local CQRP v0.2.0 draft baseline. The CQRP baseline is not a
reference to a later or generic MTC Internet-Draft.

## Profiles and precedence

The explicit profiles are `mtc_ca`, `mtc_subscriber`, `cqrp_mtc_ca`, and
`cqrp_mtc_subscriber`. The two CQRP profiles run both `mtclint` for the draft-05
base profile and `cqrplint` for the CQRP overlay. CQRP overrides the TLS Baseline
Requirements only where CQRP v0.2.0 says so explicitly. Likewise, draft-05
overrides RFC 5280 only where draft-05 says so explicitly; compatible RFC 5280
and TLS checks remain delegated to other registered linters.

Omitting `profile`, or selecting `autodetect`, may select `mtc_ca` or
`mtc_subscriber` from MTC structure. Autodetection never selects a CQRP profile,
because CQRP is an explicit policy assertion rather than an encoding property.
Selecting a CA profile for a subscriber artifact, or the reverse, produces the
profile/artifact mismatch finding while still evaluating the explicitly chosen
profile. An artifact containing both the MTC CA extension and the
`id-alg-mtcProof` TBSCertificate signature algorithm remains classified as a CA
for lintability and produces a separate type-conflict finding.

## Applicability and limits

`/lintcert` supplies a complete Certificate. `/linttbscert` supplies only a
TBSCertificate, so TBS linting cannot inspect or validate the outer
signatureAlgorithm, signatureValue, MTC proof, or proof cosignature fields.
Rows marked "Certificate and TBS" contain only checks decidable from both input
forms; rows marked "Certificate only" need the outer Certificate or proof.

The native parsers preserve recognized MTC artifacts even when zcrypto cannot
safely parse them. A linter must explicitly register support for an MTC profile.
When zlint is registered for the selected profile but has no usable zcrypto
Certificate, it is skipped with the exact reason
`zcrypto could not safely parse this MTC artifact`. The response reports this as
availability/applicability metadata rather than silently treating the linter as
successful.

Linting is offline and structural. It cannot infer the Merkle hash size from a
subscriber certificate; validate inclusion roots, proof hashes, or
cosignatures; compare an external log entry; establish signer/operator roles or
their independence; or query Chrome registries. CQRP's conditional `cRLSign`
requirements depend on external CA role and CRL behavior and are outside local
certificate scope. RFC 9925 checks are conditional on the unsigned algorithm and
cover matching algorithm identifiers, absent parameters, an empty outer
signature, absent issuerUniqueID, and warnings for authorityKeyIdentifier or
issuerAltName.

## Stable finding codes

Every implemented stable finding code appears exactly once below. "Artifact / profile"
describes the profile context in which the rule is registered, not a claim that
every input will trigger the finding. The Source column records exact finding
wire metadata; CQRP rows therefore use `CQRP v0.2.0`, while the implementation
baseline remains the user-supplied local draft described above.

### Draft-05 and conditional RFC 9925

| Code | Source | Section | Artifact / profile | Input applicability | Field(s) | Severity | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `e_mtc_artifact_type_conflict` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 and 6.2 | CA or subscriber / all four MTC profiles | Certificate and TBS | tbsCertificate.signature,tbsCertificate.extensions.mtcCertificationAuthority | error | implemented |
| `e_mtc_ca_basic_constraints_missing` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.basicConstraints | error | implemented |
| `e_mtc_ca_basic_constraints_not_ca` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.basicConstraints | error | implemented |
| `e_mtc_ca_extension_missing` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions | error | implemented |
| `e_mtc_ca_extension_not_critical` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions | error | implemented |
| `e_mtc_ca_key_cert_sign_missing` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.keyUsage | error | implemented |
| `e_mtc_ca_key_usage_missing` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.keyUsage | error | implemented |
| `e_mtc_ca_signature_algorithm_key_mismatch` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcCertificationAuthority.sigAlg | error | implemented |
| `e_mtc_ca_signature_algorithm_parameters_present` | RFC 9881 | 2 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcCertificationAuthority.sigAlg.parameters | error | implemented |
| `e_mtc_ca_serial_range_invalid` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcCertificationAuthority | error | implemented |
| `e_mtc_ca_subject_not_ca_id` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.subject | error | implemented |
| `e_mtc_cert_signature_algorithm_mismatch` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureAlgorithm | error | implemented |
| `e_mtc_proof_cosigner_duplicate` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.signatures.cosigner_id | error | implemented |
| `e_mtc_proof_cosigner_id_empty` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.signatures.cosigner_id | error | implemented |
| `e_mtc_proof_cosigner_id_malformed` | draft-ietf-tls-trust-anchor-ids-04 | 3 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.signatures.cosigner_id | error | implemented |
| `e_mtc_proof_cosigner_order` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.signatures.cosigner_id | error | implemented |
| `e_mtc_proof_extensions_duplicate` | draft-ietf-plants-merkle-tree-certs-05 | 5.2.1 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.extensions | error | implemented |
| `e_mtc_proof_extensions_order` | draft-ietf-plants-merkle-tree-certs-05 | 5.2.1 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.extensions | error | implemented |
| `e_mtc_proof_index_outside_range` | draft-ietf-plants-merkle-tree-certs-05 | 4.3.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.start,end | error | implemented |
| `e_mtc_proof_range_invalid` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.start,end | error | implemented |
| `e_mtc_proof_subtree_invalid` | draft-ietf-plants-merkle-tree-certs-05 | 4.1 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue.start,end | error | implemented |
| `e_mtc_serial_log_number_zero` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate and TBS | tbsCertificate.serialNumber | error | implemented |
| `e_mtc_serial_non_positive` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate and TBS | tbsCertificate.serialNumber | error | implemented |
| `e_mtc_serial_too_large` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate and TBS | tbsCertificate.serialNumber | error | implemented |
| `e_mtc_signature_algorithm_oid` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate and TBS | signatureAlgorithm; tbsCertificate.signature | error | implemented |
| `e_mtc_signature_algorithm_parameters_present` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate and TBS | signatureAlgorithm.parameters; tbsCertificate.signature.parameters | error | implemented |
| `e_mtc_signature_value_unused_bits` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue | error | implemented |
| `e_mtc_subscriber_issuer_not_ca_id` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate and TBS | tbsCertificate.issuer | error | implemented |
| `e_rfc9925_unsigned_algorithm_mismatch` | RFC 9925 | 3.1 | Unsigned CA / MTC and CQRP CA | Certificate only | signatureAlgorithm | error | implemented |
| `e_rfc9925_unsigned_issuer_unique_id_present` | RFC 9925 | 3.2 | Unsigned CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.issuerUniqueID | error | implemented |
| `e_rfc9925_unsigned_parameters_present` | RFC 9925 | 3.1 | Unsigned CA / MTC and CQRP CA | Certificate and TBS | signatureAlgorithm.parameters | error | implemented |
| `e_rfc9925_unsigned_signature_not_empty` | RFC 9925 | 3.1 | Unsigned CA / MTC and CQRP CA | Certificate only | signatureValue | error | implemented |
| `f_mtc_ca_extension_malformed` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions | fatal | implemented |
| `f_mtc_proof_malformed` | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | Subscriber / MTC and CQRP subscriber | Certificate only | signatureValue | fatal | implemented |
| `w_mtc_ca_self_issued` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.issuer | warning | implemented |
| `w_mtc_ca_ski_not_ca_id` | draft-ietf-plants-merkle-tree-certs-05 | 5.5 | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.subjectKeyIdentifier | warning | implemented |
| `w_rfc9925_unsigned_authority_key_identifier_present` | RFC 9925 | 3.3 | Unsigned CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.authorityKeyIdentifier | warning | implemented |
| `w_rfc9925_unsigned_issuer_alternative_name_present` | RFC 9925 | 3.3 | Unsigned CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.issuerAlternativeName | warning | implemented |

### C2SP mtc-tlog certificate overlay

The C2SP rules are pinned to repository commit
`3bc97b2329fee167f7ff39efbbbc316c84876105`. Generic MTC CAs opt in by
including the prefix URL extension; CQRP CAs require the extension through
CQRP section 4.6.1.

| Code | Source | Section | Artifact / profile | Input applicability | Field(s) | Severity | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `e_cqrp_ca_mtc_tlog_extension_missing` | CQRP v0.2.0 | 4.6.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcTlogPrefixURL | error | implemented |
| `e_mtc_tlog_ca_cosigner_not_mldsa44` | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Cosigners | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm,tbsCertificate.extensions.mtcCertificationAuthority.sigAlg | error | implemented |
| `e_mtc_tlog_extension_critical` | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Parameters | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcTlogPrefixURL | error | implemented |
| `e_mtc_tlog_extension_duplicate` | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Parameters | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcTlogPrefixURL | error | implemented |
| `e_mtc_tlog_extension_malformed` | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Parameters | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcTlogPrefixURL | error | implemented |
| `e_mtc_tlog_log_hash_not_sha256` | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Parameters | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcCertificationAuthority.logHash | error | implemented |
| `e_mtc_tlog_prefix_url_invalid` | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Parameters | CA / MTC and CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcTlogPrefixURL | error | implemented |

### CQRP v0.2.0 overlay

| Code | Source | Section | Artifact / profile | Input applicability | Field(s) | Severity | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `e_cqrp_ca_hash_mldsa` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm | error | implemented |
| `e_cqrp_ca_key_usage_not_critical` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.extensions.keyUsage | error | implemented |
| `e_cqrp_ca_signature_algorithm` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcCertificationAuthority.sigAlg | error | implemented |
| `e_cqrp_ca_signature_algorithm_encoding` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcCertificationAuthority.sigAlg | error | implemented |
| `e_cqrp_ca_signature_parameters_present` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.extensions.mtcCertificationAuthority.sigAlg.parameters | error | implemented |
| `e_cqrp_ca_spki_algorithm` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm | error | implemented |
| `e_cqrp_ca_spki_encoding` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm; tbsCertificate.subjectPublicKeyInfo.subjectPublicKey | error | implemented |
| `e_cqrp_ca_spki_parameters_present` | CQRP v0.2.0 | 4.5.1 | CA / CQRP CA | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm.parameters | error | implemented |
| `e_cqrp_subscriber_dv_subject_not_empty` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.subject | error | implemented |
| `e_cqrp_subscriber_eku_critical` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.extKeyUsage | error | implemented |
| `e_cqrp_subscriber_eku_missing` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.extKeyUsage | error | implemented |
| `e_cqrp_subscriber_eku_only_server_auth` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.extKeyUsage | error | implemented |
| `e_cqrp_subscriber_hash_mldsa` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm | error | implemented |
| `e_cqrp_subscriber_ian_critical` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.issuerAlternativeName | error | implemented |
| `e_cqrp_subscriber_ian_form` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.issuerAlternativeName | error | implemented |
| `e_cqrp_subscriber_mldsa_encoding` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm; tbsCertificate.subjectPublicKeyInfo.subjectPublicKey | error | implemented |
| `e_cqrp_subscriber_mldsa_parameters_present` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.subjectPublicKeyInfo.algorithm.parameters | error | implemented |
| `e_cqrp_subscriber_policies_critical` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.certificatePolicies | error | implemented |
| `e_cqrp_subscriber_policies_missing` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.certificatePolicies | error | implemented |
| `e_cqrp_subscriber_policy_identifier` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.certificatePolicies | error | implemented |
| `e_cqrp_subscriber_sct_present` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.signedCertificateTimestampList | error | implemented |
| `e_cqrp_subscriber_standalone_cosignatures` | CQRP v0.2.0 | 4.7 | Subscriber / CQRP subscriber | Certificate only | signatureValue.signatures | error | implemented |
| `e_cqrp_subscriber_validity_too_long` | CQRP v0.2.0 | 2.1 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.validity | error | implemented |
| `w_cqrp_subscriber_ian_name_attributes` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.issuerAlternativeName | warning | implemented |
| `w_cqrp_subscriber_policy_not_dv` | CQRP v0.2.0 | 4.5.2 | Subscriber / CQRP subscriber | Certificate and TBS | tbsCertificate.extensions.certificatePolicies | warning | implemented |

### Dispatcher and rule-runner findings

For the profile/artifact mismatch, Source and Section are emitted in the same
bracketed wire prefix used by native rule findings.

| Code | Source | Section | Artifact / profile | Input applicability | Field(s) | Severity | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `e_mtc_profile_artifact_mismatch` | pkimetal profile dispatch | Explicit MTC profile selection | CA or subscriber / all four MTC profiles | Certificate and TBS | profile | error | implemented |
| `b_mtc_rule_panic` | inherited from panicking rule (`Rule.Source`) | inherited from panicking rule (`Rule.Section`) | Any registered native MTC rule | Rule applicability | none | bug | implemented |

## Requirement-level coverage without finding codes

These rows describe ownership or limits and deliberately do not invent finding
codes.

| Requirement | Source | Section | Artifact / profile | Input applicability | Field(s) | Severity | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Compatible RFC 5280 and TLS certificate rules | RFC 5280 and TLS Baseline Requirements | Sections not explicitly overridden | All MTC profiles | When a compatible linter can parse the artifact | n/a | linter-defined | delegated |
| Outer Certificate and MTCProof checks on TBS input | draft-ietf-plants-merkle-tree-certs-05 | 6.2 | All MTC TBS profiles | TBS lacks outer and proof fields | n/a | none | not applicable |
| Inclusion root, proof hash, and cosignature cryptographic validation | draft-ietf-plants-merkle-tree-certs-05 | 4 and 6 | Subscriber / MTC and CQRP subscriber | Requires Merkle context and trusted keys | n/a | none | not locally decidable |
| Trust Anchor ID PEN ownership | draft-ietf-tls-trust-anchor-ids-04 | 3 | Subscriber / MTC and CQRP subscriber | Requires an authoritative PEN registry and ownership context | n/a | none | not locally decidable |
| Non-CA cosigner ML-DSA-44 key | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Cosigners | Subscriber / MTC and CQRP subscriber | Certificate carries only a Trust Anchor ID; resolving the cosigner key requires external trust-anchor data | n/a | none | not locally decidable |
| mtc-tlog endpoints and checkpoint state | C2SP mtc-tlog @ 3bc97b2329fee167f7ff39efbbbc316c84876105 | Client behavior and log operation | CA / MTC and CQRP CA | Requires network access and external log state | n/a | none | not locally decidable |
| External log-entry comparison and signer/operator role independence | draft-ietf-plants-merkle-tree-certs-05 and CQRP v0.2.0 local draft | Operational requirements | All MTC profiles | Requires external records and roles | n/a | none | not locally decidable |
| Chrome cosigner independence | CQRP v0.2.0 local draft | Registry-dependent requirements | CQRP profiles | Requires Chrome registry and operator identity data | n/a | none | not locally decidable |
| Chrome registry policy | CQRP v0.2.0 local draft | Registry-dependent requirements | CQRP profiles | Requires an online registry query | n/a | none | not locally decidable |
| Conditional CA cRLSign behavior | CQRP v0.2.0 local draft | 4.5.1 | CA / CQRP CA | Requires external CA role and CRL behavior | n/a | none | not locally decidable |
