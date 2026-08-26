# MTC Linting Specification Baseline

Last verified against upstream sources: 2026-08-19.

The versions below are pinned. Upstream publication does not upgrade this
repository automatically.

## Native MTC Profiles

| Specification | Pinned baseline | Lint scope | Source |
| --- | --- | --- | --- |
| Merkle Tree Certificates | `draft-ietf-plants-merkle-tree-certs-05` | MTC CA and subscriber syntax/profile rules | https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-05 |
| TLS Trust Anchor Identifiers | `draft-ietf-tls-trust-anchor-ids-04` | Relative OID and Trust Anchor ID syntax | https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-04 |
| Unsigned X.509 Certificates | RFC 9925 | Conditional unsigned CA-certificate rules | https://www.rfc-editor.org/rfc/rfc9925.html |
| ML-DSA Algorithm Identifiers for PKIX | RFC 9881 | AlgorithmIdentifier and OID checks | https://www.rfc-editor.org/rfc/rfc9881.html |
| PKIX Certificate and CRL Profile | RFC 5280 | Compatible X.509 certificate and CRL rules | https://www.rfc-editor.org/rfc/rfc5280.html |
| TLS Baseline Requirements | CA/B Forum TLS BR `2.2.8`, effective 2026-06-16 | Compatible publicly trusted TLS certificate rules | https://cabforum.org/working-groups/server/baseline-requirements/documents/CA-Browser-Forum-TLS-BR-2.2.8.pdf |

MTC `-05` overrides RFC 5280 only where explicit. Compatible RFC 5280 and TLS
BR rules remain applicable and may be delegated to registered general-purpose
linters when they can safely parse the artifact.

TLS BR `2.2.9` was current upstream at the verification date, but its normative
delta has not been audited here. It is a pending upgrade, not the claimed lint
baseline.

## C2SP MTC-Tlog Overlay

Certificate-local `mtc-tlog` rules are pinned to C2SP repository commit
`3bc97b2329fee167f7ff39efbbbc316c84876105`:

https://github.com/C2SP/C2SP/blob/3bc97b2329fee167f7ff39efbbbc316c84876105/mtc-tlog.md

The pin governs the prefix URL extension, SHA-256 log hash and applicable
cosigner algorithm constraints. Network endpoint state and remote cosigner
identity are not locally decidable certificate lints.

## CQRP Overlay

The `cqrp_mtc_ca` and `cqrp_mtc_subscriber` profiles are pinned to a
user-supplied local `CQRP v0.2.0` draft. CQRP is an explicit policy assertion,
not an encoding that autodetection may infer.

The authoritative CQRP source artifact is not stored in this repository. Do
not change CQRP findings until the authoritative source is obtained and its
title, publication date, origin and SHA-256 digest are recorded here. Do not
reinterpret this baseline as a later CQRP revision or a generic MTC draft.

CQRP overrides MTC, RFC 5280 or TLS BR requirements only where the pinned CQRP
text explicitly does so.

## Coverage Boundary

Local linting can evaluate artifact syntax and profile fields. It cannot, from
a certificate alone, establish external log state, validate inclusion roots or
cosignatures without trusted context, verify PEN ownership, query browser
registries, or prove signer/operator independence. Such requirements must stay
marked not locally decidable instead of being silently treated as passed.

## Upgrade Gate

Before changing a pin, diff normative text and audit every stable finding code,
source/section citation, profile registration, severity and applicability path.
Add positive, negative, malformed-input and cross-profile regression tests, and
update public rule coverage in the same delivery.
