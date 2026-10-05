# MTC Linting Specification Baseline

## Draft-06 Capability And Retained Legacy Profile

Implemented target: `draft-ietf-plants-merkle-tree-certs-06` with
`draft-ietf-tls-trust-anchor-ids-05`. Retained compatibility profile:
`draft-ietf-plants-merkle-tree-certs-05` with
`draft-ietf-tls-trust-anchor-ids-04`. New admission still defaults to `05`;
support for `06` is not an activation or deployment claim.

Revision is captured at acceptance and retained for retries, workers, downloads
and alternate artifacts. Bare proofs require explicit revision; the unchanged
proof OID is not a discriminator. Legacy Name/extension/vector16 and TAI-04
properties remain available; new artifacts use .47.3 RELATIVE-OID, .47.4
three-field SHA-256 CA parameters, outer vector24 and TAI-05 patterns/properties.

The selected service rollout keeps the same CA ID and key while sealing N1
and explicitly activating an independent N2 origin/tree. Historical entries,
hashes, tiles, certificates, checkpoint lineage and URLs are not rewritten.
Canonical public Log URLs use `/<CAID>/<N>`; the certified prefix ends before N.
Former version-prefixed aliases preserve historical reads only. Local linting
does not establish a current registry state, a live activation, or strict 06
monitor acceptance of historical 05 entries. Protocol selection remains
certificate-local and explicit; a URL never selects a lint profile.

CA representations and CRL issuer/publication state are revision-separated for
the same identity/key. Preserve old CA/CRL URLs and original artifact chains;
47d admission needs the new CRL view, while 7d retains its no-CRL policy.

Enable 06 only after durable expiration/history evidence is complete, the
configured lifetime bound is positive, approved full CA prefixes map BEFORE
the log number, and current registry identity, cryptographic quorum and current
public checkpoint/document coverage pass. Missing history stays unresolved,
never inferred from emitted_at/current configuration or fabricated as zero.
Read-node document parsing is keyless validation, not signature verification.
MTC-06 §6.4.3's landmark-zero/expired-sentinel row-count ambiguity returns 503
for the new view; legacy remains available. No strict conformance claim is made
at that boundary.

Deploy additive schema and dual readers before enabling writers; backfill and
validate history/archives/CRLs/prefixes/public views first. Rollback disables
NEW 06 admission, retains upgraded readers/workers to finish already accepted
06 work, and retains additive schema and committed bytes. Once 06 data exists,
an old-binary downgrade is not supported.

Runtime C2SP remains `d0fe789122c75b903bfc1680b0b8b8dc570f0db3`;
lint C2SP remains `3bc97b2329fee167f7ff39efbbbc316c84876105`; independent
CQRP is explicitly updated to `v0.3.0`; source provenance and boundaries are
recorded below. Older MTC links in pinned C2SP do not replace explicit
revision-specific MTC structures; C2SP HTTP/signature profiles stay pinned.

Local codec, Merkle/vector, mixed-history, H2 migration/concurrency/restart,
ACME, CRL and Linux Nginx route tests establish scoped implementation evidence.
Real PostgreSQL encrypted bootstrap/decryption, migrations, rollback,
concurrency and PostgreSQL restart are NOT EXECUTED. Production rollout,
actual registry/HSM and external TLS/RP/monitor interoperability are unverified.
Existing signer baseline failures and environment-gated skips remain failures
and unverified evidence respectively, not an all-green claim.


Upstream snapshot for unchanged policies: 2026-08-19.
MTC/TAI implementation capability updated: 2026-09-28; see limits below.

The versions below are pinned. Upstream publication does not upgrade this
repository automatically.

## Native MTC Profiles

| Specification | Pinned baseline | Lint scope | Source |
| --- | --- | --- | --- |
| Merkle Tree Certificates | `draft-ietf-plants-merkle-tree-certs-06` | MTC CA and subscriber syntax/profile rules | https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-06 |
| TLS Trust Anchor Identifiers | `draft-ietf-tls-trust-anchor-ids-05` | Relative OID and Trust Anchor ID syntax | https://datatracker.ietf.org/doc/html/draft-ietf-tls-trust-anchor-ids-05 |
| Unsigned X.509 Certificates | RFC 9925 | Conditional unsigned CA-certificate rules | https://www.rfc-editor.org/rfc/rfc9925.html |
| ML-DSA Algorithm Identifiers for PKIX | RFC 9881 | AlgorithmIdentifier and OID checks | https://www.rfc-editor.org/rfc/rfc9881.html |
| PKIX Certificate and CRL Profile | RFC 5280 | Compatible X.509 certificate and CRL rules | https://www.rfc-editor.org/rfc/rfc5280.html |
| TLS Baseline Requirements | CA/B Forum TLS BR `2.2.8`, effective 2026-06-16 | Compatible publicly trusted TLS certificate rules | https://cabforum.org/working-groups/server/baseline-requirements/documents/CA-Browser-Forum-TLS-BR-2.2.8.pdf |

Selected MTC revision (`-05` legacy or `-06` new) overrides RFC 5280 only where explicit. Compatible RFC 5280 and TLS
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

The `cqrp_mtc_ca` and `cqrp_mtc_subscriber` profiles are pinned to official
`CQRP v0.3.0` (2026-08-14). CQRP is an explicit policy assertion, not an encoding
that autodetection may infer. Both profiles retain their IDs and choose the
native MTC-05/06 rules and proof parser from unambiguous artifact identity.
The official original-source hashes and qualification boundaries are recorded
below.

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

## CQRP v0.3.0 source and audit boundary

The policy baseline is **[DRAFT] Chrome Quantum-resistant Root Program Policy,
Version 0.3.0**, last updated **2026-08-14**, published by Google Chrome Root
Programs. This update was explicitly requested on 2026-10-05; v0.2.0 is no
longer an acceptance baseline. The v0.3.0 original was audited directly against
the implementation; obtaining or comparing the superseded v0.2.0 is not a gate.

- Official HTML: https://googlechrome.github.io/chromerootprogram/cqrp/draft-policy/
- Original HTML SHA-256: `08820aaa2c06117a079a904bf2575ee8b8291e724fe63658b2a82baa93cb1e68`.
- Immutable official source: https://github.com/GoogleChrome/chromerootprogram/blob/65873796fe3bf4b7738fadbd35cb73396a7ddb37/content/cqrp/draft-policy.md
- Original Markdown SHA-256: `b084b7ad85985fbc31d7b2795204a05cc3a6d17ef4760c4aac0ca34ac8324393`.

CQRP applies only to its explicit Chrome policy scope and overrides compatible
MTC/RFC/BR requirements only where its text says so. Native MTC-05/06 and C2SP
pins, CA keys and immutable historical artifacts remain unchanged. CQRP lint
profiles explicitly compose the selected artifact revision with v0.3.0; proof
framing or URLs never choose a revision. Subscriber N > 4 is rejected by the
CQRP overlay (§2.5.1.3); native MTC serial domains remain unchanged.

Source provenance is established; complete Chrome policy compliance is not.
§2.4 requires BOTH standalone and landmark-relative forms; the known MTC-06
§6.4.3 zero-sentinel publication boundary remains unresolved. §2.5.1.2 permits
same-key replacement of an inoperable log and requires a public incident for
every rotation: local N2 tests do not approve routine protocol-driven rotation.
Effective machine-readable profiles/CP-CPS (§2.3.2), ten-day DCV reuse and ARI
operational tests (§§2.4.1–2.4.2), independent Usable/pre-freeze Frozen mirrors
(§2.4.5), availability/retention evidence (§§2.5, 3.2), active-key roles/HSM/
ceremonies/key schedules (§2.6), and Chrome registry/operator obligations require
external qualification. §2.3.1 delegates to latest BR; the independently pinned
BR 2.2.8 has not been silently upgraded or certified as satisfying that mandate.

Subscriber-key admission now enforces CQRP v0.3.0 §2.4.3.2 in both CA and
TC: pure ML-DSA-44/65/87 with parameters absent, exact RFC 9881 §4 key sizes
and byte-aligned BIT STRINGs, or BR 2.2.8 §§6.1.5–6.1.6/7.1.3.1 RSA/NIST EC
keys with validated parameters and points. Ed25519 subscriber keys are rejected
for both CSR and PoP; Ed25519 ACME account authentication remains supported.
CA and TC enforce BR 2.2.8 §6.1.6's RSA exponent range, small-factor and
prime-power SHOULD checks, plus Fermat/ROCA rejection (§6.1.1.3). Built-in
Debian SHA-256 modulus/X-coordinate data is fixed to CAB Forum-recommended
dwk_blocklists commit `38b221be821e79475bd07063b16d841a7bf4b3cc`, derived from
CAB Forum commit `6409c3eedb8d03d61032266150c70571a0035005`. Checksummed
resources cover RSA 2048/3072/4096/8192 and P-256/P-384/P-521; other RSA sizes
up to 8192 are rejected while their screening data is unavailable. RSA above
8192 follows the BR Debian exception; PoP retains its existing upper bound.
Data failures remain service errors, never client-key errors or allow decisions.
CA rejects new CSR/PoP keys found in retained keyCompromise (reason 1)
records, including old/expired issuers, alternate RSA exponents and negated EC
points. Accepted identical historical receipts remain immutable. This check
uses bounded scalar pages without schema changes; it does not establish atomic
serialization with concurrently uncommitted revocation reports. External
compromised-key feeds, unrecorded reports, HSM/Chrome/operational qualification
and full BR/CQRP certification remain outside this evidence.
