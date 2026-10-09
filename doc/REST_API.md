# pkimetal: REST API Documentation

## OpenAPI

An [OpenAPI](https://swagger.io/specification/) definition for pkimetal is provided by [openapi.yaml](/doc/openapi.yaml) and rendered in HTML [here](https://pkimetal.github.io/pkimetal/openapi.html).

## POST parameters

The HTTP POST API endpoints all accept the following common parameters:

Name | Required? | Default Value | Description
--- | --- | --- | ---
b64input | Required | n/a | The Base64 or PEM-encoded input.
format | Optional | json, or as configured | The desired response format.
profile | Optional | autodetect | The name of the profile that the input is intended to match.
severity | Optional | meta | The minimum severity level of linter findings that should be included in the response.

Each API also supports a purpose-specific alternative name for `b64input`.

The response `format` must be one of the following options:

- html
- json
- text

Use the [profiles](#get-endpoints) GET endpoint to list the supported values for `profile`.

The minimum `severity` must be one of the following options:

- meta
- debug
- info
- notice
- warning
- error
- bug
- fatal

The "meta" severity level includes informational "findings" added by pkimetal itself. The other severity levels are used for the findings of the various linters.

## POST endpoints

Endpoint | Description | Alternative name for b64input
--- | --- | ---
/lintcert | Lint a signed Certificate or Precertificate | b64cert
/linttbscert | Lint a to-be-signed Certificate or Precertificate | b64tbscert
/lintcrl | Lint a signed CRL | b64crl
/linttbscrl | Lint a to-be-signed CRL | b64tbscrl
/lintocsp | Lint a signed OCSP Response | b64ocsp
/linttbsocsp | Lint a to-be-signed OCSP Response | b64tbsocsp

## GET endpoints

Endpoint | Description
--- | ---
/linters | Return a JSON array that lists information about the available linters.
/profiles | Return a JSON array that lists information about the available input profiles.

### Web forms

Browse (i.e., send a GET request) to any of the POST endpoints.

## Experimental MTC certificate API

This fork supports [MTC draft-07](https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-07)
with TAI-06, retained [MTC draft-06](https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-06)
with TAI-05 and retained [MTC draft-05](https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-05)
with TAI-04,
and the official CQRP v0.3.0 policy overlay on the existing
certificate endpoints. See [MTC and CQRP rule coverage](MTC_RULE_COVERAGE.md)
for the implemented rules and offline limitations.

### Profiles

Profile | Artifact | Native linters
--- | --- | ---
`mtc_ca` | MTC CA Certificate or TBSCertificate | `mtclint` draft-05
`mtc_subscriber` | MTC subscriber Certificate or TBSCertificate | `mtclint` draft-05
`cqrp_mtc_ca` | CQRP MTC CA cosigning Certificate or TBSCertificate | `mtclint` selected draft-05/draft-06/draft-07 and `cqrplint` v0.3.0
`cqrp_mtc_subscriber` | CQRP MTC subscriber TLS Certificate or TBSCertificate | `mtclint` selected draft-05/draft-06/draft-07 and `cqrplint` v0.3.0
`mtc_draft06_ca` | Draft-06 CA Certificate or TBSCertificate | `mtclint` draft-06 / TAI-05
`mtc_draft06_subscriber` | Draft-06 subscriber Certificate or TBSCertificate | `mtclint` draft-06 / TAI-05
`mtc_draft07_ca` | Draft-07 CA Certificate or TBSCertificate | `mtclint` draft-07 / TAI-06
`mtc_draft07_subscriber` | Draft-07 subscriber Certificate or TBSCertificate | `mtclint` draft-07 / TAI-06

Profile IDs 105-110 retain their names/semantics; draft-07 IDs are 111-112.
CQRP v0.3.0 is pinned independently with verified original-source hashes in
[SPECIFICATIONS.md](../SPECIFICATIONS.md). It supports unambiguous draft-05/06/07
artifacts using their corresponding native rules and proof parser. Local linting is not evidence
of log/quorum/registry state, deployment or external TLS/RP interoperability.

An explicit profile is authoritative. CQRP is never inferred: an omitted
profile or `profile=autodetect` can select the CA/subscriber profile matching
unambiguous draft-05, draft-06 or draft-07 identity, but
never either CQRP profile. If an explicit CA/subscriber profile conflicts with
the detected artifact kind, the HTTP request still succeeds and `mtclint`
returns an `e_mtc_profile_artifact_mismatch` error finding.

07 uses formal OIDs and a 32-byte Trust Anchor ID limit. GREASE may accompany
landmark-relative proofs, so local signature count cannot classify certificate
form or validate CA/Mirror quorum. CQRP's standalone count finding is restricted
to retained 05/06 artifacts.

CQRP profiles run both the draft and CQRP native linters. CQRP replaces TLS
Baseline Requirements only where the CQRP baseline explicitly overrides them;
draft-05 replaces RFC 5280 only where draft-05 explicitly overrides it.

### Inputs

Endpoint | Form input | Raw input
--- | --- | ---
`/lintcert` | PEM or Base64 in `b64cert` or `b64input` | complete DER Certificate as `application/pkix-cert`
`/linttbscert` | PEM or Base64 in `b64tbscert` or `b64input` | DER TBSCertificate as `application/octet-stream`

Form requests use `application/x-www-form-urlencoded`; `profile`, `format`,
and `severity` may be form or query parameters. For raw requests these
parameters are query parameters. TBS input has no outer signature algorithm,
signature value, MTC proof, or proof cosignature fields, so checks requiring
those fields do not run.

These examples intentionally refer to local files instead of fabricating
certificate bytes:

```sh
curl -sS -H 'Accept: application/json' -H 'Content-Type: application/pkix-cert' \
  --data-binary @mtc-ca.der \
  'http://localhost:8080/lintcert?profile=mtc_ca&format=json'

curl -sS -H 'Accept: application/json' -H 'Content-Type: application/octet-stream' \
  --data-binary @mtc-subscriber.tbs.der \
  'http://localhost:8080/linttbscert?profile=mtc_subscriber&format=json'

curl -sS -H 'Accept: application/json' -H 'Content-Type: application/pkix-cert' \
  --data-binary @cqrp-mtc-ca.der \
  'http://localhost:8080/lintcert?profile=cqrp_mtc_ca&format=json'

curl -sS -H 'Accept: application/json' -H 'Content-Type: application/octet-stream' \
  --data-binary @cqrp-mtc-subscriber.tbs.der \
  'http://localhost:8080/linttbscert?profile=cqrp_mtc_subscriber&format=json'
```

PEM and Base64 form examples:

```sh
curl -sS --data-urlencode 'b64cert@certificate.pem' \
  --data 'profile=mtc_subscriber&format=json' \
  http://localhost:8080/lintcert

curl -sS --data-urlencode "b64tbscert=$(base64 < certificate.tbs.der)" \
  --data 'profile=cqrp_mtc_subscriber&format=json' \
  http://localhost:8080/linttbscert
```

### Status and response metadata

A JSON response is a flat array. Every item has `Linter`, `Finding`, and
`Severity`; rule findings may also have `Code` and `Field`. There is no separate
metadata object. With the default `severity=meta`, the first pkimetal item names
the selected profile and pkimetal version, for example
`Profile: mtc_subscriber; Version: <version>`. Each native linter that ran adds
its own `Queued: <duration>; Runtime: <duration>; Version: <version>` meta item
(`draft-05/draft-06/draft-07` for `mtclint`, `v0.3.0` for `cqrplint`).

Linters that do not run are represented by a meta item containing
`Not used [Available:<true|false>, Applicable:<true|false>]`. When present, a
second bracket contains `Reason:<text>`. In particular, zlint uses the exact
skip reason `zcrypto could not safely parse this MTC artifact` when the MTC
parser recognized the artifact but zcrypto could not safely supply a
Certificate.

Request or certificate/TBS parse failures return HTTP 400. In JSON format the
body is still the normal array schema with a single pkimetal fatal item; HTML
and text formats use their normal renderings. An unrecognized `format` can
produce an empty text response. By contrast, a structurally valid Certificate
whose MTCProof is malformed returns HTTP 200 with the fatal finding
`f_mtc_proof_malformed`, because proof validity is a lint result rather than a
request parsing failure.

```json
[
  {
    "Linter": "pkimetal",
    "Finding": "Profile: mtc_subscriber; Version: <version>",
    "Severity": "meta"
  },
  {
    "Linter": "zlint",
    "Finding": "zlint: Not used [Available:true, Applicable:false] [Reason:zcrypto could not safely parse this MTC artifact]",
    "Severity": "meta"
  },
  {
    "Linter": "mtclint",
    "Finding": "[draft-ietf-plants-merkle-tree-certs-05 §6.2] MTCProof is malformed",
    "Field": "signatureValue",
    "Code": "f_mtc_proof_malformed",
    "Severity": "fatal"
  }
]
```
