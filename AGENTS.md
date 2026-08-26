# Repository Collaboration Rules

## Specification Compliance

- Read `SPECIFICATIONS.md` before changing MTC parsing, profile selection,
  finding metadata, lint applicability, CQRP rules, or C2SP `mtc-tlog` checks.
- Treat the draft revisions, C2SP commit and CQRP version recorded there as
  pinned baselines. Do not silently use a newer source.
- Preserve rule precedence and distinguish locally decidable certificate rules
  from checks requiring network state, registries, trusted keys or operator
  identity.
- Every new or changed lint must cite the exact source and section, use a stable
  finding code, and have positive, negative and applicability tests.
- A baseline upgrade requires a normative-text diff, a rule-coverage audit and
  regression tests before updating finding metadata or public documentation.
- Preserve existing user changes and follow the workspace-level commit rules.
