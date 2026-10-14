# REPLACE_WITH_PRODUCT — proof-of-concept material

> Machine-readable source of truth: [`submission.json`](submission.json). Copy the scaffold from `_template/project-poc/` and replace every placeholder before creating a public PR.

**Vendor / product:** REPLACE_WITH_VENDOR / REPLACE_WITH_PRODUCT  
**Tested version and commit:** REPLACE_WITH_VERSION, REPLACE_WITH_COMMIT  
**Disclosure:** REPLACE_WITH_DISCLOSURE_STATE  
**Verification:** REPLACE_WITH_PROOF_LEVEL  
**CVE:** unassigned, or authentic CVE ID only

## Findings

| ID | Name | Proof level | Tested version | CVE |
|---|---|---|---|---|
| F1 | REPLACE_WITH_TITLE | HYPOTHESIS | REPLACE_WITH_VERSION | Unassigned |

## F1 — REPLACE_WITH_TITLE

**Security boundary:** REPLACE_WITH_EXPECTED_AUTHORIZATION_OR_ISOLATION_BOUNDARY

**Preconditions and attacker privileges:** REPLACE_WITH_PRECONDITIONS

**Observed impact:** REPLACE_WITH_RUNTIME_EVIDENCE_NOT_THEORETICAL_MAXIMUM

**Negative control:** REPLACE_WITH_CONTROL_RESULT

**What was NOT demonstrated:** REPLACE_WITH_LIMITATIONS

**Affected version scope:** Only the exact tested version/commit is verified unless further test evidence exists.

**Evidence and reproduction:** [`report.md`](report.md) and paths in `submission.json`.

**Vendor/CNA coordination:** REPLACE_WITH_CONTACT_AND_PUBLICATION_APPROVAL

## Files

- `submission.json` — canonical structured metadata
- `report.md` — precise steps, positive and negative controls, interpretation
- `poc/` — authorized minimal reproducible test
- `evidence/` — raw redacted observation and provenance
- `env/` — isolated lab setup and teardown
- `cve/` — optional, only if legitimately assigned and schema-valid
- `nuclei/` — optional, strictly detection-only
