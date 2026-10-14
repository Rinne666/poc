# Instructions for AI agents working in this repository

**These instructions are binding for every AI-generated or AI-edited pull request.** Read root `README.md` (especially "AI contribution policy and CNA submission gates"), `CONTRIBUTING.md`, and the relevant project README/report **before** editing anything. Follow the stricter rule if two internal rules differ; ask a maintainer instead of bypassing publication safeguards.

## Workflow — do not skip steps

1. Identify the exact target vendor, product, module, version, commit, clean checkout and supported deployment. Do not extrapolate from a snapshot to released versions.
2. Search for existing CVEs, vendor advisories, related bug reports, and CNA scope. Mark findings as potentially duplicate if uncertain. Do not fabricate search results or claim that a duplicate check was performed when it was not.
3. State the expected security boundary and the lowest attack privileges. Establish baseline/negative control before formulating an impact claim.
4. Build a disposable local lab. Run only with explicit authorization. PoCs must default to local/test fixtures, bound requests and side effects, avoid exfiltration/destruction, clean up only their own artifacts, and return nonzero when the claimed condition is not proven.
5. Save raw (safely redacted) command and response captures under `evidence/`. Document commands, versions, environment, time, assertion, and exit code. NEVER synthesize, paraphrase as raw, or modify captured results to fit a hypothesis.
6. Choose the **lowest supported** proof level: `HYPOTHESIS`, `SOURCE_ONLY`, `COMPONENT_VERIFIED`, or `RUNTIME_VERIFIED` as defined in root README policy. If testing was impossible, say so and do not claim successful reproduction.
7. Fill `submission.json` from `_template/project-poc/submission.json`. Its `findings[].id` values and evidence paths are authoritative; make README and report agree with it.
8. In every finding, include: preconditions/default state; attacker capability; vulnerable input-to-sink path; exact reproduction; negative control; observed consequence; what was not shown; tested and untested versions; scoped remediation; CVSS vector with rationale; references and disclosure state.
9. Treat `CVE-PENDING` as a textual placeholder only. NEVER invent a CVE ID, `assignerOrgId`, `providerMetadata`, vendor confirmation, or CVE record state. A CVE JSON 5.1 record may be created only with a legitimately assigned ID and authorized CNA metadata; otherwise keep a research draft in `submission.json`.
10. Before any public PR, require recorded human publication approval. If the vendor has not been notified, use a private vulnerability-reporting workflow; a public PR is **blocked**. Do not assume an elapsed time window automatically authorizes publication.
11. Run `python3 tools/validate_poc.py --all` locally after migrating existing projects, or `python3 tools/validate_poc.py --base <base-commit>` to check only changed project directories. Report exactly which checks ran and which did not.
12. Never bypass CI, edit evidence to pass tests, or mark an unchecked box as complete. If a guard fails, revise the finding or keep it in private research notes.

## Human decisions reserved to maintainers

- Confirm real-world vulnerability existence, expected security boundary, severity and CNA eligibility.
- Authorize public disclosure of a new finding.
- Authorize CNA submissions and fill verified CNA metadata after actual assignment.
- Approve any exceptional PoC behavior or nonstandard testing constraints.

## Required PR summary

For each finding, include: `Finding ID`, `Verified target/version/commit`, `Proof level`, `Positive control`, `Negative control`, `Observed impact`, `Not demonstrated`, `Disclosure approval`, `Possible duplicates`, `CI result`. Do not infer a missing result.
