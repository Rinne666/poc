#!/usr/bin/env python3
"""Generate the CVE JSON 5.1 records for the astron-agent-poc findings.

Kept as a script rather than three hand-written files so the three records stay
structurally identical — a CNA diffing them should see only the differences that
are actually findings.
"""
import json
import pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "cve"
ASSIGNER = "rinne666"
VENDOR = "iFlytek"
PRODUCT = "astron-agent"
REPO = "https://github.com/iflytek/astron-agent"
COMMIT = "b4f8ed57460cbfb32016a4afd3fd7212987d33c3"
POC = "https://github.com/Rinne666/poc/tree/main/astron-agent-poc"

DISCLOSURE_NOTE = (
    "Not yet reported to the vendor or any CNA at the time this record was written. "
    "The identifier is CVE-PENDING and state is RESERVED because no number has been "
    "allocated; this is not an assigned CVE record."
)


def affected(versions):
    return [{
        "vendor": VENDOR,
        "product": PRODUCT,
        "defaultStatus": "unknown",
        "versions": [{"version": v, "status": "affected"} for v in versions],
        "repo": REPO,
    }]


def record(cve_id, title, description, cwe_id, cwe_desc, vector, score, severity,
           impact_c, impact_i, impact_a, solutions, workarounds, refs, notes):
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerShortName": ASSIGNER,
            "state": "RESERVED",
        },
        "containers": {
            "cna": {
                "title": title,
                "descriptions": [{"lang": "en", "value": description}],
                "affected": affected(AFFECTED[cve_id]),
                "problemTypes": [{
                    "descriptions": [{
                        "cweId": cwe_id,
                        "lang": "en",
                        "description": cwe_desc,
                        "type": "CWE",
                    }],
                }],
                "references": [{"url": u} for u in refs],
                "metrics": [{
                    "format": "CVSS",
                    "scenarios": [{"lang": "en", "value": "GENERAL"}],
                    "cvssV3_1": {
                        "version": "3.1",
                        "vectorString": vector,
                        "baseScore": score,
                        "baseSeverity": severity,
                        "attackVector": "ADJACENT" if "AV:A" in vector else "NETWORK",
                        "attackComplexity": "LOW" if "AC:L" in vector else "HIGH",
                        "privilegesRequired": "NONE" if "PR:N" in vector else "LOW",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": impact_c,
                        "integrityImpact": impact_i,
                        "availabilityImpact": impact_a,
                    },
                }],
                "solutions": [{"type": t, "value": v} for t, v in solutions],
                "workarounds": [{"lang": "en", "value": w} for w in workarounds],
                "source": {"discovery": "EXTERNAL"},
                "exploitability": "PROOF_OF_CONCEPT",
                "notes": notes,
            },
        },
    }


AFFECTED = {
    "CVE-PENDING-astron-agent-execddl-whitelist-bypass": ["v1.1.2", f"main at commit {COMMIT}"],
    "CVE-PENDING-astron-agent-console-spaceid-authz-bypass": ["v1.1.1", "v1.1.2", f"main at commit {COMMIT}"],
    "CVE-PENDING-astron-agent-workflow-resume-authz": ["v1.1.2", f"main at commit {COMMIT}"],
}

RECORDS = {
    "CVE-PENDING-astron-agent-execddl-whitelist-bypass": record(
        cve_id="CVE-PENDING-astron-agent-execddl-whitelist-bypass",
        title=("astron-agent core-database DDL whitelist is bypassed with a comment "
               "containing an allowlisted keyword"),
        description=(
            "The astron-agent core-database service (POST /xingchen-db/v1/exec_ddl) "
            "enforces a whitelist of permitted DDL statement kinds. For statements that "
            "SQLGlot (pinned at 26.29.0) models as exp.Command — for example CREATE "
            "EXTENSION — the whitelist decides the statement type by running "
            "re.search(r'\\bALTER\\s+TABLE\\b', sql) against the ORIGINAL SQL STRING "
            "(exec_ddl.py:60-80), not against the parsed statement. SQLGlot 26.29.0 "
            "preserves comments when it re-serializes a parsed command, so a comment "
            "containing the allowlisted keyword satisfies the guard while the statement "
            "itself remains the rejected command.\n\n"
            "The router is reachable without request authentication: "
            "core/memory/database/main.py mounts the /xingchen-db/v1 routers with no "
            "auth dependency. Each route validates only caller-supplied database "
            "metadata (a database_id/uid pair the caller can mint for itself through "
            "POST /xingchen-db/v1/create_database).\n\n"
            "Observed against main at commit " + COMMIT + " and release v1.1.2: the bare "
            "statement CREATE EXTENSION IF NOT EXISTS dblink was rejected with code "
            "25040 (DDL syntax not allowed); the identical statement prefixed with "
            "/* ALTER TABLE */ was accepted and the extension was installed in the "
            "caller's own test database. The service connects to PostgreSQL with the "
            "compose-shipped role (spark), which the official postgres image creates as "
            "a superuser.\n\n"
            "Scope of the claim: the demonstrated impact is whitelist bypass leading to "
            "extension installation in a caller-created test database. File reading, "
            "cross-schema access and code execution were NOT demonstrated through this "
            "path and are not claimed. Earlier releases were not exhaustively checked.\n\n"
            "Attack reachability is deployment-qualified: the stock compose file and "
            "Helm values do not publish port 7990 to the host, so the realistic attack "
            "surface is peers on the internal Docker/Kubernetes network, or deployments "
            "that explicitly publish the port."
        ),
        cwe_id="CWE-184",
        cwe_desc=("Incomplete List of Disallowed Inputs - the whitelist resolves the "
                  "statement type from the raw SQL string, so an allowlisted keyword "
                  "inside a comment admits a non-allowlisted command"),
        vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        score=6.3,
        severity="MEDIUM",
        impact_c="L", impact_i="L", impact_a="L",
        solutions=[
            ("vendor-fix",
             "Stop inspecting the raw SQL for whitelist purposes: reject any exp.Command "
             "node outright and accept only Create/Alter/Drop nodes of a known kind. Do "
             "not fall back to re.search over the raw string."),
            ("vendor-fix",
             "Strip comments (or reject statements whose serialization retains comments) "
             "before the whitelist check; comments are not statements and must not "
             "influence the decision."),
            ("vendor-fix",
             "Run the service's PostgreSQL role with least privilege so it cannot "
             "install extensions, and require request authentication on the "
             "/xingchen-db/v1 routers."),
        ],
        workarounds=[
            "Restrict network access to core-database:7990 to the platform services that "
            "need it; the stock compose/Helm definitions do not publish the port, and "
            "deployments that keep it unpublished are reachable only from inside the "
            "cluster network.",
        ],
        refs=[f"{POC}/README.md#v1--ddl-whitelist-bypass-via-comment-smuggling",
              f"{POC}/report.md",
              f"{POC}/poc/v1_ddl_whitelist_comment_smuggling.py"],
        notes={
            "disclosure": DISCLOSURE_NOTE,
            "not_claimed": ("File read, cross-schema access and host-level code "
                            "execution are not demonstrated and not claimed. The "
                            "demonstrated effect is installation of the dblink extension "
                            "in a caller-created test database."),
            "exploit_tier": ("Proof-of-Concept. The published PoC creates its own test "
                             "database, demonstrates one rejected and one accepted "
                             "statement, then drops what it created."),
            "scoring_note": ("Scope is Unchanged: per FIRST guidance, a database used "
                             "solely by the platform application is part of that "
                             "application's security scope. AV:A reflects the "
                             "cluster-internal reachability of the unauthenticated route."),
        },
    ),

    "CVE-PENDING-astron-agent-console-spaceid-authz-bypass": record(
        cve_id="CVE-PENDING-astron-agent-console-spaceid-authz-bypass",
        title=("astron-agent Console skips knowledge-file ownership checks when the "
               "client supplies a space-id header"),
        description=(
            "The astron-agent Console knowledge-list endpoint (POST "
            "/file/list-knowledge-by-page) authorises each requested file only when the "
            "client-supplied space-id header is absent or unparseable. "
            "SpaceInfoUtil.getSpaceId() (console/backend/commons/.../SpaceInfoUtil.java "
            "64-72) parses the header to a Long, and FileInfoV2Service.listKnowledgeByPage "
            "(console/backend/toolkit/.../FileInfoV2Service.java:903-930) invokes "
            "checkFileBelong only when that value is null. Any parseable numeric value — "
            "it need not be the victim's real space id — therefore suppresses the "
            "ownership check for every file id in the request.\n\n"
            "The endpoint still requires a normal authenticated Console session "
            "(SecurityConfig.java:124-126); the defect is a missing object-level "
            "authorization check, not an authentication bypass.\n\n"
            "Observed against main at commit " + COMMIT + " and releases v1.1.1 and "
            "v1.1.2: a low-privilege authenticated user received no records for a file "
            "owned by another test account without the header, and received that file's "
            "knowledge records with the header space-id: 1.\n\n"
            "Impact is confidentiality only: reading knowledge records associated with "
            "the requested file. Cross-tenant write, delete or availability impact was "
            "not demonstrated on this endpoint and is not claimed. Exploitation requires "
            "a valid Console JWT and knowledge or discovery of a target file id. Earlier "
            "releases were not exhaustively checked."
        ),
        cwe_id="CWE-639",
        cwe_desc=("Authorization Bypass Through User-Controlled Key - the ownership "
                  "check is skipped whenever a client-controlled header parses as a "
                  "number"),
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        score=6.5,
        severity="MEDIUM",
        impact_c="H", impact_i="N", impact_a="N",
        solutions=[
            ("vendor-fix",
             "Authorize every requested file id against the authenticated user "
             "unconditionally. If a request carries a space-id, first verify the "
             "authenticated user is a member of that space; never use the mere presence "
             "of the header as grounds to skip checkFileBelong."),
        ],
        workarounds=[
            "Strip or reject client-supplied space-id headers at the public gateway for "
            "this endpoint as an interim measure; this can break legitimate space-scoped "
            "clients, so test before deploying.",
        ],
        refs=[f"{POC}/README.md#v2--cross-user-knowledge-file-read-via-the-space-id-header",
              f"{POC}/report.md",
              f"{POC}/poc/v2_knowledge_space_id_bypass.py"],
        notes={
            "disclosure": DISCLOSURE_NOTE,
            "not_claimed": ("Write, delete or availability impact is not claimed; the "
                            "demonstrated impact is reading knowledge records of a file "
                            "the caller does not own."),
            "exploit_tier": ("Proof-of-Concept. The published PoC is read-only: two "
                             "requests with the caller's own credential, comparing the "
                             "same file id with and without the header."),
        },
    ),

    "CVE-PENDING-astron-agent-workflow-resume-authz": record(
        cve_id="CVE-PENDING-astron-agent-workflow-resume-authz",
        title=("astron-agent /workflow/v1/resume accepts a paused event from an "
               "authenticated caller whose app does not own it"),
        description=(
            "The astron-agent workflow endpoint POST /workflow/v1/resume is "
            "authentication-required (CHAT_OPEN_API_PATHS in "
            "core/workflow/extensions/fastapi/base.py:19-23; middleware verification in "
            "core/workflow/extensions/fastapi/middleware/auth.py:170-185). The defect is "
            "downstream of authentication: resume_open (core/workflow/api/v1/chat/"
            "open.py:106-165) resolves the paused event from Redis by the "
            "caller-supplied event_id and writes the resume payload without comparing "
            "the event's owning app_id to the authenticated caller's app.\n\n"
            "event_id is a Snowflake id (core/common/utils/snowfake.py:12) that the "
            "platform discloses on observable channels, most directly the INTERRUPT "
            "frame of the owner's own SSE stream when the flow pauses.\n\n"
            "Observed against main at commit " + COMMIT + " and release v1.1.2, on a "
            "local compose deployment with two separately registered applications: the "
            "victim app ran a released test flow that paused at a question-answer node; "
            "the attacker app (a different app_id, its own valid Bearer credential) "
            "posted /workflow/v1/resume with the disclosed event_id and "
            "attacker-chosen content. The resume was accepted, the engine consumed the "
            "injected content as the node's answer, and post-resume output was "
            "delivered along the attacker's connection instead of the victim's.\n\n"
            "Impact: integrity (attacker-controlled content enters the victim's paused "
            "workflow) and confidentiality (post-resume node output is returned to the "
            "attacker's connection). Availability is not directly affected and is not "
            "claimed. Exploitation requires two things at once: a valid Bearer "
            "credential for some registered app other than the victim's, and the ability "
            "to observe the target event_id while it is paused (the event expires with "
            "the node's timeout), which is reflected in the attack complexity of the "
            "score. Earlier releases were not exhaustively checked."
        ),
        cwe_id="CWE-639",
        cwe_desc=("Authorization Bypass Through User-Controlled Key - the event_id is a "
                  "caller-supplied key resolved to a resource without an ownership "
                  "check"),
        vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
        score=6.8,
        severity="MEDIUM",
        impact_c="H", impact_i="H", impact_a="N",
        solutions=[
            ("vendor-fix",
             "In resume_open, after the event is retrieved, compare the authenticated "
             "caller's app_id (resolved from the middleware-trusted principal) with "
             "event.app_id and reject mismatches."),
            ("vendor-fix",
             "Treat event identifiers as capabilities: log every resume attempt with "
             "both the caller's app id and the event's owning app id, and audit other "
             "by-id handlers in the workflow service for the same pattern."),
        ],
        workarounds=[
            "At the reverse proxy, require that the event_id in /workflow/v1/resume "
            "matches a server-side event_id-to-app binding created when the event "
            "paused, and reject mismatches.",
        ],
        refs=[f"{POC}/README.md#v3--workflow-v1resume-does-not-bind-the-paused-event-to-the-callers-app",
              f"{POC}/report.md",
              f"{POC}/poc/v3_workflow_resume_event_authz.py"],
        notes={
            "disclosure": DISCLOSURE_NOTE,
            "not_claimed": ("The endpoint IS authenticated; this is not an "
                            "authentication bypass. Availability impact is not claimed. "
                            "Events outside INTERRUPT status are not reachable through "
                            "this defect."),
            "exploit_tier": ("Proof-of-Concept. The published PoC runs the victim flow "
                             "supplied by the operator, resumes it once from a second "
                             "app, and prints the frames it observes."),
            "scoping_note": ("AC:H reflects the two simultaneous prerequisites: another "
                             "app's valid credential and observation of the event_id "
                             "during the pause window."),
        },
    ),
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for cve_id, rec in RECORDS.items():
        path = OUT / f"{cve_id}.json"
        path.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {path.name}")
    print(f"\n{len(RECORDS)} records, state=RESERVED, exploitability=PROOF_OF_CONCEPT")


if __name__ == "__main__":
    main()
