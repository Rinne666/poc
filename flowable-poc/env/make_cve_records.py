#!/usr/bin/env python3
"""Generate the CVE JSON 5.1 records for the flowable-poc findings.

Kept as a script rather than three hand-written files so the three records stay
structurally identical — a CNA diffing them should see only the differences that
are actually findings.
"""
import json
import pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "cve"
ASSIGNER = "rinne666"
PRODUCT = "flowable-engine"
VERSION = "8.1.0-SNAPSHOT"
COMMIT = "74fdb349c134e96e1f10592020ccca6e2e4b85f0"


def record(cve_id, title, description, cwe_id, cwe_desc, vector, score,
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
                "descriptions": [{
                    "lang": "en",
                    "value": description,
                }],
                "affected": [{
                    "vendor": "Flowable",
                    "product": PRODUCT,
                    "defaultStatus": "unaffected",
                    "versions": [{
                        "version": VERSION,
                        "status": "affected",
                        "versionType": "custom",
                        "lessThanOrEqual": "8.1.0-SNAPSHOT",
                        "platforms": ["Java"],
                        "repo": f"https://github.com/flowable/{PRODUCT}",
                    }],
                }],
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
                        "baseSeverity": "HIGH",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "LOW",
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


REPO = f"https://github.com/Rinne666/poc/tree/main/flowable-poc"

RECORDS = {
    "CVE-PENDING-flowable-rest-deployment-rce": record(
        cve_id="CVE-PENDING-flowable-rest-deployment-rce",
        title=("Repository deployment in Flowable Engine REST is authorized by the "
               "API-consumption privilege and reaches an unsandboxed Groovy script engine"),
        description=(
            "The Flowable Engine REST application authorizes process deployment with the same "
            "access-rest-api privilege used for ordinary API consumption. The shipped application "
            "depends on flowable-groovy-script-static-engine unconditionally, and the Groovy script "
            "engine applies no sandbox, no SecureASTCustomizer and no deny list. A principal "
            "holding only access-rest-api can therefore upload a process definition containing a "
            "Groovy scriptTask and obtain arbitrary code execution in the Flowable process.\n\n"
            "The access-rest-api privilege is created automatically on first start alongside "
            "access-admin, so it exists in every default deployment, and it is grantable through "
            "POST /idm-api/privileges/{privilegeId}/users. No administrator need be involved in a "
            "deployment that already grants it to integration accounts.\n\n"
            "The scriptTask element is a developer-facing extension point, but the script content is "
            "supplied by the caller in the uploaded definition. Supporting scripting is a product "
            "decision; exposing a write path into the interpreter to the ordinary consumption role is "
            "an authorization error. The script engine being present by default is a contributing "
            "factor, not a required misconfiguration.\n\n"
            "Observed against commit " + COMMIT + ": deployment returned HTTP 201 and the uploaded "
            "script executed, writing a marker file under the target's own temp directory. The same "
            "principal was correctly refused /actuator and /actuator/env with HTTP 403, confirming "
            "the boundary is enforced elsewhere and drawn in the wrong place here."
        ),
        cwe_id="CWE-94",
        cwe_desc=("Improper Control of Generation of Code ('Code Injection') - the deployment "
                  "endpoint is an unprivileged write path into a scripting interpreter"),
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        score=8.8,
        impact_c="H", impact_i="H", impact_a="H",
        solutions=[
            ("vendor-fix",
             "Introduce a dedicated deployment privilege (for example access-process-deploy) and "
             "require it for POST and DELETE on the repository deployment endpoints, leaving "
             "access-rest-api for API consumption only. This removes the chain and is confined to "
             "the filter chain plus one bootstrap entry."),
            ("vendor-fix",
             "Remove flowable-groovy-script-static-engine from the default dependencies of "
             "flowable-app-rest so that script execution is opt-in."),
            ("vendor-fix",
             "When the Groovy engine is present, compile scripts under a SecureASTCustomizer that "
             "denies the file, process, reflection, network and classloading packages, or run them "
             "in a Groovy sandbox with an explicit policy."),
        ],
        workarounds=[
            "Do not grant access-rest-api to principals that should not deploy definitions; segregate "
            "integration service accounts from any account with deployment capability.",
            "Remove flowable-groovy-script-static-engine from the application dependencies if script "
            "tasks are not used.",
        ],
        refs=[f"{REPO}/README.md#v1--deployment-reaching-an-unsandboxed-script-engine",
              f"{REPO}/report.md", f"{REPO}/poc/v1_deployment_rce.py"],
        notes={
            "disclosure": "Not yet reported to the vendor or any CNA. The identifier is "
                          "CVE-PENDING and state is RESERVED because no number has been "
                          "allocated; this is not an assigned CVE record. This record is "
                          "published in a public repository ahead of vendor notification, so "
                          "downstream users should treat the finding as live.",
            "exploit_tier": ("Proof-of-Concept, per VulDB's definition for a simple exploit that "
                             "illustrates basic functionality. The published PoC writes one marker "
                             "file and performs no other action."),
            "reproduction_note": ("The BPMN API in the shipped build is served under "
                                  "/flowable-rest/service/, not /flowable-rest/process-api/. "
                                  "flowable-default.properties:43 overrides the servlet default. "
                                  "The documented path returns 404."),
        },
    ),

    "CVE-PENDING-flowable-rest-serializable-deser": record(
        cve_id="CVE-PENDING-flowable-rest-serializable-deser",
        title=("Unfiltered Java deserialization of caller-supplied bytes on the Flowable Engine "
               "REST variable API"),
        description=(
            "The Flowable Engine REST runtime variable endpoints accept type=serializable and pass "
            "the uploaded multipart bytes to a bare java.io.ObjectInputStream, calling readObject() "
            "on them. No ObjectInputFilter is installed. SerializableType.createObjectInputStream "
            "overrides only resolveClass, substituting ReflectUtil.loadClass, which resolves an "
            "arbitrary class name against the application classloader with no allow list.\n\n"
            "The only guard is the property rest.variables.allow.serializable, which defaults to "
            "true in code at BaseExecutionVariableResource.java:70 as well as in the shipped "
            "flowable-default.properties:57. Deleting the shipped property does not close the sink.\n\n"
            "The same sink is present on the BPMN task path, the CMMN case-instance path and the "
            "CMMN task path. The JSON variable path already refuses the type outright (HTTP 400), "
            "which shows the maintainers already consider it unsafe in at least one code path.\n\n"
            "Observed against commit " + COMMIT + ": a serialization stream naming a caller-chosen "
            "class was reconstructed and persisted, confirmed by a byte-identical round trip "
            "through the /data endpoint served as application/x-java-serialized-object.\n\n"
            "Command execution was NOT demonstrated. commons-collections 3.2.2 is present on the "
            "shipped classpath but gates its own InvokerTransformer, and ysoserial CommonsBeanutils1 "
            "and Spring1 payloads were rejected by the servlet container's multipart parser. This "
            "record therefore describes a confirmed deserialization primitive rather than a confirmed "
            "RCE, and is scored accordingly. The realistic present impact is classpath "
            "reconnaissance and denial of service; the risk is that a later dependency upgrade "
            "introducing a usable gadget converts the same upload into remote code execution with no "
            "further work by an attacker."
        ),
        cwe_id="CWE-502",
        cwe_desc="Deserialization of Untrusted Data",
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
        score=8.3,
        impact_c="H", impact_i="H", impact_a="L",
        solutions=[
            ("vendor-fix",
             "Change the code default of rest.variables.allow.serializable to false and remove the "
             "shipped line from flowable-default.properties, so the sink is opt-in."),
            ("vendor-fix",
             "Construct the stream with an explicit JEP 290 ObjectInputFilter allow list rather than "
             "a bare new ObjectInputStream."),
            ("vendor-fix",
             "Remove the resolveClass override in SerializableType so ReflectUtil.loadClass cannot "
             "be used to resolve arbitrary names."),
        ],
        workarounds=[
            "Set rest.variables.allow.serializable=false if the deployment does not pass serialized "
            "Java objects as variables. Note that this must be set explicitly; the code default is "
            "permissive.",
        ],
        refs=[f"{REPO}/README.md#v2--unfiltered-deserialization-of-caller-supplied-bytes",
              f"{REPO}/report.md", f"{REPO}/poc/v2_serializable_deser.py"],
        notes={
            "disclosure": "Not yet reported to the vendor or any CNA. The identifier is "
                          "CVE-PENDING and state is RESERVED because no number has been "
                          "allocated; this is not an assigned CVE record. This record is "
                          "published in a public repository ahead of vendor notification, "
                          "so downstream users should treat the finding as live.",
            "scope_limitation": ("Arbitrary class instantiation and readObject execution are "
                                 "confirmed. End-to-end command execution is not, and is not "
                                 "claimed. See the description."),
            "exploit_tier": ("Proof-of-Concept. The published PoC uses a serialization stream of "
                             "java.util.ArrayList containing one string. No gadget chain is "
                             "bundled, and none is required to demonstrate reachability."),
            "type_reclassification_note": ("A serialized java.lang.String is also accepted, but "
                                           "Flowable reclassifies the reconstructed object as a "
                                           "string variable, so no /data endpoint is offered. This "
                                           "is not a mitigation; it does not apply to any class that "
                                           "is not a first-class Flowable variable type."),
        },
    ),

    "CVE-PENDING-flowable-rest-externalworker-impersonation": record(
        cve_id="CVE-PENDING-flowable-rest-externalworker-impersonation",
        title=("Flowable Engine REST external-worker identity is a disclosed request-body string "
               "rather than a bound credential"),
        description=(
            "External worker operations in the Flowable Engine REST API are authorized by comparing "
            "a workerId taken from the request body against the job's lockOwner "
            "(AbstractExternalWorkerJobCmd.java:73). That workerId is never bound to the "
            "authenticated principal, and GET /external-job-api/jobs/{jobId} returns the current "
            "lockOwner to any authenticated caller. The authorization check therefore reduces to a "
            "string that the API discloses to anyone who can read a job identifier.\n\n"
            "Observed against commit " + COMMIT + ": a principal holding only access-rest-api, with "
            "no worker credential and no prior relationship to the worker, read a job's lockOwner and "
            "replayed it in a complete request, which returned HTTP 204. The same request with an "
            "identity that held no lock returned HTTP 403.\n\n"
            "Scope is stated precisely: the check is per-job. Presenting worker A's identity on "
            "worker B's job is correctly refused with HTTP 403, and that case was tested. The defect "
            "is not cross-job access; it is that the identity is neither secret nor bound to a "
            "principal, so a caller who can read a jobId can act as that job's owner.\n\n"
            "The bulk unacquire endpoint is weaker still: it releases every job held by a "
            "caller-named workerId with no per-job ownership check, and is not tenant-scoped. The "
            "cross-tenant property is read from source and was not measured; testing was single-"
            "tenant.\n\n"
            "Impact is not limited to availability. In Flowable's external-worker model a complete "
            "call does not mean 'mark this task done'; it asserts that the event which was supposed "
            "to happen outside the engine has happened, and the engine has no other source for that "
            "fact. Forging it asserts something about the outside world that never occurred, in the "
            "system whose purpose is to trust that assertion."
        ),
        cwe_id="CWE-639",
        cwe_desc=("Authorization Bypass Through User-Controlled Key - the worker identity is a "
                  "caller-supplied value and is also disclosed by the API"),
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H",
        score=8.3,
        impact_c="L", impact_i="H", impact_a="H",
        solutions=[
            ("vendor-fix",
             "Mint a per-worker secret at acquire time, store it with the lock, and require it on "
             "complete, fail and unacquire."),
            ("vendor-fix",
             "Alternatively, bind worker identity to the authenticated principal so that two distinct "
             "credentials cannot act as the same worker."),
            ("vendor-fix",
             "Stop returning lockOwner to non-owners in the job resource."),
            ("vendor-fix",
             "Apply the per-job ownership check to the bulk unacquire endpoint, and require an "
             "administrative privilege when no tenant is specified."),
        ],
        workarounds=[
            "Treat the workerId as a shared secret and keep job identifiers unguessable. This is a "
            "mitigation of the disclosure, not a fix: the value is returned by the API to any "
            "caller who already has a job identifier.",
        ],
        refs=[f"{REPO}/README.md#v3--external-worker-identity-is-a-replayable-disclosed-string",
              f"{REPO}/report.md", f"{REPO}/poc/v3_worker_impersonation.py"],
        notes={
            "disclosure": "Not yet reported to the vendor or any CNA. The identifier is "
                          "CVE-PENDING and state is RESERVED because no number has been "
                          "allocated; this is not an assigned CVE record. This record is "
                          "published in a public repository ahead of vendor notification, "
                          "so downstream users should treat the finding as live.",
            "not_claimed": ("Cross-job impersonation is not claimed and was tested and rejected. "
                            "Bulk unacquire cross-tenant scope is read from source, not measured."),
            "exploit_tier": ("Proof-of-Concept. The published PoC creates its own definition and its "
                             "own jobs, replays one disclosed lockOwner, and releases what it holds."),
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
