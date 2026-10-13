# CVSS scoring

These are the reporter's scoring for the three PoCs in this project. CNA
triage may differ; the records under `cve/` are what is sent to the CNA.

## F-1 — `piwigo:upgrade_feed:unauthenticated_db_mutation`

**Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
**Score**: 9.1
**Severity**: Critical

| Metric | Value | Justification |
|---|---|---|
| Attack Vector | Network | the endpoint is `GET /upgrade_feed.php` over HTTP |
| Attack Complexity | Low | single GET, no setup beyond the routine `piwigo_upgrade` desync described in `report.md` |
| Privileges Required | None | no session, no token, no role |
| User Interaction | None | the request is unauthenticated; no victim is involved |
| Scope | Changed | the include()s run in the application's PHP process under the application's MySQL credentials; the database is the application's, not the attacker's |
| Confidentiality | High | the included scripts read the application's full `piwigo_config` table and may write attacker-influenced content into application-shared views (e.g. `gallery_title`, `page_banner`) |
| Integrity | High | the included scripts issue DDL (`ALTER TABLE`) and DML (`INSERT INTO piwigo_config`, `mass_inserts(...)`) on the application database |
| Availability | None | the demonstrated DDL/DML does not directly take the database offline |

The score is `9.1`, not `10.0`, because the **demonstrated** availability
impact is None — the included scripts do not drop tables. The latent
availability impact (a non-idempotent script run twice) is in the source
review but is not in the demonstrated reach, and CVSS scoring is
restricted to what the PoC shows.

## F-4 — `piwigo:default.error.sql.trace.disclosure`

**Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**Score**: 5.3
**Severity**: Medium

| Metric | Value | Justification |
|---|---|---|
| Attack Vector | Network | the trigger is a single anonymous request to a public URL |
| Attack Complexity | Low | the trigger requires a mysqli error from any anon path; with default `die_on_sql_error=true` and `show_php_errors_on_frontend=true`, the disclosure happens |
| Privileges Required | None | the request is unauthenticated |
| User Interaction | None | the disclosure happens on the first error |
| Scope | Unchanged | the disclosure reflects server-side state to the unauthenticated client; nothing on the application's behalf is touched |
| Confidentiality | High | the body contains the failing SQL string (with attacker-influenced substrings), the mysqli error string, the application's filesystem paths, and the PHP function call graph |
| Integrity | None | no state is modified by the disclosure |
| Availability | None | the disclosure is read-only |

The score is `5.3`, not higher, because the disclosed information is
*informational* — it does not include credentials or session tokens
directly. The information materially accelerates subsequent attacks
(credential brute-forcing, fingerprinting of installed extensions and
versions, path-based exploit chain selection) but is not a primary
vulnerability on its own.

## nv5 — `piwigo:ws.images.rate.db_amplification`

**Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
**Score**: 7.5
**Severity**: High

| Metric | Value | Justification |
|---|---|---|
| Attack Vector | Network | `pwg.images.rate` is a public WS endpoint |
| Attack Complexity | Low | one POST, no setup |
| Privileges Required | None | `rate_anonymous=true` is the vendor default |
| User Interaction | None | the request is unauthenticated |
| Scope | Unchanged | the cost is borne by the application itself, in its own database and PHP process |
| Confidentiality | None | the request does not exfiltrate application data |
| Integrity | None | the request does not modify persistent state beyond the single rate row it inserts |
| Availability | High | a small burst of unauthenticated rate calls drives `N` full `GROUP BY` scans plus `N` `mass_updates(IMAGES_TABLE, …)` rounds, on the application's own database |

The score is `7.5`, not `9.x`, because the *demonstrated* impact is on
availability only; the confidentiality and integrity columns are not
crossed. A motivated attacker who could observe the database's
`Com_select` rate through some other means (e.g. an information
disclosure vulnerability) could chain it; the PoC here is bounded to
the rate endpoint itself.

**Note on the live PoC**: in the test fixture, `piwigo_config.rate =
false` (set by `install.php` overriding the default), and the rate
handler bails out before the GROUP BY. The PoC's contribution is the
demonstrated anonymous reachability of the endpoint and the source-traced
amplification handler. On a fresh install where `piwigo_config.rate =
true` (the vendor default in `include/config_default.inc.php`), the
amplification fires on every anonymous rate call.

## What is excluded from this scoring

The PoC repository publishes only the three findings that survived live
testing. The other findings from the upstream audit deliverable were
either invalidated by live testing (stored XSS via the search rules
footer — blocked by PHP 8's `json_encode` slash escaping) or bounded
in scope (the decorative CSRF gate in `register.php` does not actually
create a user). The findings that require admin or higher privilege
(F-2, F-3, F-5, nv7) are out of scope for the public PoC repository
and are retained in the upstream audit deliverable for insider-threat
assessment.
