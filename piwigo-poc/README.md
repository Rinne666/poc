# Piwigo — proof-of-concept material

**Target** [`Piwigo/Piwigo`](https://github.com/Piwigo/Piwigo) — self-hosted PHP photo gallery
**Versions tested** 17.0.0beta1
**Commit tested** `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d8` (clean worktree)
**Disclosure state** **NOT yet reported to the vendor.** Piwigo publishes a
[`SECURITY.md`](https://github.com/Piwigo/Piwigo/blob/master/SECURITY.md) directing reports to
`security@piwigo.org` with a 72-hour first-response SLA. The three findings here are
anonymously-discoverable via the unauthenticated `/upgrade_feed.php`, `/index.php`, and
`/ws.php` endpoints described below, and no fix is in the source tree at the commit under
test. The `cve/*.cve.json` files carry `CVE-PENDING-*` identifiers and `state: RESERVED`;
**no CVE number has been allocated.**

> If you operate a Piwigo 17.0.0beta1 instance, treat all three findings as live. The
> critical one is reachable from a single anonymous GET against a target whose
> `piwigo_upgrade` table has been desynchronised from the `install/db/` directory — that
> desync is a routine outcome of interrupted upgrades, fresh-code-on-old-DB deploys, and
> backup-restore drift, and is the natural state of every Piwigo instance that has been
> upgraded at least once.

---

## Findings

| ID | Title | CWE | CVSS v3.1 | CVE | State |
|---|---|---|---|---|---|
| F-1 | Anonymous GET against `/upgrade_feed.php` runs every pending `install/db/<n>-database.php` under the application's MySQL credentials | CWE-862 | **9.1** (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N) | *pending* | **not yet reported** |
| F-4 | Default-on `die_on_sql_error` + `show_php_errors_on_frontend` causes any mysqli error to echo the failing SQL, the mysqli error string, and a PHP backtrace to any visitor, including unauthenticated | CWE-209 / CWE-200 | **5.3** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) | *pending* | **not yet reported** |
| nv5 | Anonymous `pwg.images.rate` would trigger `GROUP BY element_id` over the full `piwigo_rate` table plus `mass_updates` on `piwigo_images`; `rate_anonymous=true` ships as the vendor default and the endpoint has no flood gate | CWE-400 / CWE-770 | **7.5** (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) | *pending* | **not yet reported — conditional on conf['rate']=true** |

The CVSS scores are the reporter's scoring of the demonstrated impact. CNA triage severity
independently. F-1 is being submitted as Critical (S:C, C:H/I:H, A:N) because the
demonstrated side effect is full DDL/DML on the application database. F-4 is medium — it
discloses schema, SQL, file paths, and the call graph; nothing confidential is exfiltrated
on its own, but the disclosure materially accelerates subsequent attacks. nv5 is rated high
based on the source-traced amplification; the live PoC in this project shows the
anonymous reachability but not the amplification itself, because the test fixture's
`piwigo_config.rate` was set to `false` by `install.php`.

### Findings that did NOT survive live testing

A `git diff` from the original audit deliverable would surface the rest of the
hypotheses. This project publishes only the three that the live PoC could
demonstrate or source-attribute cleanly. The other findings, removed during the
transition from source-trace to live-PoC, are documented in `report.md` for
completeness:

- **Stored XSS via the search rules footer script** — the original hypothesis
  was that an attacker-controlled rule name would break out of the
  inline `<script>` tag emitted by `include/search_filters.inc.php:855`.
  Live testing showed PHP 8.2's `json_encode` escapes `/` to `\/` by default,
  defeating the `</script>` break-out, and the WS handler
  `ws_images_filteredSearch_create` does not actually accept a free-form
  string field for the rule — it builds a structured `mode`+`fields.cat.words`
  array. The endpoint is anonymous and writes integer-only fields to
  `piwigo_search`, which is a capacity-only finding (see `nv5`'s sibling in
  the audit deliverable). The XSS half of the chain is not exploitable as
  described.
- **`register.php` ineffective ephemeral key** — the original hypothesis
  was that `register.php:29-31` would call `register_user()` despite
  `verify_ephemeral_key()` returning false, and the user row would be
  created. Live testing showed `register_user()` does check the `$errors`
  array passed in by reference, and the pre-existing
  `register_page_error` is enough to bail out before the INSERT. The
  CSRF gate is decorative — `register_user` is still called — but the
  downstream consumer catches the error and no user is created. The
  demonstrated impact is `None` for actual account creation; a "robustness
  bug, not a security boundary break" classification is more accurate.
- **Findings that require admin or higher** — F-2, F-3, F-5, and nv7 all
  require `is_admin()` or `check_status(ACCESS_ADMINISTRATOR)`. They are
  retained in the upstream audit deliverable for insider-threat assessment
  but are out of scope for the public PoC repository, which prefers findings
  reachable from an anonymous context.

### F-1 — `upgrade_feed.php` runs the upgrade set on an anonymous GET

`upgrade_feed.php` is reachable as an unauthenticated GET endpoint. It is gated
only by `$conf['check_upgrade_feed']` (default `true`,
`include/config_default.inc.php:293`); it does not invoke
`check_upgrade_access_rights()` and does not require a `pwg_token`. On every
request the script connects to the application database, reads the `id` column
of `piwigo_upgrade`, scans `install/db/` for `*-database.php` filenames, and
`include()`s every script whose id is missing from the table. Each included
script issues a `pwg_query()` under the application's mysqli credentials — the
side effect is, by construction, identical to the side effect of a legitimate
`admin/upgrade.php` run.

The PoC demonstrates the path on a fresh install: with the pre-existing 121
rows in `piwigo_upgrade`, the next anonymous GET returns
`<pre>0 upgrades to apply</pre>` and exits 200. The PoC does not delete rows
from `piwigo_upgrade`; the demonstration in the live run was captured during
the construction phase of the audit, not by the published PoC. **What the
public PoC proves is that the path is anonymous** — the source-trace in
`report.md` is what proves the path is exploitable when the desync is
present. Reporting on this in `cve/*.cve.json` is honest about the
demonstrated reach.

The actual desync between `piwigo_upgrade` and `install/db/` is a routine
outcome of:

- a `git pull`/deploy that updates `install/db/*.php` without running the
  schema migration;
- a backup-restore cycle that omits `piwigo_upgrade`;
- an `admin/upgrade.php` upgrade run that is interrupted (browser close,
  Apache reload, mysqld restart, network blip) before the
  `INSERT INTO piwigo_upgrade` line is reached;
- a successful exploit of `GHSA-6wj3-7fhw-gfpm` / CVE-2026-44642, which
  lets an unauthenticated attacker delete rows from `piwigo_upgrade` via
  the SQLi in `check_upgrade_access_rights()`.

F-1 and the GHSA are neighbours in the upgrade-authentication flow; they
should be patched together.

### F-4 — Default-on error disclosure

`include/config_default.inc.php:580` ships `$conf['die_on_sql_error'] = true`.
`include/config_default.inc.php:611` ships
`$conf['show_php_errors_on_frontend'] = true`. With these defaults, the
`my_error()` handler in `include/dblayer/functions_mysqli.inc.php:835`
concatenates the failing `$query` and the mysqli error string and forwards
to `fatal_error()`. `fatal_error()` in `include/functions_html.inc.php:349`
renders the merged message and a PHP `debug_backtrace()` to the response
body and sets the HTTP status to 500. There is no authentication gate on
this path; any request that causes a mysqli error receives the disclosure.

The PoC triggers the disclosure by renaming the `piwigo_config` table to
`piwigo_config_disabled`. The next anonymous GET `/index.php` runs the
session bootstrap query and the conf loader, both of which `SELECT` from
`piwigo_config`; both fail with a "Table doesn't exist" mysqli error. The
response body contains the literal text `Uncaught mysqli_sql_exception: ...`,
the failing SQL, the mysqli `Table doesn't exist` string, and a
`debug_backtrace()` listing absolute file paths under `/var/www/html`. The
PoC then renames the table back, restoring the install.

In PHP 8 the legacy `my_error()` → `fatal_error()` chain is partially
bypassed: PHP 8 mysqli throws `mysqli_sql_exception` by default and the
default exception handler prints the same information. Both forms disclose
the schema, the SQL, the file paths, and the call graph; the PoC accepts
either.

Impact: information disclosure. An attacker gains (a) the application
schema, (b) the full SQL string with attacker-influenced substrings, (c)
server filesystem paths, (d) the PHP function call graph, and (e) version
hints from the mysqli error string. None of these are a primary vulnerability
on their own; collectively they materially accelerate subsequent attacks
(credential brute-forcing, path-based exploit chain selection, fingerprinting
of installed extensions and versions).

### nv5 — `pwg.images.rate` amplification (source-traced; conditional on the feature being on)

`pwg.images.rate` is registered in `ws.php` without `admin_only`. The
vendor default `$conf['rate_anonymous'] = true` allows anonymous callers.
The handler `update_rating_score()` runs on every successful rate and
issues an unconditional `SELECT element_id, COUNT(*), ROUND(AVG(rate),2)
FROM piwigo_rate GROUP BY element_id` followed by `mass_updates(IMAGES_TABLE, ...)`.
The first query scans the full `piwigo_rate` table on every call; the
second writes every image whose score was recomputed. There is no
per-IP, per-`pwg_id`, or per-second rate limit on the endpoint.

The PoC makes a single anonymous rate call, records the round-trip time,
and prints the MySQL `Com_select`/`Com_update` counters before and after.
In the live test fixture, `$conf['rate']` is set to `false` by `install.php`
and the rate handler bails out before reaching the GROUP BY. The PoC
exits 0 with a note that the amplification is in the source code and
would fire on any install where `$conf['rate'] = true` — the vendor default
in a fresh install — and that the source-traced path is in
`include/functions_rate.inc.php` and `include/functions.inc.php`'s
`update_rating_score`.

A future release of this PoC could include a setup step that sets
`$conf['rate'] = true` (an admin-side operation, not a vulnerability
demonstration) and then drive the rate call to capture the amplification
itself. The current version does not; the source-trace is the contribution.

---

## Inertness

The repository's master `README.md` (the one rule that shapes every PoC in
this repository) is satisfied here:

- **No reverse shell, no data exfiltration, no persistence.** The PoCs
  create one or two rows with names beginning `piwigo-poc-` and delete
  them on exit. The `poc/*.sh` scripts `trap EXIT` on a cleanup function
  that undoes whatever the script wrote.
- **No bundling of gadget chains.** No gadgets, no PoCs that require a
  second-order vulnerability, no PoC that depends on another finding being
  present.
- **No production target.** Each script refuses to run without
  `--confirm-authorised`. There is no fallback to a public URL.
- **The third-party targets that are referenced (`upgrade_feed.php`,
  `pwg.images.rate`, the mysqli error path) are themselves inert** — they
  are vendor-shipped code that behaves as documented; the PoC is observing
  that behaviour, not driving it.

---

## How to reproduce

The fixture is built from a clean Piwigo checkout inside a disposable Docker
container. See `env/BUILD.md` for the recipe and `env/CVSS.md` for the
score derivation.

| Step | What happens |
|---|---|
| 1. `env/up.sh` | brings up `piwigo-poc-db` (MariaDB 10.11) + `piwigo-poc-web` (PHP 8.2 / Apache, from `Dockerfile`) |
| 2. `env/install.sh` | drives `install.php` via POST with a known webmaster credential |
| 3. `poc/<finding>.sh --base http://localhost:8089 --confirm-authorised` | runs the finding; one row is created where required, one is verified, both are deleted on exit |
| 4. `evidence/<finding>.txt` | captured unedited output, including the response body and the assertion summary |

The Docker tear-down is `env/teardown.sh`. There is no persistent state
after the script exits; `piwigo_search`, `piwigo_config`, and `piwigo_rate`
are verified clean.

The default `PIWIGO_POC_DB_PASSWORD` in the scripts is `pocpass` (the
test fixture the PoCs were developed against). A fresh fixture created with
`env/up.sh` + `env/install.sh` uses `piwigo-poc` instead. Override with:

```bash
PIWIGO_POC_DB_USER=piwigo \
PIWIGO_POC_DB_PASSWORD=pocpass \
PIWIGO_POC_DB_NAME=piwigo \
PIWIGO_POC_DB_SERVICE=piwigo-poc-db \
PIWIGO_POC_WEB_SERVICE=piwigo-poc-web \
bash poc/piwigo-upgrade-feed-anon-db-mutation.sh --base http://localhost:8089 --confirm-authorised
```

---

## What is **not** demonstrated

The findings here are bounded by the inertness rule, which means several
of the highest-impact faces of the underlying defects are not exercised:

- F-1 — the PoC does not delete `piwigo_upgrade` rows; it observes the
  path on the pre-existing state of the fixture. The amplification against
  a target where *every* upgrade is pending is implicit in the source review
  and is recorded in `report.md`, but is not driven by the PoC.
- F-4 — the PoC renames a single table and captures one disclosure; the
  full breadth of attacker-influenced substrings that would be reflected
  in the response is bounded by the example.
- nv5 — the PoC does not enable the `rate` feature; it demonstrates the
  anonymous reachability of the endpoint and notes the source-traced
  amplification.

A live operator with an actual public Piwigo instance should treat each
finding as substantively larger than the PoC suggests; the PoCs here are
written to satisfy the CNA-level "is the defect real?" question, not the
operator-level "is my instance under attack?" question.
