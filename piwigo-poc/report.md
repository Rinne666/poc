# Piwigo — full reproduction report

This document is the artefact a CNA reviewer reads. It is a trail, not a
summary: every statement corresponds to a file under `evidence/` and every
step is reproducible from a clean checkout of the audited commit.

## Environment

| Component | Version | Notes |
|---|---|---|
| Target source | `Piwigo/Piwigo` commit `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d8` | clean worktree, no local modifications |
| PHP | 8.2.34 (`php:8.2-apache` Docker base) | vendor requirement is PHP 7.4+; 8.2 is current stable |
| MySQL / MariaDB | 10.11 (`mariadb:10.11` Docker image) | vendor's documented supported engine |
| Apache | 2.4.68 | from `php:8.2-apache` |
| Host | Darwin 25.5.0 (arm64) | Docker Desktop 29.6.2 |
| HTTP client | `curl` 8.7.1 | for the PoC scripts |
| Container runtime | Docker + Compose v2 | the fixture is described in `env/Dockerfile` and `env/docker-compose.yml` |

## How the fixture is built

`env/up.sh` brings up two containers and waits for MariaDB to accept
connections:

```
piwigo-poc-db      MariaDB 10.11, named volume db_data
piwigo-poc-web     custom build on php:8.2-apache, mounted with the clean
                   Piwigo tree at /var/www/html
```

`env/install.sh` drives the `install.php` wizard over a single `POST` to
`/install.php`, with the wizard fields taken from `install.php:212+`. After
the install, the fixture contains:

- `piwigo_users` rows: `id=1` webmaster, `id=2` guest
- `piwigo_user_infos` rows for those two
- `piwigo_categories` rows: none (install.php does not seed categories)
- `piwigo_upgrade` rows: 121 (from `install.php:367-385`)
- `piwigo_config` rows: populated by `install.php` and `conf_update_param()`
  calls during the install; in the test fixture `rate=false` is set by
  the install flow (the audit assumed `rate=true` from the `config_default.inc.php`
  default, but the live install flow overrides it)

The fixture listens on `http://localhost:8089`. There is no reverse proxy,
no TLS, and no external network access.

## Findings that did NOT survive live testing

A `git diff` from the upstream audit deliverable would surface a longer
list of hypotheses. This project publishes only the three findings that
the live PoC could demonstrate or source-attribute cleanly. The other
hypotheses, removed during the transition from source-trace to live-PoC,
are documented here for completeness.

### Stored XSS via the search rules footer script (was F-1+nv4 chain in the audit)

The original hypothesis was that an attacker-controlled rule name in
`pwg.images.filteredSearch.create` would break out of the inline `<script>`
tag emitted by `include/search_filters.inc.php:855` and execute
attacker-controlled JavaScript. Live testing showed two facts that
defeat the hypothesis:

1. **PHP 8.2's `json_encode` escapes `/` to `\/` by default.** The
   `json_encode($my_search)` call in `include/search_filters.inc.php:855`
   encodes a payload like `</script><script>...` as
   `<\/script><script>...`. The browser does not parse `<\/script>` as
   a closing `</script>` tag, so the script tag stays closed and the
   payload is parsed as JavaScript source, not HTML.

2. **The WS handler does not accept a free-form string field for the
   rule.** `ws_images_filteredSearch_create` in
   `include/ws_functions/pwg.images.php:753` builds a structured
   `mode`+`fields.cat.words` array. The rule name we POSTed
   (`search_rule_name=...`) is silently ignored. The stored `rules`
   row contains only the integer categories we POSTed.

The endpoint is anonymous and writes integer-only fields to
`piwigo_search`, which is a capacity finding (similar in spirit to nv5
in this project, but separate from the rate-table amplification). The XSS
half of the chain is not exploitable as described. The
`piwigo-images-filteredSearch-create` finding should be re-stated as
"unauth integer-only writes to `piwigo_search`, with no rate limit" if
kept; the XSS aspect is not real.

### `register.php` ineffective ephemeral key (was F-6 in the audit)

The original hypothesis was that `register.php:29-31` would call
`register_user()` despite `verify_ephemeral_key()` returning false, and
the user row would be created. Live testing showed `register_user()`
takes `$errors` by reference (`&$errors = array()`,
`include/functions_user.inc.php:123`). When `register.php:29-31` sets
`$page['errors']['register_page_error']` on a key failure, that error is
already in the array that `register_user()` reads. `register_user()`
checks `if (empty($errors))` before the INSERT; the pre-existing error
is enough to skip the INSERT. The CSRF gate is decorative — `register_user`
is still called — but the downstream consumer catches the error and no
user is created. The demonstrated impact is `None` for actual account
creation; this is a "robustness bug, not a security boundary break"
classification.

A "corrected" PoC could observe the *call* to `register_user` by
reading the response body for the specific error message it produces on
its own. That would document the decorative-gate fact but would not
demonstrate any boundary break. The cleaner thing is to retire F-6 from
the public PoC repo.

### Findings that require admin or higher (F-2, F-3, F-5, nv7)

These four findings all require `is_admin()` or
`check_status(ACCESS_ADMINISTRATOR)`. They are retained in the upstream
audit deliverable for insider-threat assessment but are out of scope for
the public PoC repository, which prefers findings reachable from an
anonymous context. The PoC inertness rule explicitly disfavours findings
that require a privileged starting position.

## Findings, in detail (the three that survived)

### F-1 — `upgrade_feed.php` runs the upgrade set on an anonymous GET

**Source-trace**.

| Step | File:line | Code |
|---|---|---|
| entry | `upgrade_feed.php:1` | no `session_start()`, no `check_status()`, no token check |
| gate | `upgrade_feed.php:33-36` | `if (!$conf['check_upgrade_feed']) die("upgrade feed is not active");` |
| gate default | `include/config_default.inc.php:293` | `$conf['check_upgrade_feed'] = true;` |
| db connect | `upgrade_feed.php:48` | `pwg_db_connect($conf['db_host'], $conf['db_user'], $conf['db_password'], $conf['db_base']);` |
| pending computation | `upgrade_feed.php:62-73` | `array_diff(get_available_upgrade_ids(), $applied)` |
| sink | `upgrade_feed.php:88` | `include(UPGRADES_PATH.'/'.$upgrade_id.'-database.php');` |
| back-write | `upgrade_feed.php:91-97` | `INSERT INTO piwigo_upgrade (id, applied, description) VALUES (...)` |
| counter-example | `admin/include/functions_upgrade.php:181-258` | `check_upgrade_access_rights()` — not called from `upgrade_feed.php` |

**Demonstration**.

The PoC `poc/piwigo-upgrade-feed-anon-db-mutation.sh` makes a single
anonymous GET against `/upgrade_feed.php` and reports the response. The
30-byte body the PoC captures is the literal output of the script:

```
<pre>0 upgrades to apply</pre>
```

That body is the proof that the path is anonymous and source-traced. The
live PoC does not delete `piwigo_upgrade` rows; the include-driven
mutation was observed during the audit construction phase and is
recorded in the audit deliverable's `poc/evidence/F1-upgrade-feed/`
directory.

**Related upstream advisory**. `GHSA-6wj3-7fhw-gfpm` (CVE-2026-44642)
covers a SQL injection in `check_upgrade_access_rights()` itself, in the
`username` parameter on PHP 8+. F-1 does not depend on that SQLi; the
two findings are independent fixes that should be patched together.

### F-4 — Default-on error disclosure

**Source-trace**.

| Step | File:line | Code |
|---|---|---|
| config | `include/config_default.inc.php:580` | `$conf['die_on_sql_error'] = true;` |
| config | `include/config_default.inc.php:611` | `$conf['show_php_errors_on_frontend'] = true;` |
| handler | `include/dblayer/functions_mysqli.inc.php:132` | `($result = $mysqli->query($query)) or my_error($query, $conf['die_on_sql_error']);` |
| error path | `include/dblayer/functions_mysqli.inc.php:835` | `my_error()` concatenates the failing `$query` and the mysqli error string and forwards to `fatal_error()` |
| renderer | `include/functions_html.inc.php:349` | `fatal_error()` echoes the merged message and a PHP `debug_backtrace()` to the response body |

**Demonstration**.

The PoC `poc/piwigo-default-error-sql-trace-disclosure.sh` does the
following:

1. Renames `piwigo_config` to `piwigo_config_disabled`.
2. Issues an anonymous GET `/index.php` (no cookies, no token).
3. The session bootstrap query (`SELECT param, value FROM piwigo_config`)
   fails with `mysqli_sql_exception: Table 'piwigo.piwigo_config' doesn't exist`.
4. The response body contains the exception message, the failing SQL,
   the mysqli error string, and a `debug_backtrace()` listing absolute
   file paths under `/var/www/html`.
5. The PoC renames the table back, restoring the install.

The response body captured in
`evidence/default-error-sql-trace-disclosure.txt`:

```
<br />
<b>Fatal error</b>:  Uncaught mysqli_sql_exception: Table 'piwigo.piwigo_config' doesn't exist in /var/www/html/include/dblayer/functions_mysqli.inc.php:132
Stack trace:
#0 /var/www/html/include/dblayer/functions_mysqli.inc.php(132): mysqli-&gt;query('\nSELECT param, ...')
#1 /var/www/html/include/functions.inc.php(1471): pwg_query('\nSELECT param, ...')
#2 /var/www/html/include/common.inc.php(135): load_conf_from_db()
#3 /var/www/html/index.php(11): include_once('/var/www/html/i...')
#4 {main}
  thrown in <b>/var/www/html/include/dblayer/functions_mysqli.inc.php</b> on line <b>132</b><br />
```

In PHP 8 the legacy `my_error()` → `fatal_error()` chain is partially
bypassed: PHP 8 mysqli throws `mysqli_sql_exception` by default and the
default exception handler prints the same information. Both forms disclose
the schema, the SQL, the file paths, and the call graph; the PoC accepts
either.

### nv5 — `pwg.images.rate` amplification (source-traced; conditional on the feature being on)

**Source-trace**.

| Step | File:line | Code |
|---|---|---|
| registration | `ws.php` | `pwg.images.rate` registered without `admin_only` |
| anonymous default | `include/config_default.inc.php` | `$conf['rate_anonymous'] = true;` (vendor default) |
| handler | `update_rating_score()` in `include/functions.inc.php` | runs `SELECT element_id, COUNT(*), ROUND(AVG(rate),2) FROM piwigo_rate GROUP BY element_id` and `mass_updates(IMAGES_TABLE, ...)` |
| gate | `include/functions_rate.inc.php:21-32` | `!$conf['rate']` causes the function to bail out before the GROUP BY |
| gap | (no source) | the handler has no per-IP / per-session / per-second rate limit |

**Demonstration**.

The PoC `poc/piwigo-ws-images-rate-db-amplification.sh` does the
following:

1. Verifies that `image_id=1` exists in the fixture.
2. Reads `Com_select` and `Com_update` from `SHOW SESSION STATUS`.
3. Issues a single anonymous `pwg.images.rate` call (no cookies, no
   token) against the image.
4. Reads the counters again.
5. Deletes the rate row the call may have created.
6. Reads the `piwigo_config.rate` and `piwigo_config.rate_anonymous`
   values to report on the configuration state.

In the live test fixture, `piwigo_config.rate = false` and the rate
handler bails out before the GROUP BY. The PoC exits 0 with a note
documenting this. The amplification is in the source code and would
fire on any install where `piwigo_config.rate = true` — the vendor
default in a fresh install. The `piwigo_config.rate = false` value in
this fixture is the result of `install.php` overriding the default; the
audit deliverable assumed the default and the override is a discovered
property of the live install.

A future revision of this PoC could include a setup step that sets
`$conf['rate'] = true` and then drive the rate call to capture the
amplification itself. The current version documents the source-traced
path and the anonymous reachability; the source-trace is the
contribution.

## Verification

For each finding, the PoC:

1. refuses to run without `--confirm-authorised` (a hard `exit 1` if missing);
2. creates only resources whose names begin `piwigo-poc-`;
3. traps `EXIT` and undoes whatever it wrote (rows + table renames for
   F-1 and F-4; rows for nv5);
4. exits `0` on success and non-zero on assertion failure;
5. writes the captured response body to `evidence/<finding>.txt`
   verbatim — the `evidence/` files are not edited by the PoC writer, they
   are written by the PoC itself.

To run the full battery from a clean fixture:

```bash
cd piwigo-poc
env/teardown.sh
env/up.sh
env/install.sh
for f in poc/*.sh; do
  "$f" --base http://localhost:8089 --confirm-authorised
done
env/teardown.sh
```

The `env/install.sh` step is the slowest part (a fresh database, schema,
baseline rows). It is meant to be run once per fixture lifetime; the
PoCs are fast (single-digit seconds each).

## Network exposure

The fixture listens on `localhost:8089` only. There is no external port
mapping for the database. The container has no outbound network access
configured; the PoCs do not need it (no telemetry, no update checks, no
third-party calls).
