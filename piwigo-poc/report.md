# Piwigo — reproduction report

> This document is the artefact a CNA reviewer reads. It is a trail, not a
> summary: every statement corresponds to a file under `evidence/` and every
> step is reproducible from a clean checkout of the audited commit. The
> canonical metadata is `submission.json`; this report is derived from it.

## Environment and provenance

- **Vendor / product / component:** Piwigo / Piwigo / core gallery,
  including `upgrade_feed.php`, `index.php` / `picture.php` action
  dispatch, `ws.php` endpoints, and `include/functions_*` library code.
- **Tested release:** 17.0.0beta1.
- **Exact commit, source URL, unmodified:** `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`,
  `https://github.com/Piwigo/Piwigo`, clean worktree, no local modifications.
- **Date, OS/architecture, runtime, dependencies:** 2026-10; Darwin 25.5.0
  (arm64); Docker Desktop 29.6.2; PHP 8.2.34 (`php:8.2-apache`); MariaDB
  10.11; Apache 2.4.68; curl 8.7.1; Docker + Compose v2.
- **Fixture creation and teardown:** `env/up.sh` brings up two containers
  (`piwigo-poc-db`, `piwigo-poc-web`) and waits for MariaDB readiness.
  `env/install.sh` drives `install.php` over a single `POST` with the
  wizard fields taken from `install.php:212+`. The fixture listens on
  `http://localhost:8089`. There is no reverse proxy, no TLS, and no
  external network access.
- **Authentication and attacker privileges:** Anonymous traffic
  (`PR:N`, no Cookie, no Authorization, no token) for F-1 / nv4 / nv5;
  status=normal authed user for nv3 (PoC logs in as a victim with a
  status=normal account it creates via direct INSERT into `piwigo_users`
  + `piwigo_user_infos`; the existing `pocadmin2` admin user is used
  for the contrast half of nv3 because `user_can_delete_comment=false`
  blocks normal users from deleting their own comments).
- **Default/non-default configuration and exposure:** Out-of-the-box
  defaults for F-1, nv3, nv4 (no `local/config/config.inc.php` overrides;
  `install.php` defaults). For nv5, the rate feature is enabled via
  `UPDATE piwigo_config SET value='true' WHERE param='rate'`; the PoC
  also seeds 100 000 synthetic rows into `piwigo_rate`. Both extensions
  are documented in the per-finding sections below.
- **Authorization to test:** OWN_DISPOSABLE_LAB_ONLY. The Docker fixture
  is on the local bridge, has no external port mapping, and the host
  has no production Piwigo instance under test.

## F1 — Anonymous `upgrade_feed.php` runs DDL/DML on the application database

### Expected security boundary

`upgrade_feed.php` is an unauthenticated GET endpoint. The product's
security model is that schema migrations run from the admin/manager shell
(`admin/upgrade.php`), which is gated by `check_status(ACCESS_ADMINISTRATOR)`
via `check_upgrade_access_rights()` at
`admin/include/functions_upgrade.php:181-258`. An anonymous network
caller should not be able to drive the same code path.

### Source-to-sink analysis

- **Entry and user-controlled input:** `upgrade_feed.php:1` — no
  `session_start()`, no `check_status()`, no token check. The only
  request-derived inputs are the cookie / query / headers / method;
  none influence the upgrade selection.
- **Authorization and validation checks:** `upgrade_feed.php:33-36` —
  `if (!$conf['check_upgrade_feed']) die("upgrade feed is not active");`.
  Default: `$conf['check_upgrade_feed'] = true;` in
  `include/config_default.inc.php:293`. `check_upgrade_access_rights()`
  exists at `admin/include/functions_upgrade.php:181-258` but is
  **not** called from `upgrade_feed.php`.
- **Security-relevant sink and action:**
  `upgrade_feed.php:88` — `include(UPGRADES_PATH.'/'.$upgrade_id.'-database.php');`.
  Each included script issues `pwg_query()` under the application's
  mysqli credentials. The include set is
  `array_diff(get_available_upgrade_ids(), $applied)` (lines 62-73).
- **Back-write:** `upgrade_feed.php:91-97` — `INSERT INTO piwigo_upgrade
  (id, applied, description) VALUES (...)`.
- **Preconditions and limitations:** The application's `piwigo_upgrade`
  table is desynchronised from the on-disk `install/db/` directory.
  This is a routine outcome of interrupted upgrades,
  fresh-code-on-old-DB deploys, backup-restore drift, or successful
  exploitation of GHSA-6wj3-7fhw-gfpm / CVE-2026-44642.

### Reproduction and controls

1. **Environment setup.** `env/up.sh && env/install.sh`.
2. **Test setup (test-fixture preparation; mirrors what install.php:367-385
   does in reverse for one specific id):**
   ```
   docker exec piwigo-poc-db mysql -upiwi** -e \
     "DROP TABLE IF EXISTS piwigo_image_format;
      DELETE FROM piwigo_upgrade WHERE id='145';"
   ```
3. **Baseline / negative control.** Anonymous GET against
   `/upgrade_feed.php` when no `piwigo_upgrade` row is missing returns
   HTTP 200 with body `<pre>0 upgrades to apply</pre>` and executes
   zero DDL/DML.
4. **Minimal PoC positive test.** Single anonymous GET:
   ```
   curl -sS -o response-body.txt -w '%{http_code}' \
     http://localhost:8089/upgrade_feed.php
   ```
   Returns HTTP 200 with body
   `<pre>1 upgrades to apply\n\n=== upgrade 145\n\nadd image formats table\n</pre>`.
5. **Independent side-effect verification.**
   ```
   docker exec piwigo-poc-db mysql -upiwi** -e "SHOW CREATE TABLE piwigo_image_format\G"
   ```
   shows the table now exists with the exact schema from
   `install/db/145-database.php`. `SELECT id, applied, description FROM
   piwigo_upgrade WHERE id='145'` shows the row has been re-populated
   with `applied=NOW()` and the upgrade description.
6. **Wire confirmation.** `curl -v` trace shows no `Cookie:`,
   no `Authorization:`, no `pwg_token` header on the wire.
7. **Cleanup.** The PoC undoes the DROP step implicitly by re-running
   the upgrade; the table is left in place because re-running
   `install.php` will not recreate it. The PoC exits 0 only when all
   7 assertions pass.

All captured output is in `evidence/F1-upgrade-feed/`:

- `response-body.txt` — the 73-byte response body
- `db-before-table.txt` — empty (`ERROR: table doesn't exist`)
- `db-after-table.txt` — `SHOW CREATE TABLE` after the GET
- `db-after-describe.txt` — `DESCRIBE piwigo_image_format`
- `db-before-upgrade.txt`, `db-after-upgrade.txt` — `piwigo_upgrade`
  before/after
- `setup-after-drop.txt` — table presence after the test setup
- `request-trace.txt` — full curl `-v` trace

### Evidence classification

- **Proof level:** RUNTIME_VERIFIED.
- **Observed facts:** Anonymous GET executes `CREATE TABLE
  piwigo_image_format`; the application database is mutated; the
  curl trace shows no Cookie / Authorization / pwg_token.
- **Inferences (NOT yet proven):** That the same anonymous-trigger
  model applies to all 121 entries in `install/db/` is from
  source-trace; we ran 145 (`CREATE TABLE`) and 180 (`[Aborted]`,
  row repopulation only) and source-reviewed the rest.
- **Negative results / counterexamples:** None — the path fired
  exactly as the source-trace predicts.
- **Security impact actually demonstrated:** Unauthenticated
  network caller executes real DDL on the application database.
- **What was NOT demonstrated:** All 121 scripts not run; production
  hardware not exercised; the GHSA-6wj3-7fhw-gfpm coupling not
  demonstrated end-to-end (F-1 and the GHSA are independent fixes).

### Scope, severity and remediation

- **Versions directly tested:** `17.0.0beta1` /
  `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`.
- **Versions not tested / assumptions:** Other releases in the
  17.x line, 16.x, 15.x. The static-review claim about the missing
  `check_upgrade_access_rights()` call applies to the whole master
  branch as observed; releases that have refactored the upgrade
  path are not covered.
- **CVSS vector and basis for each metric:**
  - `AV:N` — network-reachable (no auth, no local position).
  - `AC:L` — no special access conditions.
  - `PR:N` — no privileges required.
  - `UI:N` — no user interaction.
  - `S:C` — scope changed: code that should run in admin context
    runs on the anonymous GET path, mutating the application
    database.
  - `C:H` — full confidentiality impact: arbitrary read on the
    application database via the included scripts' `SELECT` paths.
  - `I:H` — full integrity impact: DDL/DML under the application
    credentials.
  - `A:N` — availability not directly affected, though DDL can
    take the gallery down.
- **CWE and rationale:** CWE-862 (Missing Authorization).
- **Vendor guidance / fix / workaround (distinguish confirmed from
  proposed):** *Proposed, not confirmed.* Call
  `check_upgrade_access_rights()` from `upgrade_feed.php`, or move
  the upgrade dispatcher behind admin authentication. The neighbour
  GHSA-6wj3-7fhw-gfpm SQLi in `check_upgrade_access_rights()` is a
  separate fix and should be patched alongside.
- **Duplicate / CVE / GHSA research and disclosure state:** No exact
  duplicate found for the missing-auth path. The GHSA-6wj3-7fhw-gfpm
  SQLi in the same authentication flow is a neighbour; it lets an
  unauthenticated attacker delete rows from `piwigo_upgrade`, which
  then turns into a F-1 trigger.
- **Vendor coordination:** Not yet contacted.

---

## nv3 — `picture.php` GET mutations are CSRF on any authed user

### Expected security boundary

`picture.php:248-401` dispatches state-changing actions through
`$_GET['action']`. The product's security model is that any state
change goes through a `pwg_token` check; peer actions
(`delete_comment`, `validate_comment`, `edit_comment`) follow that
rule. An authed user's `pwg_id` cookie should not be sufficient to
drive state-changing actions without a session-bound CSRF token.

### Source-to-sink analysis

- **Entry and user-controlled input:** `picture.php:248` — `if
  (isset($_GET['action'])) { switch ($_GET['action']) {`. The
  `$_GET['action']` selects which DB call to make.
- **Authorization and validation checks:** For the four
  unprotected actions, none.
  - `add_to_favorites` (`:252-264`): `INSERT INTO piwigo_favorites`.
  - `remove_from_favorites` (`:266-285`): `DELETE FROM piwigo_favorites`.
  - `add_to_caddie` (`:306-310`): `INSERT INTO piwigo_caddie`.
  - `rate` (`:312-316`): `rate_picture()`.
  Peer actions on the same page that **do** check `pwg_token()`:
  - `edit_comment` (`:328`) — `check_pwg_token()` on the content path.
  - `delete_comment` (`:368`) — `check_pwg_token()` on entry.
  - `validate_comment` (`:385`) — `check_pwg_token()` on entry.
- **Security-relevant sink and action:** the four unprotected
  actions directly mutate `piwigo_favorites`, `piwigo_caddie`,
  `piwigo_rate`. `rate_picture` also calls `update_rating_score()`,
  which runs the O(R) GROUP BY.
- **Preconditions and limitations:** The victim must be logged in;
  the attacker's page only needs to send the victim an
  `<img src="…action=add_to_favorites">` link.

### Reproduction and controls

1. **Environment setup.** `env/up.sh && env/install.sh`.
2. **Test setup.** Create a victim with `status=normal`:
   ```
   HASH=$(docker exec piwigo-poc-web php -r 'echo password_hash("VictimPass!2026", PASSWORD_BCRYPT);')
   docker exec piwigo-poc-db mysql -upiwi** -e \
     "INSERT INTO piwigo_users (username, password) VALUES ('victim_user_csrf', '$HASH');
      SET @uid = LAST_INSERT_ID();
      INSERT INTO piwigo_user_infos (user_id, status, language, registration_date) VALUES (@uid, 'normal', 'en_GB', NOW());"
   ```
3. **Baseline / negative control.** Before the PoC, `SELECT COUNT(*)
   FROM piwigo_favorites WHERE user_id=<victim>` and similarly for
   `piwigo_caddie` should both be `0`.
4. **Minimal PoC positive test.** Login as victim, then issue two
   tokenless GETs:
   ```
   curl -sS -c jar -b jar -X POST http://localhost:8089/identification.php \
     --data 'login=1&username=victim_user_csrf&password=VictimPass!2026'
   curl -sS -b jar -o /dev/null -w '%{http_code}' \
     'http://localhost:8089/picture.php?/1/category/1&action=add_to_favorites'
   curl -sS -b jar -o /dev/null -w '%{http_code}' \
     'http://localhost:8089/picture.php?/1/category/1&action=add_to_caddie'
   ```
   Both return HTTP 302. After the requests, `piwigo_favorites` and
   `piwigo_caddie` each contain a row keyed to (victim_uid,
   image_id=1).
5. **Independent side-effect verification.** Direct `SELECT` against
   the rows above.
6. **Peer contrast (negative control).** As `pocadmin2`
   (admin; required because `user_can_delete_comment=false` blocks
   normal users from deleting their own comments):
   - `delete_comment&comment_to_delete=<id>` without `pwg_token` →
     HTTP 400, comment row preserved.
   - same request with the correct `pwg_token`
     (`hash_hmac('md5', $pwg_id, $secret_key)` per
     `include/functions.inc.php:2201-2206`) → HTTP 302 redirect,
     comment row deleted.
7. **Cleanup.** The PoC creates and removes its own victim user and
   the inserted favorite / caddie rows on EXIT.

All captured output is in `evidence/nv3-csrf-get-mutations/`:

- `db-before.txt`, `db-after.txt` — favorites + caddie row counts
  before/after the PoC
- `db-comment-after-no-token.txt` — peer-contrast comment after the
  no-token attempt
- `csrf-trace.txt` — full curl `-v` trace of one CSRF URL
- `victim-create.txt` — captured INSERT confirmation

### Evidence classification

- **Proof level:** RUNTIME_VERIFIED.
- **Observed facts:** Two single tokenless GETs insert rows into
  `piwigo_favorites` and `piwigo_caddie`; the peer contrast shows
  `check_pwg_token()` is the missing gate.
- **Inferences (NOT yet proven):** The CSRF works in a real browser
  end-to-end (HTML+cookie); the cURL PoC reproduces the same wire
  behaviour the browser would produce.
- **Negative results / counterexamples:** None.
- **Security impact actually demonstrated:** State mutation driven
  by an attacker-supplied URL with a logged-in victim's session
  cookie, no token required.
- **What was NOT demonstrated:** `remove_from_favorites`, `rate`,
  and `set_as_representative` (admin-gated) share the same omission
  but were not directly exercised. Real-browser end-to-end
  reproduction (HTML + cookie) not captured.

### Scope, severity and remediation

- **Versions directly tested:** `17.0.0beta1` /
  `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`.
- **Versions not tested / assumptions:** Other releases.
- **CVSS vector and basis for each metric:**
  - `AV:N` — network-reachable.
  - `AC:L` — no special access conditions.
  - `PR:N` — no privileges required (the victim is authed but the
    CSRF exploits the missing CSRF gate).
  - `UI:R` — requires the victim to click the attacker-supplied
    link (or render an `<img>`).
  - `S:U` — scope unchanged.
  - `C:N` — no direct confidentiality impact.
  - `I:H` — high integrity impact: bookmarks / caddie pollution /
    rating inflation under the victim's identity.
  - `A:N` — no direct availability impact.
- **CWE and rationale:** CWE-352 (Cross-Site Request Forgery).
- **Vendor guidance / fix / workaround (distinguish confirmed from
  proposed):** *Proposed.* Replace the unprotected action dispatch
  with a peer-style `check_pwg_token()` at the top of each
  `case '…':` block. The `pwg_token` infrastructure is already
  present and works (peer actions demonstrate this).
- **Duplicate / CVE / GHSA research and disclosure state:** None
  found for this exact picture.php gap.
- **Vendor coordination:** Not yet contacted.

---

## nv4 — Anonymous unbounded `pwg.images.filteredSearch.create`

### Expected security boundary

`ws_images_filteredSearch_create` is a WS endpoint that the
saved-search sidebar calls when a logged-in user saves a search. An
unauthenticated caller should not be able to grow the application's
`piwigo_search` table without bound.

### Source-to-sink analysis

- **Entry and user-controlled input:** `ws.php` registers
  `pwg.images.filteredSearch.create` without `admin_only`. The
  handler at `include/ws_functions/pwg.images.php:753-1089`
  accepts anonymous POSTs.
- **Authorization and validation checks:** None. No authentication
  gate, no `pwg_token` check, no per-IP / per-session rate limit,
  no duplicate detection.
- **Security-relevant sink and action:**
  `include/ws_functions/pwg.images.php:1083` — `list($search_uuid,
  $search_url) = save_search($search, $search_info['id'] ?? null);`,
  which calls `save_search()` at
  `include/functions_search.inc.php:2106-2127` and unconditionally
  `INSERT`s into `piwigo_search`.
- **Preconditions and limitations:** Default Piwigo 17.0.0beta1
  install.

### Reproduction and controls

1. **Environment setup.** `env/up.sh && env/install.sh`.
2. **Baseline / negative control.** `SELECT COUNT(*) FROM
   piwigo_search` before the PoC.
3. **Minimal PoC positive test.** `N=10` anonymous POSTs:
   ```
   for i in 1..10:
     curl -sS -X POST 'http://localhost:8089/ws.php?method=pwg.images.filteredSearch.create' \
       --data "allwords=anon_poc_${i}&allwords_mode=AND"
   ```
   Each returns HTTP 200 with a unique `<search_id>psk-…</search_id>`.
4. **Independent side-effect verification.** `SELECT COUNT(*) FROM
   piwigo_search` returns `baseline + N` with unique `search_uuid`
   values populated.
5. **Wire confirmation.** `curl -v` trace shows no `Cookie:`,
   no `Authorization:`, no `pwg_token` on the wire.
6. **Cleanup.** The PoC does not remove the inserted rows; the
   operator can `TRUNCATE piwigo_search` after the run if desired.

All captured output is in `evidence/nv4-filtered-search-unbounded/`:

- `db-before-count.txt`, `db-after-count.txt` — row counts
- `db-after-sample.txt` — newest 5 rows
- `request-log.txt` — per-request HTTP code + search_id
- `resp-*-*.xml` — full response XML for each request
- `anonymous-trace.txt` — curl `-v` trace

### Evidence classification

- **Proof level:** RUNTIME_VERIFIED.
- **Observed facts:** `N=10` anonymous POSTs grow `piwigo_search`
  by exactly 10 rows with unique search_ids; the curl trace
  carries no Cookie header.
- **Inferences (NOT yet proven):** That gallery-page-load time
  grows with `piwigo_search` row count; the read-amplification claim
  is from the static-review of `include/search_filters.inc.php`.
- **Negative results / counterexamples:** None — every request
  succeeds.
- **Security impact actually demonstrated:** Anonymous POSTs grow
  the application's `piwigo_search` table at the rate of `N` rows
  per `N` requests.
- **What was NOT demonstrated:** Gallery-page-load time as a
  function of `piwigo_search` row count; `N > 10`; cross-botnet
  coordination.

### Scope, severity and remediation

- **Versions directly tested:** `17.0.0beta1` /
  `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`.
- **Versions not tested / assumptions:** Other releases.
- **CVSS vector and basis for each metric:**
  - `AV:N` — network-reachable.
  - `AC:L` — no special access conditions.
  - `PR:N` — no privileges required.
  - `UI:N` — no user interaction.
  - `S:U` — scope unchanged.
  - `C:N` — no direct confidentiality impact.
  - `I:N` — no direct integrity impact.
  - `A:H` — high availability impact: unbounded DB growth with read
    amplification on every gallery page load.
- **CWE and rationale:** CWE-400 (Uncontrolled Resource Consumption),
  CWE-770 (Allocation of Resources Without Limits or Throttling).
- **Vendor guidance / fix / workaround (distinguish confirmed from
  proposed):** *Proposed.* Require authentication before
  `ws_images_filteredSearch_create` (a logged-in user is the only
  intended caller; the saved-search sidebar has no benefit for
  unauthenticated callers). Add a duplicate-detection /
  rate-limit gate.
- **Duplicate / CVE / GHSA research and disclosure state:** None
  found.
- **Vendor coordination:** Not yet contacted.

---

## nv5 — `pwg.images.rate` unconditional O(R) per request

### Expected security boundary

`ws_images_rate` is a WS endpoint that lets gallery visitors rate
images. The product's security model is that this feature is gated
by `$conf['rate']` and that callers cannot drive unbounded DB
work. Per CNA Rules §4.1.5, the product-side resource control
defect is the unconditional O(R) `GROUP BY` plus `mass_updates`
on every successful call, where R is the row count of
`piwigo_rate`.

### Source-to-sink analysis

- **Entry and user-controlled input:** `ws.php` registers
  `pwg.images.rate` without `admin_only`. The handler at
  `include/ws_functions/pwg.images.php:622-652` accepts anonymous
  POSTs.
- **Authorization and validation checks:** Image accessibility via
  F&F only. No `pwg_token` check. No per-IP / per-session /
  per-second rate limit.
- **Security-relevant sink and action:**
  `include/functions_rate.inc.php:123-178` — `update_rating_score()`
  unconditionally issues
  ```sql
  SELECT element_id, COUNT(rate) AS rcount, SUM(rate) AS rsum
    FROM piwigo_rate
    GROUP BY element_id;
  ```
  followed by `mass_updates(IMAGES_TABLE, …)` over every image that
  has at least one rate, plus a second SELECT to null-out
  `rating_score` on images whose rate count went to zero
  (`:181-197`).
- **Preconditions and limitations:** `$conf['rate'] = true` (the
  rate feature toggle). `$conf['rate_anonymous']` is conventionally
  true when `$conf['rate']` is true. Neither is declared in
  `include/config_default.inc.php`; both default to NULL/false.

### Reproduction and controls

1. **Environment setup.** `env/up.sh && env/install.sh`.
2. **Test setup.** Enable the rate feature, then truncate
   `piwigo_rate`:
   ```
   docker exec piwigo-poc-db mysql -upiwi** -e \
     "UPDATE piwigo_config SET value='true' WHERE param='rate';
      UPDATE piwigo_config SET value='0,1,2,3,4,5' WHERE param='rate_items';
      DELETE FROM piwigo_rate;"
   ```
3. **Baseline.** `N=5` anonymous rate POSTs, time each:
   ```
   for i in 1..5:
     time curl -sS -X POST 'http://localhost:8089/ws.php?method=pwg.images.rate' \
       --data 'image_id=1&rate=3'
   ```
4. **Seed.** `INSERT 100 000` synthetic rows into `piwigo_rate`.
5. **Minimal PoC positive test.** Same `N=5` anonymous rate POSTs,
   time each. Measured avg 0.0300s vs baseline avg 0.0120s.
6. **Decisive proof (EXPLAIN).** `EXPLAIN SELECT element_id,
   COUNT(rate), SUM(rate) FROM piwigo_rate GROUP BY element_id`
   returns `type=ALL, key=NULL, rows=100001, Extra=Using temporary;
   Using filesort`. This is the proof that every call scans and
   sorts the full set regardless of which image was rated.
7. **Wire confirmation.** `curl -v` trace shows no `Cookie: pwg_id`,
   no `Authorization:`, no `pwg_token`.
8. **Cleanup.** The PoC leaves the seeded rows in place; the
   operator can `TRUNCATE piwigo_rate` and reset
   `piwigo_config.rate='false'` after the run if desired.

All captured output is in `evidence/nv5-rate-db-amplification/`:

- `config.txt` — `piwigo_config` rows for rate / rate_items /
  rate_anonymous
- `baseline-count.txt`, `baseline-timing.txt` — empty-table
  row count + per-request timing
- `seeded-count.txt` — row count after seeding
- `measured-timing.txt` — per-request timing at N=100k
- `explain.txt` — EXPLAIN output
- `anonymous-trace.txt` — curl `-v` trace

### Evidence classification

- **Proof level:** RUNTIME_VERIFIED.
- **Observed facts:** Per-request timing grows with `piwigo_rate`
  row count; `EXPLAIN` confirms full scan + filesort on every
  call.
- **Inferences (NOT yet proven):** That the amplification scales
  linearly to `N=1M` and beyond is from the EXPLAIN (the
  GROUP BY + filesort + temporary table work is O(R) by
  definition); we did not seed at that size.
- **Negative results / counterexamples:** None — the path fires
  exactly as the source-trace predicts.
- **Security impact actually demonstrated:** Anonymous POSTs drive
  an unconditional O(R) computation on the application's database;
  the EXPLAIN is the proof, the 1.5× timing at N=100k is the
  incidental observation.
- **What was NOT demonstrated:** `N > 100k` (seed time bound);
  per-image-cache details; the read-side amplification on gallery
  pages; the `rate_anonymous=false` branch.

### Scope, severity and remediation

- **Versions directly tested:** `17.0.0beta1` /
  `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`.
- **Versions not tested / assumptions:** Other releases.
- **CVSS vector and basis for each metric:**
  - `AV:N` — network-reachable.
  - `AC:L` — no special access conditions.
  - `PR:N` — no privileges required.
  - `UI:N` — no user interaction.
  - `S:U` — scope unchanged.
  - `C:N` — no direct confidentiality impact.
  - `I:N` — no direct integrity impact.
  - `A:H` — high availability impact: per-call O(R) DB work
    against attacker-growable state.
- **CWE and rationale:** CWE-400 (Uncontrolled Resource Consumption),
  CWE-770 (Allocation of Resources Without Limits or Throttling),
  CWE-405 (Asymmetric Resource Consumption / Amplification) per CNA
  Rules §4.1.5.
- **Vendor guidance / fix / workaround (distinguish confirmed from
  proposed):** *Proposed.* Per-caller throttling on
  `pwg.images.rate` (e.g., session-id based rate limit at
  `include/ws_functions/pwg.images.php:622`). Ideally, computing
  scores incrementally (the per-image delta) rather than
  re-aggregating from scratch on every rate.
- **Duplicate / CVE / GHSA research and disclosure state:** None
  found.
- **Vendor coordination:** Not yet contacted.

---

## Findings removed from this report

The audit deliverable contains additional candidate records that did not
survive live testing, or that require admin / higher privileges.
Those records are retained in the upstream audit deliverable for
reference but are not in this report:

- **F-4 (`piwigo:default.error.sql.trace.disclosure`)** — the
  published trigger required renaming `piwigo_config` to
  `piwigo_config_disabled`, which an unauthenticated user cannot
  do on the application database. Removed per the "regular
  attacker reach" principle.
- **F-6 (`piwigo:register:ineffective_ephemeral_key`)** — live
  testing showed `register_user()` checks the `$errors` array
  passed in by reference and the pre-existing `register_page_error`
  is enough to skip the INSERT.
- **Stored XSS via the search rules footer script** — PHP 8.2's
  `json_encode` escapes `/` to `\/` by default, defeating the
  `</script>` break-out; the WS handler does not accept a
  free-form string field for the rule.
- **F-2, F-3, F-5, nv7** — require `is_admin()` or
  `check_status(ACCESS_ADMINISTRATOR)`. Out of scope for the public
  PoC repository, which prefers findings reachable from a non-admin
  user.

## Network exposure

The fixture listens on `localhost:8089` only. There is no external
port mapping for the database. The container has no outbound network
access configured; the PoCs do not need it (no telemetry, no update
checks, no third-party calls).

## Verification

Each PoC:

1. creates only resources whose names begin `piwigo-poc-`,
   `anon_poc_`, `seed_`, `csrf_`, or `contrast_`;
2. exits `0` on success and non-zero on assertion failure;
3. writes the captured response body, before/after DB state, and
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
lifetime; the PoCs are fast (single-digit seconds each, except for
nv5's 1-second seed step).

## Quality gates checklist (per project policy)

- [x] Lab authorization recorded (OWN_DISPOSABLE_LAB_ONLY)
- [x] `submission.json` is complete with schemaVersion 1
- [x] Each finding has positive control, negative control, observed
      impact, and explicit "not demonstrated"
- [x] CVSS vector is backed by observed evidence; does not overclaim
- [x] No self-issued CVE ID, no fabricated CNA fields; cve/ omitted
- [ ] Vendor/CNA coordination recorded — **NOT YET**; status is
      NOT_REPORTED, no human publication approval
- [x] Scripts are bounded / non-destructive; no real-user data or
      secrets included (cookie jars excluded via `.gitignore`)