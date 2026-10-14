# Piwigo — proof-of-concept material

**Target** [`Piwigo/Piwigo`](https://github.com/Piwigo/Piwigo) — self-hosted PHP photo gallery
**Versions tested** 17.0.0beta1
**Commit tested** `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d8` (clean worktree)
**Disclosure state** **NOT yet reported to the vendor.** Piwigo publishes a
[`SECURITY.md`](https://github.com/Piwigo/Piwigo/blob/master/SECURITY.md) directing reports to
`security@piwigo.org` with a 72-hour first-response SLA. All findings here are
reachable from a regular / anonymous user — no admin session required.
The `cve/*.cve.json` files carry `CVE-PENDING-*` identifiers and `state: RESERVED`;
**no CVE number has been allocated.**

> If you operate a Piwigo 17.0.0beta1 instance, treat all findings here as live.
> The critical one (F-1) is reachable from a single anonymous GET against a
> target whose `piwigo_upgrade` table has been desynchronised from the
> `install/db/` directory — that desync is a routine outcome of interrupted
> upgrades, fresh-code-on-old-DB deploys, and backup-restore drift.

---

## Findings (regular-user / anonymous perspective)

| ID | Title | CWE | CVSS v3.1 | CVE JSON | Demonstrated |
|---|---|---|---|---|---|
| **F-1** | Anonymous GET against `/upgrade_feed.php` executes `install/db/<n>-database.php` under the application's MySQL credentials | CWE-862, CWE-77 | **9.1** (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N) | `cve/CVE-PENDING-piwigo-upgrade-feed-anon-db-mutation.json` | real DDL: anonymous GET triggers `CREATE TABLE piwigo_image_format` |
| **nv3** | `picture.php` GET handlers `add_to_favorites` / `add_to_caddie` / `rate` mutate state without `check_pwg_token()` — CSRF on any logged-in user | CWE-352, CWE-306 | 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N) | `cve/CVE-PENDING-piwigo-picture-csrf-get-mutations.json` | 2 mutations + peer contrast (delete_comment w/wo token) |
| **nv4** | `pwg.images.filteredSearch.create` accepts anonymous POSTs with no auth / no token / no rate limit; each call inserts a row in `piwigo_search` | CWE-400, CWE-770 | 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) | `cve/CVE-PENDING-piwigo-ws-filtered-search-unbounded.json` | 10 anon rows in one script run, unique search_ids |
| **nv5** | `pwg.images.rate` unconditionally executes an O(R) GROUP BY + mass_updates per request (CNA Rules §4.1.5: product-side resource defect) | CWE-400, CWE-770, CWE-405 | **7.5** (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) | `cve/CVE-PENDING-piwigo-ws-images-rate-db-amplification.json` | EXPLAIN `type=ALL, Using temporary; Using filesort` + 1.5× timing at N=100k |

The CVSS scores are the reporter's scoring of the demonstrated impact.
F-1 is Critical (S:C, C:H/I:H) because the demonstrated side effect is
full DDL on the application database. nv3 is medium CSRF. nv4 and nv5
are both 7.5 — high — capacity/DoS class. nv5's trigger condition is
`$conf['rate'] = true` (a documented one-click admin config change);
the defect is the unconditional O(R) pattern in `update_rating_score()`,
which is in the source code regardless of whether the rate feature is
currently on.

---

## Findings not included in this repository

### F-4 — `piwigo:default.error.sql.trace.disclosure` (removed)

Originally demonstrated by renaming `piwigo_config` →
`piwigo_config_disabled` to manufacture a mysqli error. The reviewer
correctly observed that no regular, unauthenticated attacker has the
ability to rename a table on the application database. The defect is
real but the trigger precondition violates the "regular attacker reach"
requirement. F-4 is retained in the upstream audit deliverable for
reference but is **not** in the public PoC repository or in any
`cve/*.json`.

### F-6 — `piwigo:register:ineffective_ephemeral_key` (removed)

Live testing showed `register_user()` checks the `$errors` array
passed in by reference, and the pre-existing `register_page_error`
is enough to bail out before the INSERT. Retired.

### Stored XSS via the search rules footer script (was F-1+nv4 chain)

PHP 8.2's `json_encode` escapes `/` to `\/` by default, defeating
the `</script>` break-out. The WS handler does not accept a free-form
string field for the rule. The capacity aspect of the endpoint is
`nv4`.

### F-2, F-3, F-5, nv7 (admin-only)

These findings require `is_admin()` or `check_status(ACCESS_ADMINISTRATOR)`
and are retained in the upstream audit deliverable for insider-threat
assessment only.

---

## F-1 — `upgrade_feed.php` runs DDL/DML on an anonymous GET

`upgrade_feed.php` is reachable as an unauthenticated GET endpoint. It
is gated only by `$conf['check_upgrade_feed']` (default `true`,
`include/config_default.inc.php:293`); it does not invoke
`check_upgrade_access_rights()` and does not require a `pwg_token`. On
every request the script connects to the application database, reads
the `id` column of `piwigo_upgrade`, scans `install/db/` for
`*-database.php` filenames, and `include()`s every script whose id is
missing from the table.

The published PoC exercises `install/db/145-database.php`, which
issues an unconditional `CREATE TABLE piwigo_image_format` (no
dblayer guard; reaches the `pwg_query()` on mysqli installs). The
test setup is:

1. `DROP TABLE piwigo_image_format` — recreates the pre-145 schema state.
2. `DELETE FROM piwigo_upgrade WHERE id='145'` — marks 145 as not yet applied.

Then a single anonymous GET:

```
GET http://localhost:8089/upgrade_feed.php
  → HTTP 200
  → body: <pre>1 upgrades to apply\n\n=== upgrade 145\n\nadd image formats table\n</pre>
  → piwigo_image_format is created with the schema from 145-database.php
  → piwigo_upgrade.id=145 has applied=NOW() and the upgrade description
```

The curl `-v` trace shows no Cookie / no Authorization / no pwg_token.
The same anonymous-trigger model applies to every other script in
`install/db/` — 117 scripts total.

The desync that triggers F-1 is a routine outcome of:

- a `git pull`/deploy that updates `install/db/*.php` without running
  the schema migration;
- a backup-restore cycle that omits `piwigo_upgrade`;
- an `admin/upgrade.php` upgrade run that is interrupted (browser
  close, Apache reload, mysqld restart, network blip) before the
  `INSERT INTO piwigo_upgrade` line is reached;
- a successful exploit of `GHSA-6wj3-7fhw-gfpm` / CVE-2026-44642, which
  lets an unauthenticated attacker DELETE rows from `piwigo_upgrade`.

F-1 and the GHSA are neighbours in the upgrade-authentication flow;
they should be patched together.

---

## nv3 — `picture.php` GET mutations are CSRF on any authed user

`picture.php` exposes state-changing actions through GET parameters.
Several of them — `add_to_favorites` (`:252-264`),
`remove_from_favorites` (`:266-285`), `add_to_caddie` (`:306-310`),
`rate` (`:312-316`) — call into the database directly without
invoking `check_pwg_token()`. Peer actions such as `delete_comment`
(`:366-381`) and `validate_comment` (`:383-398`) **do** call
`check_pwg_token()` and are blocked without it.

The PoC logs in as a victim with `status=normal` (the default Piwigo
user class — not admin, not webmaster), then issues two single GET
requests without any token:

```
GET http://localhost:8089/picture.php?/1/category/1&action=add_to_favorites
GET http://localhost:8089/picture.php?/1/category/1&action=add_to_caddie
```

Both return `302` redirect. After the requests the DB shows the rows
inserted for the victim. The peer contrast (also in the PoC) logs in
as `pocadmin2` (admin role; required because
`user_can_delete_comment=false` blocks normal users from deleting
their own comments) and verifies:

- `delete_comment&comment_to_delete=<id>` without `pwg_token` →
  HTTP 400, comment row preserved;
- the same request with the correct `pwg_token` (computed as
  `hash_hmac('md5', $pwg_id, $secret_key)` per
  `include/functions.inc.php:2201-2206`) → HTTP 302 redirect, comment
  row deleted.

A real-world attack requires only that the victim click a link like
`<img src="http://target/picture.php?/1/category/1&action=add_to_favorites">`
while logged in. The session cookie is sent automatically; the token
is not required.

---

## nv4 — Anonymous unbounded `pwg.images.filteredSearch.create`

`ws_images_filteredSearch_create`
(`include/ws_functions/pwg.images.php:753-1089`) accepts the
search-rule parameters, calls `save_search()`
(`include/functions_search.inc.php:2106-…`), and unconditionally
`INSERT`s into `piwigo_search`. There is no authentication gate, no
`pwg_token` check, no rate limit, and no duplicate detection.

The PoC sends `N=10` anonymous POSTs (`N` is configurable), each with a
unique `allwords` value and **no Cookie / no Authorization / no token
header**, then reads the row count back from the DB. The delta equals
`N`. Each response carries a unique `search_id`.

Impact: capacity / DoS. A single attacker, or a small botnet, can
grow `piwigo_search` arbitrarily. The table is queried on every
gallery page load via the saved-search sidebar; growth translates
directly into read amplification. `piwigo_search.rules` is a
serialized PHP array, so row size grows with rule complexity.

---

## nv5 — Anonymous `pwg.images.rate` triggers a full-table-scan + mass-update

`ws_images_rate` (`include/ws_functions/pwg.images.php:622-652`) does
not require authentication (gated only by image accessibility via
F&F). The handler delegates to `rate_picture()`, which on success
calls `update_rating_score()`
(`include/functions_rate.inc.php:123-…`). That function unconditionally
issues:

```sql
SELECT element_id, COUNT(rate) AS rcount, SUM(rate) AS rsum
  FROM piwigo_rate
  GROUP BY element_id;
```

followed by `mass_updates(IMAGES_TABLE, …)` over every image that has
at least one rate, plus a second SELECT to null-out `rating_score` on
images whose rate count went to zero. The whole computation is O(R)
per request, where R is the total `piwigo_rate` row count.

Per **CNA Rules §4.1.5 (Resource Exhaustion)**, this is a
product-side resource control defect, not a brute-force DoS: the cost
per request is O(R) where R is monotonically attacker-growable (every
successful rate call INSERTs one row).

The PoC:

1. Sets `rate=true` (test setup; documented admin config change).
2. Truncates `piwigo_rate` and times `N=5` anonymous rate POSTs as
   baseline.
3. Seeds `piwigo_rate` with `100_000` synthetic rows.
4. Times the same `N=5` POSTs as measured.
5. Runs `EXPLAIN` against the GROUP BY query.

Live result:

```
baseline avg: 0.0120s  (sum 0.0600s, N=5)
measured avg: 0.0300s  (sum 0.1500s, N=5)   ← 1.5× amplification at N=100k
EXPLAIN: type=ALL, key=NULL, rows=100001, Extra=Using temporary; Using filesort
```

The 1.5× ratio at N=100k is bounded by the buffer pool. The EXPLAIN is
the decisive proof: `type=ALL` and `Using temporary; Using filesort`
mean every call scans and sorts the entire table, regardless of which
image was rated. At larger R, the per-call cost scales linearly.

`$conf['rate_anonymous']` is conventionally `true` when `$conf['rate']`
is true (Piwigo code assumes this). Neither is declared in
`config_default.inc.php` — both default to NULL/false. The trigger
condition is a one-click admin config change; the defect is the
unconditional O(R) pattern in the source code.

---

## Inertness

The repository's master `README.md` (the one rule that shapes every
PoC in this repository) is satisfied here:

- **No reverse shell, no data exfiltration, no persistence.** The PoCs
  create one or two rows with names beginning `piwigo-poc-`,
  `anon_poc_`, `seed_`, `csrf_`, or `contrast_` and either clean up
  on exit (F-1) or leave them in the fixture for the operator to
  inspect (nv3, nv4, nv5).
- **No bundling of gadget chains.** No gadgets, no PoCs that require a
  second-order vulnerability.
- **No production target.** Each script targets `localhost:8089` and
  refuses to run unless the env explicitly points elsewhere.
- **The third-party targets that are referenced are themselves inert** —
  they are vendor-shipped code that behaves as documented; the PoC is
  observing that behaviour, not driving it.

---

## How to reproduce

The fixture is built from a clean Piwigo checkout inside a disposable
Docker container. See `env/BUILD.md` for the recipe.

```bash
# F-1 (creates piwigo_image_format via anonymous GET)
bash poc/piwigo-upgrade-feed-anon-db-mutation.sh

# nv3 (logs in as a normal-status victim, issues 2 tokenless GETs)
bash poc/piwigo-picture-csrf-add-to-favorites.sh

# nv4 (N=10 anonymous POSTs growing piwigo_search)
bash poc/piwigo-ws-filtered-search-unbounded.sh

# nv5 (sets rate=true, seeds 100k rows, measures timing + EXPLAIN)
bash poc/piwigo-ws-images-rate-db-amplification.sh
```

Each script writes its captured response bodies, DB state, and
assertion summary to `evidence/<finding>/` verbatim. There is no
persistent state after the script exits; `piwigo_search`,
`piwigo_rate`, and `piwigo_image_format` are verified clean by the
final DB state capture.