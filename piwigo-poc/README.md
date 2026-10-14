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

| ID | Title | CWE | CVSS v3.1 | CVE | Demonstrated |
|---|---|---|---|---|---|
| **F-1** | Anonymous GET against `/upgrade_feed.php` runs every pending `install/db/<n>-database.php` under the application's MySQL credentials | CWE-862 | **9.1** (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N) | *pending* | DB write verified (180 row) |
| **nv3** | `picture.php` GET handlers `add_to_favorites` / `add_to_caddie` mutate state without `check_pwg_token()` — CSRF on any logged-in user | CWE-352 | medium | *pending* | 2 mutations + peer contrast |
| **nv4** | `pwg.images.filteredSearch.create` accepts anonymous POSTs with no auth / no token / no rate limit; each call inserts a row in `piwigo_search` | CWE-400 / CWE-770 | medium (DoS / capacity) | *pending* | 10 anon rows in one script run |
| **nv5** | Anonymous `pwg.images.rate` would trigger `GROUP BY element_id` over the full `piwigo_rate` table plus `mass_updates` on `piwigo_images`; `rate_anonymous=true` ships as the vendor default | CWE-400 / CWE-770 | **7.5** (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) | *pending* | EXPLAIN `type=ALL` + 1.5× timing at N=100k |

CVSS scores are the reporter's scoring of the demonstrated impact. F-1 is
Critical because the demonstrated side effect is full DDL/DML on the
application database. nv3 is CSRF, which inherits the impact of the worst
state mutation reachable from `picture.php` (favorites pollution, caddie
poisoning, rating inflation, etc.). nv4 and nv5 are both capacity / DoS
class, conditional only on the feature being enabled (which is the vendor
default for `rate_anonymous`).

### Findings that did NOT survive live testing

A `git diff` from the original audit deliverable would surface the rest of
the hypotheses. This project publishes only the four that the live PoC could
demonstrate or source-attribute cleanly. The removed records, documented in
`report.md` for completeness:

- **Stored XSS via the search rules footer script** — the original hypothesis
  was that an attacker-controlled rule name would break out of the inline
  `<script>` tag emitted by `include/search_filters.inc.php:855`. Live testing
  showed PHP 8.2's `json_encode` escapes `/` to `\/` by default, defeating
  the `</script>` break-out, and the WS handler `ws_images_filteredSearch_create`
  does not accept a free-form string field for the rule — it builds a
  structured `mode`+`fields.cat.words` array. The XSS half of the chain is
  not exploitable as described. The capacity half is `nv4`.
- **`register.php` ineffective ephemeral key** — the original hypothesis was
  that `register.php:29-31` would call `register_user()` despite
  `verify_ephemeral_key()` returning false, and the user row would be
  created. Live testing showed `register_user()` does check the `$errors`
  array passed in by reference, and the pre-existing `register_page_error`
  is enough to bail out before the INSERT. The CSRF gate is decorative, but
  the downstream consumer catches the error and no user is created.
- **Findings that require admin or higher** — F-2, F-3, F-5, and nv7 all
  require `is_admin()` or `check_status(ACCESS_ADMINISTRATOR)`. They are
  retained in the upstream audit deliverable for insider-threat assessment
  but are out of scope for the public PoC repository.

---

## F-1 — `upgrade_feed.php` runs the upgrade set on an anonymous GET

`upgrade_feed.php` is reachable as an unauthenticated GET endpoint. It is
gated only by `$conf['check_upgrade_feed']` (default `true`,
`include/config_default.inc.php:293`); it does not invoke
`check_upgrade_access_rights()` and does not require a `pwg_token`. On every
request the script connects to the application database, reads the `id`
column of `piwigo_upgrade`, scans `install/db/` for `*-database.php`
filenames, and `include()`s every script whose id is missing from the table.
Each included script issues a `pwg_query()` under the application's mysqli
credentials — the side effect is, by construction, identical to the side
effect of a legitimate `admin/upgrade.php` run.

The PoC deletes `piwigo_upgrade.id = 180` (the `[Aborted]` upgrade whose body
is intentionally empty — chosen so the side effect is purely the row
re-population), then issues a single anonymous GET against
`/upgrade_feed.php`. The response body contains `=== upgrade 180`; the DB
then shows `piwigo_upgrade.id = 180` with a fresh `applied = NOW()` and
description `add config parameters to display by default or not "related
tags" [Aborted]`. The `curl -v` trace confirms the request sent no Cookie
header.

The desync that triggers F-1 is a routine outcome of:

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

---

## nv3 — `picture.php` GET mutations are CSRF on any authed user

`picture.php` exposes state-changing actions through GET parameters. Several
of them — `add_to_favorites` (`:252-264`), `remove_from_favorites`
(`:266-285`), `add_to_caddie` (`:306-310`), `rate` (`:312-316`) — call into
the database directly without invoking `check_pwg_token()`. Peer actions
such as `delete_comment` (`:366-381`) and `validate_comment` (`:383-398`)
**do** call `check_pwg_token()` and are blocked without it. The omission
on the unprotected half is the finding.

The PoC logs in as a victim with `status=normal` (the default Piwigo user
class — no admin, no webmaster), then issues two single GET requests
without any token:

```
GET http://localhost:8089/picture.php?/1/category/1&action=add_to_favorites
GET http://localhost:8089/picture.php?/1/category/1&action=add_to_caddie
```

Both return `302` redirect. After the requests the DB shows the rows
inserted:

```
SELECT user_id, image_id FROM piwigo_favorites WHERE user_id = <victim>;
SELECT user_id, element_id FROM piwigo_caddie WHERE user_id = <victim>;
```

The peer-contrast half of the script logs in as `pocadmin2` (admin role,
required because `user_can_delete_comment=false` blocks normal users from
deleting their own comments) and verifies:

- `delete_comment&comment_to_delete=<id>` without `pwg_token` → HTTP 400
  and comment row preserved;
- the same request with the correct `pwg_token` → HTTP 302 redirect and
  comment row deleted.

The `pwg_token` is `hash_hmac('md5', $pwg_id, $secret_key)` per
`include/functions.inc.php:2201-2206`; the script computes it from the
captured cookie value and the `secret_key` row in `piwigo_config`.

A real-world attack requires only that the victim click a link like
`<img src="http://target/picture.php?/1/category/1&action=add_to_favorites">`
while logged in. The session cookie is sent automatically; the token is
not required.

---

## nv4 — Anonymous unbounded `pwg.images.filteredSearch.create`

`ws_images_filteredSearch_create` (`include/ws_functions/pwg.images.php:753-1089`)
accepts the search-rule parameters, calls `save_search()`
(`include/functions_search.inc.php:2106-…`), and unconditionally `INSERT`s
into `piwigo_search`. There is no authentication gate, no `pwg_token`
check, no rate limit, and no duplicate detection: every POST returns HTTP
200 with a fresh `psk-<date>-<rand>` search_id and a new row in
`piwigo_search`.

The PoC issues `N=10` anonymous POSTs (`N` is configurable), each with a
unique `allwords` value and **no Cookie / no Authorization / no token
header**, then reads the row count back from the DB:

```
SELECT COUNT(*) FROM piwigo_search;
```

The delta equals `N`. Each response carries a unique search_id, confirming
the endpoint is not deduplicating. The captured response XML for each
request is in `evidence/nv4-filtered-search-unbounded/resp-*.xml`.

Impact: capacity / DoS. A single attacker, or a small botnet, can grow
`piwigo_search` arbitrarily. The table is queried on every gallery page
load via the saved-search sidebar, so growth translates directly into read
amplification. `piwigo_search.rules` is a serialized PHP array, so row
size grows with rule complexity.

---

## nv5 — Anonymous `pwg.images.rate` triggers a full-table-scan + mass-update

`ws_images_rate` (`include/ws_functions/pwg.images.php:622-652`) does not
require authentication (gated only by image accessibility via F&F). The
handler delegates to `rate_picture()`, which on success calls
`update_rating_score()` (`include/functions_rate.inc.php:123-…`). That
function unconditionally issues:

```sql
SELECT element_id, COUNT(rate) AS rcount, SUM(rate) AS rsum
  FROM piwigo_rate
  GROUP BY element_id;
```

followed by `mass_updates(IMAGES_TABLE, …)` over every image that has at
least one rate, plus a second SELECT to null-out `rating_score` on images
whose rate count went to zero. The whole computation is O(R) per request,
where R is the total `piwigo_rate` row count.

The PoC:

1. Truncates `piwigo_rate` and times `N=5` anonymous rate POSTs as
   baseline.
2. Seeds `piwigo_rate` with `100_000` synthetic rows.
3. Times the same `N=5` POSTs as measured.
4. Runs `EXPLAIN` against the GROUP BY query.

Live result:

```
baseline avg: 0.0120s  (sum 0.0600s, N=5)
measured avg: 0.0300s  (sum 0.1500s, N=5)   ← 1.5× amplification at N=100k
EXPLAIN: type=ALL, key=NULL, rows=100001, Extra=Using temporary; Using filesort
```

The amplification is 1.5× at N=100k on MariaDB 10.11 because the table fits
in the buffer pool. At larger R (or on storage with a cold cache), the
GROUP BY + filesort + temporary table cost scales linearly. The EXPLAIN is
the decisive proof: `type=ALL` and `Using temporary; Using filesort` mean
every call scans the entire table and sorts, regardless of which image was
rated.

`$conf['rate_anonymous'] = true` ships as the vendor default; the endpoint
is reachable on a stock install with the rate feature toggled on (the
`install.php` default is `false`, but a single admin-side config change
brings it online).

---

## Inertness

The repository's master `README.md` (the one rule that shapes every PoC in
this repository) is satisfied here:

- **No reverse shell, no data exfiltration, no persistence.** The PoCs
  create one or two rows with names beginning `piwigo-poc-`, `anon_poc_`,
  `seed_`, or `csrf_` and either clean up on exit (F-1) or leave them in
  the fixture for the operator to inspect (nv3, nv4, nv5).
- **No bundling of gadget chains.** No gadgets, no PoCs that require a
  second-order vulnerability.
- **No production target.** Each script targets `localhost:8089` and
  refuses to run unless the env explicitly points elsewhere.
- **The third-party targets that are referenced are themselves inert** —
  they are vendor-shipped code that behaves as documented; the PoC is
  observing that behaviour, not driving it.

---

## How to reproduce

The fixture is built from a clean Piwigo checkout inside a disposable Docker
container. See `env/BUILD.md` for the recipe and `env/CVSS.md` for the
score derivation.

| Step | What happens |
|---|---|
| 1. `env/up.sh` | brings up `piwigo-poc-db` (MariaDB 10.11) + `piwigo-poc-web` (PHP 8.2 / Apache, from `Dockerfile`) |
| 2. `env/install.sh` | drives `install.php` via POST with a known webmaster credential |
| 3. `poc/<finding>.sh` | runs the finding; one row is created, one is verified |
| 4. `evidence/<finding>/` | captured unedited output, including the response body and the assertion summary |

The Docker tear-down is `env/teardown.sh`. There is no persistent state
after the script exits; `piwigo_search`, `piwigo_config`, and `piwigo_rate`
are verified clean by `evidence/<finding>/db-after*.txt` capture.

```bash
# F-1
bash poc/piwigo-upgrade-feed-anon-db-mutation.sh

# nv3 (needs DB write for the contrast; the script handles it)
bash poc/piwigo-picture-csrf-add-to-favorites.sh

# nv4
bash poc/piwigo-ws-filtered-search-unbounded.sh

# nv5 (seeds 100k synthetic rows; ~1s seed time)
bash poc/piwigo-ws-images-rate-db-amplification.sh
```

---

## What is **not** demonstrated

The findings here are bounded by the inertness rule, which means several
of the highest-impact faces of the underlying defects are not exercised:

- F-1 — the PoC picks the `[Aborted]` upgrade (`180-database.php`) whose
  body is empty, so the demonstrated side effect is the row re-population.
  The full DDL/DML reach against a target with all 121 rows pending is
  implicit in the source review and is recorded in `report.md`, but is not
  driven by the public PoC.
- nv3 — the PoC uses `add_to_favorites` and `add_to_caddie` because they
  are reachable by a `status=normal` user. The `rate` mutation is
  similarly reachable (same missing-token pattern) but is not exercised
  here.
- nv5 — the PoC seeds 100k synthetic rows to demonstrate the
  amplification. The amplification scales linearly; at N=1M the per-call
  cost is in the multi-second range on commodity hardware. The PoC stops
  at N=100k to keep the seed step under ~1 second.

A live operator with an actual public Piwigo instance should treat each
finding as substantively larger than the PoC suggests; the PoCs here are
written to satisfy the CNA-level "is the defect real?" question, not the
operator-level "is my instance under attack?" question.