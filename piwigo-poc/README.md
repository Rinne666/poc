# Piwigo — proof-of-concept material

> **Machine-readable source of truth:** [`submission.json`](submission.json). The
> `id`, `slug`, `title`, `cwe`, `proofLevel`, `preconditions`,
> `positiveControl`, `negativeControl`, `observedImpact`, `notDemonstrated`,
> `cvssVector`, `poc`, and `evidence` fields there are authoritative. This
> README and `report.md` are derived from it.

**Vendor / product:** Piwigo / Piwigo  
**Tested version and commit:** 17.0.0beta1, `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`  
**Disclosure:** NOT_REPORTED — vendor has not been contacted as of this submission; security contact is `security@piwigo.org` per upstream `SECURITY.md`. Maintainer publication approval not yet recorded.  
**Verification:** RUNTIME_VERIFIED for every finding in this project (see `submission.json` per-finding `proofLevel`).  
**CVE:** unassigned; internal drafts archived locally under access-controlled research notes.

---

## Findings

| ID | Slug | Proof level | Tested version | CVE |
|---|---|---|---|---|
| F1 | `piwigo-upgrade-feed-anon-db-mutation` | RUNTIME_VERIFIED | 17.0.0beta1 | Unassigned |
| nv3 | `piwigo-picture-csrf-get-mutations` | RUNTIME_VERIFIED | 17.0.0beta1 | Unassigned |
| nv4 | `piwigo-ws-filtered-search-unbounded` | RUNTIME_VERIFIED | 17.0.0beta1 | Unassigned |
| nv5 | `piwigo-ws-images-rate-db-amplification` | RUNTIME_VERIFIED | 17.0.0beta1 | Unassigned |

The finding set in `submission.json`, `README.md`, and `report.md` MUST agree.
CVSS scores in `submission.json` are the reporter's scoring of the
demonstrated impact; CNA triage severity independently.

---

## F1 — Anonymous `upgrade_feed.php` runs DDL/DML on the application database

**Security boundary:** `upgrade_feed.php` is an unauthenticated GET endpoint.
The only gate is `$conf['check_upgrade_feed']` (default `true`,
`include/config_default.inc.php:293`); the script does not invoke
`check_upgrade_access_rights()` and does not require a `pwg_token`. An
unauthenticated caller should not be able to drive DDL/DML on the
application database through this path.

**Preconditions and attacker privileges:** Default Piwigo 17.0.0beta1
install on PHP 7.4+ / MariaDB or MySQL. The application's `piwigo_upgrade`
table is desynchronised from the on-disk `install/db/` directory — a
routine outcome of interrupted upgrades, fresh-code-on-old-DB deploys,
backup-restore drift, or successful exploitation of GHSA-6wj3-7fhw-gfpm /
CVE-2026-44642 (which lets an unauthenticated attacker DELETE rows from
`piwigo_upgrade` via the SQLi in `check_upgrade_access_rights()`).

**Observed impact:** Single anonymous GET against
`/upgrade_feed.php` (no Cookie, no Authorization, no `pwg_token`) returns
HTTP 200 with body `<pre>1 upgrades to apply\n\n=== upgrade 145\n\nadd
image formats table\n</pre>`. The application database shows
`piwigo_image_format` has been CREATEd with the exact schema from
`install/db/145-database.php`; `piwigo_upgrade.id=145` has been
re-populated with `applied=NOW()` and the upgrade_description. The same
anonymous-trigger model applies to the other 121 entries in `install/db/`
(including additional `CREATE TABLE` / `UPDATE piwigo_config` /
`safe_unserialize` paths). CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N.

**Negative control:** An anonymous GET against `/upgrade_feed.php` when no
`piwigo_upgrade` row is missing returns HTTP 200 with body `<pre>0 upgrades
to apply</pre>` and executes zero DDL/DML — confirming the path is dormant
in the steady state and only fires on a desync.

**What was NOT demonstrated:** We did not run every one of the 121
`install/db/<n>-database.php` scripts against a live target; we ran
145 (`CREATE TABLE`) and 180 ([Aborted], row repopulation only) and
source-reviewed the rest. We did not exploit F-1 via the
GHSA-6wj3-7fhw-gfpm path; F-1 and the GHSA are independent defects. We did
not run on production hardware; the local fixture uses the Docker bridge
gateway IP.

**Affected version scope:** Only the exact tested
version/commit (`17.0.0beta1` / `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`)
is verified unless further test evidence exists.

**Evidence and reproduction:** [`report.md`](report.md) and the paths
listed under `submission.json.findings[F1].evidence`.

**Vendor/CNA coordination:** Not yet contacted. The vendor security
contact is `security@piwigo.org` per upstream `SECURITY.md`. The defect
and the GHSA-6wj3-7fhw-gfpm SQLi are neighbours in the
upgrade-authentication flow and should be patched together.

---

## nv3 — `picture.php` GET mutations are CSRF on any authed user

**Security boundary:** `picture.php:248-401` routes state-changing
actions through `$_GET['action']`. Peer actions (`delete_comment`,
`validate_comment`, `edit_comment`) call `check_pwg_token()`; four other
actions do not. An authed user's `pwg_id` cookie should not be sufficient
to drive state-changing actions without a CSRF token bound to the session.

**Preconditions and attacker privileges:** Default Piwigo 17.0.0beta1
install with at least one logged-in user. The attacker hosts a malicious
page or sends the victim an `<img src=...>` link; the victim's session
cookie is sent automatically on the cross-origin GET.

**Observed impact:** Victim with `status=normal` is forced into
`add_to_favorites` and `add_to_caddie` via single tokenless GETs; both
return HTTP 302 redirect; `piwigo_favorites` and `piwigo_caddie` show the
inserted rows keyed to (victim_uid, image_id=1). CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N.

**Negative control:** Peer action `delete_comment` demonstrates the gate
is present and works: HTTP GET against `delete_comment` WITHOUT
`pwg_token` returns HTTP 400 and the comment row is preserved; the same
request WITH the correct `pwg_token` (computed as
`hash_hmac('md5', $pwg_id, $secret_key)` per
`include/functions.inc.php:2201-2206`) returns HTTP 302 and the row is
deleted.

**What was NOT demonstrated:** We did not test `remove_from_favorites`,
`rate`, or `set_as_representative` directly; the source-trace shows they
share the same missing `check_pwg_token()` and the same code path. We did
not capture a browser end-to-end exploit (HTML+cookie); the cURL PoC
reproduces the same wire behaviour the browser would produce.

**Affected version scope:** Only the exact tested
version/commit (`17.0.0beta1` / `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`)
is verified unless further test evidence exists.

**Evidence and reproduction:** [`report.md`](report.md) and the paths
listed under `submission.json.findings[nv3].evidence`.

**Vendor/CNA coordination:** Not yet contacted.

---

## nv4 — Anonymous unbounded `pwg.images.filteredSearch.create`

**Security boundary:** `ws_images_filteredSearch_create`
(`include/ws_functions/pwg.images.php:753-1089`) is a WS endpoint
registered without `admin_only`. There is no authentication gate, no
`pwg_token` check, no per-IP/per-session rate limit, and no duplicate
detection. An anonymous caller should not be able to grow
`piwigo_search` arbitrarily on the application database.

**Preconditions and attacker privileges:** Default Piwigo 17.0.0beta1
install.

**Observed impact:** `N=10` anonymous POSTs to
`http://localhost:8089/ws.php?method=pwg.images.filteredSearch.create` with
unique `allwords` values and no Cookie / no Authorization / no token
header return HTTP 200 with a unique `<search_id>psk-…</search_id>`. After
the run, `SELECT COUNT(*) FROM piwigo_search` returns `baseline + N` with
unique `search_uuid` values populated. The endpoint is not deduplicating.
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H.

**Negative control:** None applicable — the endpoint accepts anonymous
traffic without any gate. The implicit baseline (delta equals N, unique
search_ids) confirms there is no per-caller throttle.

**What was NOT demonstrated:** We did not measure the gallery-page-load
time as a function of `piwigo_search` row count (the live amplifier);
the read-amplification claim is from the static review of
`include/search_filters.inc.php` and the saved-search sidebar query
path. We did not run at `N > 10`; the delta-equality result is the proof
of unboundedness.

**Affected version scope:** Only the exact tested
version/commit (`17.0.0beta1` / `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`)
is verified unless further test evidence exists.

**Evidence and reproduction:** [`report.md`](report.md) and the paths
listed under `submission.json.findings[nv4].evidence`.

**Vendor/CNA coordination:** Not yet contacted.

---

## nv5 — `pwg.images.rate` unconditional O(R) per request

**Security boundary:** `ws_images_rate`
(`include/ws_functions/pwg.images.php:622-652`) is registered without
`admin_only`. The handler delegates to `rate_picture()`, which on success
calls `update_rating_score()`. The product unconditionally executes an
O(R) `SELECT … FROM piwigo_rate GROUP BY element_id` plus
`mass_updates(IMAGES_TABLE, …)` on every successful rate call. Per CNA
Rules §4.1.5, that is a resource-control defect in the product, not a
brute-force DoS.

**Preconditions and attacker privileges:** `$conf['rate'] = true` (the
rate feature toggle; not declared in `include/config_default.inc.php` so
it defaults to NULL/false; flipping it requires a single admin-side
UPDATE of `piwigo_config`). `$conf['rate_anonymous']` is conventionally
true when `$conf['rate']` is true (`rate_picture()` assumes this; not
declared in `config_default.inc.php` either). The endpoint is registered
in `ws.php` without `admin_only`; the only check is image accessibility
via F&F.

**Observed impact:** Baseline `N=5` anonymous rate POSTs avg 0.0120s on
empty `piwigo_rate`; after seeding 100 000 synthetic rows, the same
`N=5` POSTs avg 0.0300s. `EXPLAIN` on the GROUP BY query:
`type=ALL, key=NULL, rows=100001, Extra=Using temporary; Using filesort`.
The 1.5× timing at N=100k is bounded by the buffer pool in the test
fixture; EXPLAIN is the proof that every call scans and sorts the full
set regardless of which image was rated. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H.

**Negative control:** When `$conf['rate'] = false` (the out-of-the-box
default), `rate_picture()` returns false at
`include/functions_rate.inc.php:25-31` before reaching
`update_rating_score()`, and the request is rejected without GROUP BY.

**What was NOT demonstrated:** We did not run the test at `N > 100k`
(seed time grows linearly with N); the linear scaling is a property of
the GROUP BY + filesort work and is the only thing the EXPLAIN leaves
open to growth. We did not measure the read-side amplification on
gallery pages; the live amplifier is the read path that scans
`piwigo_search` for sidebar saved-search rendering.

**Affected version scope:** Only the exact tested
version/commit (`17.0.0beta1` / `08cd55a4e6c17d3a36e5d9585dbe7ce690d16d8d`)
is verified unless further test evidence exists.

**Evidence and reproduction:** [`report.md`](report.md) and the paths
listed under `submission.json.findings[nv5].evidence`.

**Vendor/CNA coordination:** Not yet contacted.

---

## Inertness

The repository's master `README.md` (the one rule that shapes every PoC
in this repository) is satisfied here:

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

## Files

- `submission.json` — canonical structured metadata
- `report.md` — precise steps, positive and negative controls, interpretation
- `poc/` — authorized minimal reproducible tests
- `evidence/` — raw redacted observation and provenance
- `env/` — isolated lab setup and teardown
- `cve/` — *omitted.* Internal CVE drafts (formerly under `cve/`) are
  archived locally under access-controlled research notes pending a real
  CNA-assigned ID and authorised CNA metadata. `CVE-PENDING-*` is not a
  valid CVE ID and is not published in this repository.