# krayin/laravel-crm — proof-of-concept material

**Target** `krayin/laravel-crm` — open-source Laravel CRM (admin panel, leads, contacts, activities, mail, web forms, data transfer)
**Version tested** 2.2 line (master)
**Commit tested** `ed6deebfcb8c616eaf352c893a10a6d8e666fc6e` (clean worktree)
**Disclosure state** **not yet reported to the vendor or any CNA.** The vendor's `SECURITY.md` declares a private reporting channel (support@webkul.com). Eight findings are staged for VulDB submission; the seven findings below are the ones this repository publishes PoC material for. The `evidence/` files carry the adjudication-era identifiers (E0000xx) and the per-finding runtime verdict logs.

> **If you run krayin/laravel-crm, treat all seven findings as live.** No fix has shipped for any of them at the tested commit. The most urgent operator actions: restrict ACL role design until V2 is fixed (any view-only key may authorize unmapped destructive routes), audit who holds `data_transfer.imports.import` (V3), and assume any file uploaded through activities is world-readable (V6).

All findings were reproduced at runtime against a locally built Docker instance of the exact commit above (PHP 8.3.35 + MySQL 8.0, scratch install). Every payload is an inert dummy marker; every fixture row created for a test was deleted afterwards. No real user data was touched.

---

## Findings

| ID | Title | CWE | CVSS v3.1 | CVE |
|---|---|---|---|---|
| V1 | Inbound mail HTML reaches the forward/reply editor initial content without the sanitizer every sibling render sink applies | CWE-79 | **9.3** (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N) | *pending* |
| V2 | `acl.php` leaves destructive attribute routes unmapped and the Bouncer dotted-prefix ancestor fallback authorizes them, while exact-mapped sibling deletes stay permission-gated | CWE-862 | **9.9** (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) | *pending* |
| V3 | The data-transfer import delete path resolves row targets without the authorized-user scope the interactive delete route enforces | CWE-863 | **8.1** (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H) | *pending* |
| V4 | The lead person-attach path persists person ids without re-asserting the actor's authorized-user scope, while the direct person read path enforces it | CWE-639 | **7.1** (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N) | *pending* |
| V5 | The export writer returns stored cell values verbatim while the JSON datagrid path strips them (CSV/XLSX formula injection) | CWE-1236 | **8.7** (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N) | *pending* |
| V6 | The activity file upload path stores payloads of any type and size on the public disk, while mail attachments land on a private disk behind an authenticated download route | CWE-434 | **7.1** (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N) | *pending* |
| V7 | The layout renders the stored `custom_scripts` value outside the escaping every neighbouring template value goes through | CWE-79 | **8.7** (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N) | *pending* |

The CVSS scores are the reporter's own scoring of the demonstrated conditions. V1's score reflects the filter-survivor delivery into the authenticated editor surface; end-to-end editor-iframe execution was not demonstrated in a browser harness (see per-finding scope notes). V7 is the one finding where browser execution was confirmed (benign marker payload changing the login page title in real Chromium).

---

## V1 — mail forward editor renders unsanitized inbound HTML

**An external mail sender's markup survives the sole filter on the forward/reply editor initial content, where every automatic render sink on the same data applies DOMPurify/strip_tags.**

**Affected code**

- `packages/Webkul/Email/src/InboundEmailProcessor/SendgridEmailProcessor.php:121` — stores the reply behind `HtmlFilter::process` only (blacklist, body-scoped)
- `packages/Webkul/Admin/src/Resources/views/emails/view.blade.php:1222` — serializes the raw Email model with `@json($email)`; forward computed returns `action.email.reply` (:1373)
- `packages/Webkul/Admin/src/Resources/views/components/tinymce/index.blade.php:86` — `tinymce.init` with no `valid_elements`/sanitize hook
- Contrast: `view.blade.php:246` uses `v-safe-html` for the automatic sink; `DataGrid.php:472` uses `strip_tags`

**Preconditions**

1. Inbound mail with attacker-chosen HTML body — true for any deployment with mail ingestion configured.
2. An agent opens the forward/reply editor for that mail.

**Steps and observed result** — full steps in `report.md`; verbatim capture in `evidence/`. On the deployed runtime, `HtmlFilter::process` (the same call ingestion makes) passed through verbatim: `data:text/html` URIs in `href` and `form action`, and the SMIL construct `<svg><a href="#"><animate attributeName="href" values="javascript:…">` (attribute-name lowercasing only). Controls behaved: `on*` attributes stripped, `<script>`/`<iframe>` removed, `javascript:` URIs rewritten to `#`. The stored reply carrying the survivors was captured verbatim in the live authenticated page DOM as the editor's data source (`email.reply` serialized via `@json`).

**What was NOT demonstrated**

- End-to-end click execution inside the TinyMCE 6.6.2 editor iframe. The thread pane renders only with ingestion-pipeline-complete fixtures, so the composer did not mount for the hand-crafted row in the lab. The missing second sanitizer layer and the filter's survivor set are runtime-confirmed; actual execution remains the library/browser fact.

**Impact**

An external sender can seed script-class markup that reaches an authenticated staff session's editor surface (agents handle customer mail routinely). Session scope = CRM data access.

**Remediation**

1. Route the editor initial content through the same sanitizer as the other sinks (or render as text and let the editor parse on demand).
2. Replace the blacklist-only filter with a real allowlist sanitizer.

---

## V2 — Bouncer dotted-ancestor walk authorizes unmapped destructive routes

**A role holding only a view ACL key can invoke destructive admin routes that `acl.php` never maps, because the authorization fallback walks the dotted-prefix ancestors — while the exact-mapped sibling delete of the same resource is refused.**

**Affected code**

- `packages/Webkul/Admin/src/Routes/Admin/settings-routes.php:250` — attribute `mass-destroy` route (name `admin.settings.attributes.mass_delete`), absent from `acl.php`
- `packages/Webkul/Admin/src/Http/Controllers/Settings/AttributeController.php:311` — mass-destroy handler (hard delete)
- `config/acl.php` (package) — mapping gap; every sibling delete key carries `mass_delete`, this one does not

**Preconditions**

1. Actor's role grants only a view/ancestor key such as `settings.automation.attributes` (no write keys). Restricted roles are a supported configuration, not a misconfiguration.
2. `acl.php` has no mapping for the write route — true by default at the tested commit.

**Steps and observed result** — full steps in `report.md`. A view-only role issued `POST /admin/settings/attributes/mass-destroy` with two admin-created attribute ids: HTTP 200, both definitions hard-deleted, and the `attribute_values` FK (`DELETE_RULE=CASCADE`, confirmed via information_schema) destroyed all stored values of the deleted attributes. The identical session received HTTP 401 for the exact-mapped `DELETE /admin/settings/attributes/<id>` — proving the walk grants the unmapped destructive route to a principal the mapped equivalent refuses. Reflection-level checks of `Bouncer::isAuthorizedByFeature` additionally confirmed cross-domain grants (`leads.view` → `admin.leads.attributes.update`, `admin.leads.emails.store`; `products.view` → `admin.products.inventories.store`, `admin.products.search`).

**What was NOT demonstrated**

- HTTP-level execution of the additional grants (inventory writes, quote send, lead attribute/email writes) — those were confirmed by reflection against the same authorization routine, not driven end-to-end. The attribute mass-destroy was driven end-to-end.
- Introducing commit not traced (no `git -S` archaeology performed).

**Impact**

One request by any restricted role cascade-deletes all stored values of arbitrary attribute definitions (permanent data loss) and, per the reflection checks, hands read-only roles cross-domain write/send capabilities. The fallback is on by default for every deployment.

**Remediation**

1. Add explicit `acl.php` mappings for every currently unmapped write route (attributes `mass_delete` above all).
2. Bound the dotted-prefix ancestor fallback so it cannot authorize state-changing verbs; add a regression test that walks `acl.php` against the route list.

---

## V3 — import delete path ignores the caller's record scope

**A restricted staff user with only the import ACL keys can hard-delete other users' CRM records through the bulk import pipeline, which the interactive delete route for the same records refuses.**

**Affected code**

- `packages/Webkul/Admin/src/Routes/Admin/settings-routes.php:376` — import start route
- `packages/Webkul/DataTransfer/src/Helpers/Importers/Persons/Importer.php:346` — delete-path row target resolution (no authorized-user predicate; the DataTransfer package has zero bouncer references)

**Preconditions**

1. Initiator holds the import ACL keys (`settings.automation.data_transfer.imports.create`, `.import`) with limited `view_permission` (individual) — a supported configuration.
2. Rows target records outside the initiator's authorized ids (ids enumerable).

**Steps and observed result** — full steps in `report.md`. Restricted user U2 (individual scope, authorized ids = self) created a persons import with `action=delete`, validated (2 rows, 0 errors) and started it: summary `deleted=2`. The admin-owned person (id 62, `user_id=1`, outside U2's authorized ids) was hard-deleted from `persons` (its `attribute_values` rows left orphaned), while the same user's interactive attempt on the same record returned 401 (`preventUnauthorizedAccess`) and the record did not appear in U2's datagrid.

**What was NOT demonstrated**

- Only the persons importer was driven end-to-end; the leads/products/quotes importers share the same unscoped resolution pattern but were not executed in this test.
- Introducing commit not traced.

**Impact**

Cross-scope hard deletion (and rewrite, for upsert actions) of CRM records by any import-ACL holder: permanent data loss entirely bypassing the permission model the UI enforces.

**Remediation**

1. Snapshot `authorized_user_ids` onto the import record at start and enforce the predicate in every delete/upsert target resolution across the importers.

---

## V4 — lead person-attach skips the contact-data scope check

**A staff user scoped to their own records can bind another user's person onto their own lead and read that person's email and phone from the lead view — while the direct person read path returns 401 for the same id.**

**Affected code**

- `packages/Webkul/Admin/src/Http/Controllers/Lead/LeadController.php:318` — attach/update path persists `person[id]` without re-asserting authorized-user scope
- `packages/Webkul/Admin/src/Resources/views/leads/view/person.blade.php:65` — renders the linked person's contact data

**Preconditions**

1. Actor holds lead-edit rights under individual/group `view_permission` (their own lead is editable).
2. A person outside the actor's bouncer authorized-user-ids exists (belongs to another user). Ids are enumerable.

**Steps and observed result** — full steps in `report.md`. Restricted user (individual scope, `leads.view`) issued `PUT /admin/leads/attributes/edit/<own-lead>` with `person[id]=<victim id>`: HTTP 200, link persisted. The subsequent lead view HTML and kanban JSON rendered the victim person's email address and contact number verbatim. Controls: direct `GET /admin/contacts/persons/view/<victim id>` → 401; same payload at another user's lead → 401.

**What was NOT demonstrated**

- Write access to the victim lead (this record demonstrates cross-scope read of contact PII only); attribute-file contents of the victim were not accessed.
- Introducing commit not traced.

**Impact**

Cross-tenant contact PII readout (email, phone) with a single authenticated request and an enumerable id; no preconditions beyond two accounts.

**Remediation**

1. Validate the submitted person id against `bouncer()->getAuthorizedUserIds()` for contacts.persons inside the lead attach/update handler before linking.

---

## V5 — datagrid export writes stored values into spreadsheet cells unescaped

**Stored cell values reach the CSV/XLSX export writer verbatim (no formula neutralization) while the JSON datagrid path strips them — attacker-chosen formulas survive into files staff open in spreadsheet software.**

**Affected code**

- `packages/Webkul/WebForm/src/Http/Controllers/WebFormController.php:232` — web-form submissions create records with attacker-chosen field values (anonymous origin)
- `packages/Webkul/DataGrid/src/Exports/DataGridExport.php:48` — `map()` returns `$record->{$index}` verbatim into the maatwebsite/excel + PhpSpreadsheet writer; the JSON path's `strip_tags` `sanitizeRow` is bypassed on the export branch

**Preconditions**

1. Any user able to create records with chosen field values — including anonymous public web-form submissions.
2. A staff member exports and opens the CSV/XLSX in spreadsheet software.

**Steps and observed result** — full steps in `report.md`. Persons seeded with names `=VERIFY(1)+1 <tag>` and `+VERIFY(2)+2 <tag>`; admin export `GET /admin/contacts/persons?export=1&format=csv` returned 200 `text/csv` whose raw bytes carry the leading `=` and `+` intact, with no quote-prefix or escape. The XLSX variant was additionally inspected: the `=`-prefixed stored value was typed as a real formula element — sheet1.xml cell `<c r="B3" t="str"><f>VERIFY(1)+1 VF7F-1794112781</f><v>0</v></c>` — and the writer attempts to evaluate it server-side during column-width calculation (a dummy formula can crash the export with a TypeError 500).

**What was NOT demonstrated**

- Execution of a formula on the analyst's machine (depends on the spreadsheet application's DDE/macro settings) — a client fact outside this repository. What is demonstrated: the raw bytes/formula element leave the server unneutralized.

**Impact**

An anonymous web-form submitter can seed spreadsheet formulas that staff machines evaluate when opening routine exports (local code-execution context dependent on host application settings).

**Remediation**

1. Neutralize formula-leading cells in `DataGridExport::map` (apostrophe prefix or escape) for CSV and XLSX writers alike; add tests for `=`, `+`, `-`, `@` leading values.

---

## V6 — activity file uploads land unvalidated on the public disk

**The activity file upload path accepts arbitrary types and unbounded sizes onto the web-served public disk, while mail attachments use a private disk behind an authenticated download route.**

**Affected code**

- `packages/Webkul/Admin/src/Routes/Admin/activities-routes.php:11` — upload route
- `packages/Webkul/Activity/src/Repositories/ActivityRepository.php:32` — stores to the `public` disk with no mimes/size validation

**Preconditions**

1. Any authenticated staff user who can create activities.
2. Default filesystem disk is `public` and `/storage/*` is served without authentication — shipped defaults.

**Steps and observed result** — full steps in `report.md`. Authenticated multipart uploads returned HTTP 200 for (a) a `.php`-named file containing `<?php /* dummy mark`, (b) a `.php`-named plain-text file, (c) a 2,000,000-byte dummy file — zero mime/extension/size validation. All three payloads physically landed under `storage/app/public/activities/<id>/` (disk listing + first-bytes dump verified). Unauthenticated GETs of the returned `/storage/...` URLs returned HTTP 200 echoing the stored bytes, with serving content types following the stored names (the verifier's matrix: `text/plain` for `.txt`, `text/html`, `image/svg+xml`).

**What was NOT demonstrated**

- PHP code execution: the framework's content-sniffing `hashName()` stores PHP-ish content without a `.php` extension (a separate polyglot hypothesis was runtime-refuted), so `.php` persistence was not achievable. The demonstrated result is world-readable hosting of attacker-chosen content, including `text/html` and `image/svg+xml` (stored-XSS/defacement delivery from the deployment origin).

**Impact**

Any staff user can permanently host arbitrary world-readable content on the deployment origin, unauthenticated — stored XSS delivery and content-hosting abuse.

**Remediation**

1. Move activity (and attribute-file) uploads to the private local disk with authenticated scoped download routes — the pattern already present for mail attachments; add mimes/size validation.

---

## V7 — stored `custom_scripts` echoed raw into unauthenticated pages

**Undefined configuration keys persist verbatim and the `custom_scripts` values are echoed unescaped into the admin, login and public web-form layouts, while every neighbouring template value goes through escaping.**

**Affected code**

- `packages/Webkul/Admin/src/Routes/Admin/configuration-routes.php:12` — configuration store route
- `packages/Webkul/Admin/src/Resources/views/components/layouts/anonymous.blade.php:120` — raw echo of `custom_scripts` (login and public web-form layouts; admin layout echoes `custom_css` raw inside `<style>`)
- `getConfigField()` returns null for undefined keys, so `sanitizeConfigValue` applies no HTMLPurifier pass and no validation rule rejects them

**Preconditions**

1. Actor holding settings/configuration write rights writes the configuration key once (this is an admin-privileged origin; compromise of that principal or a malicious insider is the precondition class).

**Steps and observed result** — full steps in `report.md`. `POST /admin/configuration/general/content` with `keys[]` declaring `general.content.custom_scripts.{custom_javascript,custom_css}` (plus a third nested key without any `keys[]` entry) persisted all three undefined keys verbatim into `core_config`. The unauthenticated login page echoed the stored `custom_javascript` value unescaped inside its `<script>` element and `custom_css` unescaped inside `<style>`; the marker `</style><b>` survived as literal markup. **Browser execution confirmed**: the benign executing-class payload `document.title='VF3EXECUTED'` stored through the same endpoint was executed by a real Chromium on the unauthenticated login page — the tab title changed from "Sign In" to "VF3EXECUTED"; the echo context `<script type="text/javascript"> alert('VF3VERIFY') // VF3RAW </script>` was captured verbatim in the anonymous layout.

**What was NOT demonstrated**

- Session theft or a malicious payload (only the benign executing-class marker was run); exploitation requires an admin-originated value, so this crosses the admin→visitor boundary rather than being reachable by an unauthenticated attacker directly.

**Impact**

Stored script execution on pages every unauthenticated visitor loads (login page, public web forms), originating from a single admin-side save — session theft of the next admin, persistent script on unauthenticated pages.

**Remediation**

1. Whitelist persisted configuration keys against the registered config tree; encode or sandbox `custom_scripts` (CSP nonce + text node, or a safe subset); never echo admin-set values into unauthenticated pages.

---

## Files

| Path | Contents |
|---|---|
| `report.md` | full environment and per-finding reproduction report |
| `submission.json` | per-finding reporting state (schema as `pinpoint-poc/submission.json`) |
| `evidence/` | verbatim captured output, `E0000xx.txt` (adjudication-era identifiers) |
| `evidence/runtime-verdicts/` | per-finding runtime verdict logs (status, observations, decisive facts) |
| `evidence/README.md` | which evidence file supports which finding |

This directory contains no runnable exploit scripts: the PoCs are documentation-type (steps + verbatim observation logs). The lab is rebuildable from the target's own Docker install path at the tested commit.
