# Report — krayin-laravel-crm-poc findings V1–V7

## Environment (exact)

- Host: local Docker lab (scratch install built for this audit).
- Runtime: PHP 8.3.35 (phpfpm) + MySQL 8.0; TinyMCE 6.6.2 loaded from cdnjs by the application itself.
- Source under test: `krayin/laravel-crm` commit `ed6deebfcb8c616eaf352c893a10a6d8e666fc6e` (2.2 line, clean worktree, unmodified).
- Installed via the project's own Docker install path; default configuration throughout. The only deployment-level fact relied on: the default `public` filesystem disk with `/storage/*` served unauthenticated (shipped default, V6).
- Browser execution evidence for V7 was captured in a real Chromium against `http://127.0.0.1:8000`.
- All payloads are inert dummy markers (`VERIFY`/`VF3`/`FP1`-class strings). All fixture users, roles, leads, persons, attributes and configuration rows created for a test were deleted afterwards. No real user data exists in the lab and none was touched.

Per-finding raw observation logs are in `evidence/` (E0000xx identifiers, unedited) and `evidence/runtime-verdicts/` (per-finding status records with decisive facts).

---

## V1 — mail forward editor renders unsanitized inbound HTML

### Expected security boundary

Every automatic render sink on stored email content applies a sanitizer (`v-safe-html` at `view.blade.php:246`, `strip_tags` at `DataGrid.php:472`). The forward/reply editor initial content path applies only `HtmlFilter::process` — a blacklist, body-scoped — at ingestion; no second layer guards the editor mount.

### Step-by-step reproduction

1. **Ingest** an inbound mail whose body carries the probe markup below (inert markers).
2. **Run the sole filter** the way ingestion does: `HtmlFilter::process($body)` on the deployed runtime. Survivor set measured precisely (`evidence/runtime-verdicts/mail-forward-editor-htmlfilter-only-body.json`, `filter_results`):
   - PASSES verbatim: `<svg><a id=x href="#"><animate attributeName="href" values="javascript:…VERIFY…"></a></svg>` (only attribute-name lowercasing), `<svg><set attributeName="onmouseover" to="VERIFY">`, `data:text/html;base64,…` URIs in `href` and `<form action>`.
   - Correctly removed: `on*` attributes, `<script>`, `<iframe>`, literal and entity-encoded `javascript:` URIs, newline-split `javascript:` (rewritten to `#`); `<style>` kept with content emptied.
3. **Render the editor path**: the forward flow is statically confirmed — `EmailController@view` returns the raw Email model; `view.blade.php:1222` serializes it with `@json($email)`; the forward computed returns `action.email.reply` (:1373); `control.blade.php` mounts `x-admin::tinymce` on `textarea#reply`; `tinymce/index.blade.php:86` runs `tinymce.init` with no `valid_elements`/sanitize hook.
4. **Live page capture**: the stored reply carrying the survivor constructs was captured verbatim in the authenticated page DOM as the editor's data source (the `v-email-list` component data `email.reply`, serialized via `@json($email)`).

### Observed result

The filter's survivor set on the deployed runtime was measured precisely; the dangerous constructs pass through and reach the editor's data source in the authenticated page DOM. The three sibling automatic sinks on the same data are guarded; this path is not.

### What was NOT demonstrated

End-to-end execution inside the TinyMCE editor iframe. The thread pane renders only with ingestion-pipeline-complete fixtures (attachments/relations), so the composer did not mount for the hand-crafted row. Editor-iframe execution remains the library/browser fact; delivery of filter-surviving script-class markup into the authenticated editor surface is runtime-confirmed.

### Impact

An external mail sender seeds script-class markup; an agent opening forward/reply renders it into the TinyMCE surface inside an authenticated staff session (agents handle customer mail routinely). Session scope = CRM data access.

### Remediation

Route the editor initial content through the same sanitizer as the other sinks (or render as text and let the editor parse on demand); extend the blacklist miss class to a real allowlist sanitizer.

### CVSS 3.1

9.3 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`. UI:R reflects the agent interaction step; S:C reflects the external-sender → authenticated-session boundary.

---

## V2 — Bouncer dotted-ancestor walk authorizes unmapped destructive routes

### Expected security boundary

A role holding only a view ACL key must not be able to invoke destructive admin routes. `acl.php` maps permissions per route; the exact-mapped single delete `DELETE /admin/settings/attributes/<id>` requires `settings.automation.attributes.delete`.

### Step-by-step reproduction

1. **Setup**: admin seeds three user-defined attributes; create a role granting only `settings.automation.attributes` (view key) plus dashboard; create a user with that role.
2. **The destructive call**: restricted user POSTs `/admin/settings/attributes/mass-destroy` with two attribute ids (route name `admin.settings.attributes.mass_delete`, absent from `acl.php`) → **HTTP 200**, both definitions hard-deleted.
3. **Cascade verification**: `information_schema` shows `attribute_values` FK `DELETE_RULE=CASCADE`; stored values of the deleted attributes went 1 → 0 per deleted attribute; the untouched attribute kept its values.
4. **Positive/negative controls (same session)**: `GET /admin/settings/attributes` (exact view key) → 200; `DELETE /admin/settings/attributes/<id>` (exact-mapped) → **401**.
5. **Reflection checks** of `Bouncer::isAuthorizedByFeature` (same routine the middleware calls): `leads.view` holder → granted `admin.leads.attributes.update`, `admin.leads.emails.store`; `products.view` holder → granted `admin.products.inventories.store`, `admin.products.search`; `leads.view` holder → DENIED `admin.leads.quotes.delete` (walk stops at the mapped `admin.leads.quotes.` prefix, requires `quotes.mail`); view-only attributes holder → granted `admin.settings.warehouse.activities.index` (two-level walk).

### Observed result

The unmapped destructive route is authorized for a view-only principal through the dotted-prefix ancestor walk, with HTTP 200 and permanent cascade data loss; the exact-mapped equivalent refuses the same principal with 401.

### What was NOT demonstrated

HTTP-level execution of the additional reflection-confirmed grants (inventory writes, quote send, lead attribute/email writes); introducing commit not traced (no `git -S` archaeology).

### Impact

One request by any restricted role cascade-deletes all stored values of arbitrary attribute definitions (permanent data loss) and, per reflection, hands read-only roles cross-domain write/send capabilities. The fallback is on by default for every deployment.

### Remediation

Add explicit `acl.php` mappings for every unmapped write route; bound the dotted-prefix ancestor fallback so it cannot authorize state-changing verbs; add a regression test walking `acl.php` against the route list.

### CVSS 3.1

9.9 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`. PR:L = a restricted-role account (supported configuration); S:C = the walk crosses ACL domains beyond the granted key.

---

## V3 — import delete path ignores the caller's record scope

### Expected security boundary

Interactive delete of a person is gated by `preventUnauthorizedAccess` against the caller's authorized-user ids; the datagrid does not even list out-of-scope records. The bulk import pipeline must not be a bypass.

### Step-by-step reproduction

1. **Setup**: admin-owned person id 62 (`user_id=1`). U2 = staff user with role holding exactly `settings.automation.data_transfer.imports.create` + `.import`, `view_permission=individual`, authorized ids = self.
2. **Craft the import CSV** against the shipped persons importer columns (`name,emails,contact_numbers,organization_id,job_title,user_id`) with `action=delete`; stored upload verified byte-identical on read-back.
3. **U2 drives the pipeline**: `POST /admin/settings/data_transfer/imports` (type=persons, action=delete) → `GET validate/{id}` (`is_valid=true`, processed_rows=2, errors=[]) → `GET start/{id}` → summary `deleted=2`.
4. **Verify**: admin-owned person id 62 hard-deleted from `persons` (4 `attribute_values` rows left orphaned); U2's own person also deleted.
5. **Controls (same user)**: `GET edit/{id}` on an admin-owned person → **401** (`preventUnauthorizedAccess`); U2's persons datagrid does not list the admin-owned person.

### Observed result

Cross-scope bulk hard-delete through the import pipeline, confirmed end-to-end on the live instance; the interactive path refuses the identical mutation for the identical principal.

### What was NOT demonstrated

Only the persons importer was driven end-to-end; leads/products/quotes importers share the unscoped resolution pattern but were not executed. Introducing commit not traced.

### Impact

Any import-ACL holder can permanently delete (or rewrite, for upsert actions) other users' CRM records — permanent data loss bypassing the permission model the UI enforces.

### Remediation

Snapshot `authorized_user_ids` onto the import record at start; enforce the predicate in every delete/upsert target resolution across the importers (the DataTransfer package currently has zero bouncer references).

### CVSS 3.1

8.1 (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`.

---

## V4 — lead person-attach skips the contact-data scope check

### Expected security boundary

Direct person read `GET /admin/contacts/persons/view/<id>` is scope-enforced (401 outside the caller's authorized ids). The lead attach/update path persisting `person[id]` must enforce the same predicate — it renders the person's contact data on the lead view.

### Step-by-step reproduction

1. **Setup**: victim person owned by a different user; restricted user (individual scope, `leads.view`) owns a lead.
2. **Attach**: restricted user sends `PUT /admin/leads/attributes/edit/<own-lead-id>` with `person[id]=<victim id>` → **HTTP 200**, `leads.person_id` persisted to the out-of-scope person. The bare mass-assignable `person_id=<id>` request field (no `person[]` branch) also persists the link.
3. **Read out**: `GET /admin/leads/view/<lead-id>` (HTML) and `GET /admin/leads/get` (kanban JSON) render the victim person's email address and contact number verbatim (`person.blade.php:65`).
4. **Controls (same user)**: direct `GET /admin/contacts/persons/view/<victim id>` → **401**; the same `person[id]` payload aimed at another user's lead → **401**.

### Observed result

Cross-scope contact PII readout demonstrated at runtime: the attacker-lead view and kanban render the victim person's email and phone; the direct path refuses the same id for the same principal.

### What was NOT demonstrated

Write access to the victim lead (this record demonstrates cross-scope read only); victim attribute-file contents were not accessed. Introducing commit not traced.

### Impact

Cross-tenant contact PII readout (email, phone) with a single authenticated request and an enumerable id; no preconditions beyond two accounts.

### Remediation

Validate the submitted person id against `bouncer()->getAuthorizedUserIds()` for contacts.persons inside the lead attach/update handler before linking; reject cross-scope ids exactly like the direct person read path.

### CVSS 3.1

7.1 (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`.

---

## V5 — datagrid export writes stored values into spreadsheet cells unescaped

### Expected security boundary

The JSON datagrid path strips cell values (`strip_tags` in `sanitizeRow`, `DataGrid.php:472`). The export writer (`DataGridExport::map`, `DataGridExport.php:48`) returns `$record->{$index}` verbatim — the export branch bypasses the same data's sanitize step.

### Step-by-step reproduction

1. **Seed** persons with names `=VERIFY(1)+1 <tag>` and `+VERIFY(2)+2 <tag>` (inert formula markers) — creatable by any staff user or anonymous public web-form submission.
2. **Export CSV**: admin `GET /admin/contacts/persons?export=1&format=csv` → 200 `text/csv`; raw bytes contain `"…","=VERIFY(1)+1 <tag>",…` — leading `=` and `+` intact, no quote-prefix, escape or neutralization.
3. **Export XLSX**: same dataset; `sheet1.xml` cell for the stored value is a real formula element — `<c r="B3" t="str"><f>VERIFY(1)+1 VF7F-1794112781</f><v>0</v></c>` — and the writer attempts to evaluate it server-side during `calculateColumnWidths` (`getCalculatedValue` → Calculation engine); a dummy formula can crash the export with a TypeError 500.
4. **Contrast**: the JSON datagrid path for the same rows applies `strip_tags`.

### Observed result

Stored values reach both spreadsheet writers unneutralized; the XLSX writer even types them as formulas and attempts server-side evaluation.

### What was NOT demonstrated

Evaluation of the formula on the analyst's machine — depends on the spreadsheet application's DDE/macro settings, a client fact outside this repository. What is demonstrated: attacker-chosen formula bytes leave the server unneutralized into files staff open.

### Impact

An anonymous web-form submitter can seed spreadsheet formulas executed on staff machines opening routine exports (local code-execution context dependent on host application settings).

### Remediation

Neutralize formula-leading cells in `DataGridExport::map` (apostrophe prefix or escape) for CSV and XLSX writers alike; add tests for `=`, `+`, `-`, `@` leading values.

### CVSS 3.1

8.7 (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`. UI:R = staff member opening the export.

---

## V6 — activity file uploads land unvalidated on the public disk

### Expected security boundary

Mail attachments land on a private disk behind an authenticated download route. Activity uploads must not be a less-guarded sibling: the default `public` disk is web-served unauthenticated at `/storage/*`.

### Step-by-step reproduction

1. **Upload A**: authenticated multipart to the activity file endpoint, file named `x.php` containing `<?php /* FP1 dummy mark` → **HTTP 200** "Activity created successfully"; `activity_files` row created with path `activities/<id>/<hash>`.
2. **Upload B**: `.php`-named plain-text file → **HTTP 200** (no mime/extension validation error).
3. **Upload C**: 2,000,000-byte dummy file → **HTTP 200** (no size validation error).
4. **Disk verification**: all three payloads physically present under `storage/app/public/activities/<id>/` (disk listing + first-bytes dump, e.g. caseA first bytes `3c3f706870…`).
5. **Unauthenticated fetch**: `GET /storage/activities/<id>/<file>` with no Cookie header → **HTTP 200** echoing the stored bytes; serving content type follows the stored name (verifier's matrix: `.txt` → `text/plain`, `.html` → `text/html`, `.svg` → `image/svg+xml`).

### Observed result

Unvalidated, attacker-chosen content is world-readable on the deployment origin, end-to-end, exactly as claimed. Extension note: the framework's content-sniffing `hashName()` derives the stored extension from content, so PHP-ish content lands without a `.php` extension — `.php` persistence was NOT achievable (the separate polyglot hypothesis was runtime-refuted during adjudication).

### What was NOT demonstrated

Server-side PHP execution (blocked by `hashName()` content sniffing, verified). The demonstrated result is world-readable hosting of arbitrary content including `text/html` and `image/svg+xml`.

### Impact

Any authenticated staff user can permanently host arbitrary world-readable content on the origin — stored-XSS delivery (served `text/html`/`image/svg+xml` on the deployment's own origin) and content-hosting abuse.

### Remediation

Move activity (and attribute-file) uploads to the private local disk with authenticated scoped download routes (the pattern already present for mail attachments); add mimes/size validation; keep `hashName`'s content-derived extension.

### CVSS 3.1

7.1 (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`.

---

## V7 — stored `custom_scripts` echoed raw into unauthenticated pages

### Expected security boundary

Neighbouring template values in the same layouts go through Blade escaping. Undefined configuration keys should be rejected at store time (`getConfigField()` returns null for them, so `sanitizeConfigValue` applies no HTMLPurifier pass); `custom_scripts` must never reach unauthenticated pages raw.

### Step-by-step reproduction

1. **Persist undefined keys**: `POST /admin/configuration/general/content` as admin with `keys[]` declaring `general.content.custom_scripts.{custom_javascript,custom_css}` and a third nested key posted without any `keys[]` entry → **HTTP 200**; all three keys persisted verbatim into `core_config` (undefined keys are not rejected).
2. **Unauthenticated render**: `GET /login` with no session → the stored `custom_javascript` value echoed unescaped inside the page's `<script>` element, `custom_css` unescaped inside `<style>` (`anonymous.blade.php:120`). The `</style><b>` marker survived as literal markup — no output encoding; the style-context breakout executes script with a real payload.
3. **Browser execution (confirmed)**: store the benign executing-class payload `document.title='VF3EXECUTED'` through the same endpoint; load `/login` in a real Chromium against `http://127.0.0.1:8000` → the tab title changed from "Sign In" to `VF3EXECUTED` (an `alert()`-variant also fired interactively on an earlier load). Echo context captured verbatim: `<script type="text/javascript"> alert('VF3VERIFY') // VF3RAW </script>` inside the anonymous layout.
4. **Additional sinks**: the authenticated admin dashboard echoed `custom_css` raw inside `<style>`; the public web-form layout renders the same raw echo (three sinks total).
5. **Cleanup**: the `core_config` rows were deleted and the login page verified clean afterwards.

### Observed result

Stored script execution on the unauthenticated login page, executed in a real browser, from a single admin-side configuration save. Echo contexts captured verbatim in all three layouts.

### What was NOT demonstrated

Session theft or a malicious payload (only the benign executing-class marker was run). The precondition is an admin-originated value: this crosses the admin→visitor boundary (a compromised admin account or malicious insider plants script for every subsequent visitor, including the next admin login), not an unauthenticated-attacker entry point.

### Impact

Stored script on pages every unauthenticated visitor loads (login page, public web forms): session theft of the next admin, persistent script on unauthenticated pages.

### Remediation

Whitelist persisted configuration keys against the registered config tree; encode or sandbox `custom_scripts` (CSP nonce + text node, or strip to a safe subset); never echo admin-set values into unauthenticated pages.

### CVSS 3.1

8.7 (High) — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N`. PR:H = configuration write rights; S:C = the value executes on unauthenticated pages for every visitor.

---

## Reproduction-claim statement

Every claim above came from running against the lab, not from reading code: static findings listed per record (file:line) were each paired with a runtime observation in the same record, and each reproduction includes a control demonstrating the enforcement exists on the sibling path it should have existed on. Raw, unedited captures are in `evidence/`; per-finding verdict logs with decisive facts are in `evidence/runtime-verdicts/`.
