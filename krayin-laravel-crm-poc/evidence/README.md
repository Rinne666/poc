# Evidence index — krayin-laravel-crm-poc

Verbatim captured output from the lab (commit `ed6deeb`, Docker PHP 8.3.35 + MySQL 8.0). `E0000xx.txt`
files carry adjudication-era capture identifiers; nothing in these files is edited. Per-finding
runtime verdict logs (status, static observations, filter/probe results, decisive facts) live in
`runtime-verdicts/`.

Shared provenance records:

- `E000001.txt` — vendor policy capture (`SECURITY.md`: private email reporting, credited GHSA, CVSS welcome)
- `E000002.txt` — published-advisory check (`CHANGELOG.md` release history; no same-shape entries)
- `E000008.txt` — route definitions excerpt (data-transfer import routes; also used by V3)
- `E000013.txt` — activity route definitions excerpt (also used by V6)
- `E000023.txt` — datagrid export route/controller excerpt (also used by V5)
- `E000027.txt` — LeadController attach/update excerpt (also used by V4)

Per finding:

| Finding | Evidence files | runtime-verdicts/ |
|---|---|---|
| V1 mail-forward-editor-htmlfilter-only-body | E000035, E000036, E000125 | `mail-forward-editor-htmlfilter-only-body.json` |
| V2 bouncer-ancestor-walk-unmapped-write-routes | E000007, E000017, E000104 | `bouncer-ancestor-walk-unmapped-write-routes.json` |
| V3 data-transfer-import-delete-ignores-view-scope | E000008, E000058, E000084, E000107 | `data-transfer-import-delete-ignores-view-scope.json` |
| V4 lead-person-attach-missing-scope-check | E000027, E000033, E000083, E000123 | `lead-person-attach-missing-scope-check.json` |
| V5 datagrid-export-cells-formula-injection-unescaped | E000023, E000038, E000039, E000111 | `datagrid-export-cells-formula-injection-unescaped.json` |
| V6 activity-file-upload-unvalidated-public-disk | E000013, E000020, E000088, E000102 | `activity-file-upload-unvalidated-public-disk.json` |
| V7 configuration-store-undefined-key-raw-layout-echo | E000009, E000021, E000105 | `configuration-store-undefined-key-raw-layout-echo.json` |

All fixture rows created during the reproductions were deleted afterwards; every payload in these
captures is an inert dummy marker.
