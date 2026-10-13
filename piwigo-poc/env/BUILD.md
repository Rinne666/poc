# Build / run environment for the Piwigo PoCs

This is the target fixture the PoCs run against. It is fully disposable. The build is
identical to what was used during the audit construction; the audit's
`run-1/poc/docker-compose.yml` is the source of truth.

## Files in this directory

| File | Role |
|---|---|
| `Dockerfile` | custom image on `php:8.2-apache` with `mysqli`, `gd`, `exif`, `mbstring`, `xml`, `zip`, `fileinfo`, `opcache`. Vendor requires PHP 7.4+; 8.2 is current stable. |
| `docker-compose.yml` | two-service compose: `db` (mariadb:10.11) + `web` (custom image), exposed only on `localhost:8089` |
| `up.sh` | `docker compose up -d --build`, waits for `db` healthcheck, waits for Apache to return 200 on `/install.php` |
| `down.sh` | `docker compose stop` (keeps the named volumes around) |
| `teardown.sh` | `docker compose down -v` plus a recursive `rm -rf` on the snapshot directory |
| `install.sh` | POSTs to `/install.php` with the wizard fields; this is the **only** way to reach a clean state for the PoCs |
| `CVSS.md` | the CVSS vector derivation per finding |

## What the PoCs need from this fixture

- A reachable Piwigo webroot at `http://localhost:8089/` (overridable via `--base`).
- The `piwigo_users` table containing the webmaster account the `install.sh` step
  creates. The PoCs do not log in as the webmaster, but the table needs to be
  populated because the WS layer reads the user table on every call.
- The `piwigo_search`, `piwigo_images`, `piwigo_image_category`, `piwigo_rate`,
  and `piwigo_categories` tables empty of `piwigo-poc-*` rows at the start of
  the run. The PoC scripts `INSERT` only `piwigo-poc-*` rows and clean them up
  on `EXIT`; if a previous run aborted without cleanup, the next run will
  report the leftover rows in the script output and ask the operator to
  `DELETE FROM piwigo_search WHERE rules LIKE '%piwigo-poc-%'` or equivalent
  before continuing.

## Re-running from a clean state

```bash
cd piwigo-poc
env/teardown.sh   # docker compose down -v + remove snapshot/
env/up.sh
env/install.sh
for f in poc/*.sh; do
  "$f" --base http://localhost:8089 --confirm-authorised || echo "FAILED: $f"
done
env/teardown.sh
```

The `install.sh` step is the slowest part (a fresh database, schema, baseline
rows). It is meant to be run once per fixture lifetime; the PoCs are fast
(single-digit seconds each).

## Network exposure

The fixture listens on `localhost:8089` only. There is no external port mapping
for the database. The container has no outbound network access configured; the
PoCs do not need it (no telemetry, no update checks, no third-party calls).
