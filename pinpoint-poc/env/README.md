# Lab environment — pinpoint-poc

## Prerequisites

- Docker Desktop (tested: 29.6.2, linux/arm64 VM) with Compose v2+.
- ~6 GB free RAM for the stack.
- The two PoC scripts need only Python 3.9+ stdlib.

## Bring up

```sh
cd env
docker compose -f docker-compose-verify.yml up -d
# wait for pinpoint-web "Started WebApp" (docker logs -f pinpoint-web); 1-3 min.
# HBase is included for stack completeness but is NOT required for F1/F2 and
# is known to deadlock during table creation on arm64 images (see report.md
# Limitations); the web findings do not depend on it.
```

Port map (chosen to avoid common host-port collisions):

| Host | Container | Surface |
|---|---|---|
| 18080 | web:8080 | main web app (login + APIs) |
| 18443 | web:8443 | web management server (actuator) — plain HTTP despite the port number |
| 8081 | collector:8081 | collector HTTP (not used by F1/F2) |

Web is launched with the vendor-documented basic-login mode and planted dummy
credentials via `JAVA_TOOL_OPTIONS` (the Jib images do not consume `JAVA_OPTS`):

- ROLE_USER `verifyuser` / `verifypw`
- ROLE_ADMIN `verifyadmin` / `verifyadminpw`
- JWT secret `VERIFY-DUMMY-SECRET-KEY-0123456789abcdef`
- `admin.password` `verify-admin-pw`

Every value is a research-planted dummy; nothing real is present.

## Run the PoCs

```sh
python3 ../poc/poc_f1_actuator_jwt_forgery.py \
  --main-base http://127.0.0.1:18080 \
  --mgmt-base http://127.0.0.1:18443 \
  --confirm-authorised

python3 ../poc/poc_f2_error_page_stacktrace.py \
  --main-base http://127.0.0.1:18080 \
  --confirm-authorised
```

Both exit 0 only when the full claimed observation chain reproduces.

## Tear down

```sh
docker compose -f docker-compose-verify.yml down -v
```

No state persists outside the compose volumes (removed with `-v`).

## Collector-side findings (F3, F4)

F3 uses the same stack: the `pinpoint-collector` service (host port 8081) is started by
`docker-compose-verify.yml` with planted dummy credentials via `JAVA_TOOL_OPTIONS`
(`collector.admin.password`, hikari/redis passwords). Run:

```sh
python3 ../poc/poc_f3_collector_monitor_unauthenticated.py \
  --collector-base http://127.0.0.1:8081 --confirm-authorised
```

F4 cannot run against this stack (the plain collector image carries no OTLP modules and
the full metric stack needs Pinot/Kafka/HBase — the official hbase 4.0.0 image
deadlocks on arm64). It uses the released-artifact fixture instead:

```sh
cd fixture-c8
# follow README.md: extract /app/libs from
#   pinpointdocker/pinpoint-collector:4.0.0-metric
# compile fixture -> run on 127.0.0.1:18091 (-Xmx128m) -> probe
python3 -I gen_payload.py --mib 8 --out /tmp/pb8.pb
python3 -I probe.py
python3 ../../poc/poc_f4_otlp_metric_unbounded_body.py \
  --base http://127.0.0.1:18091 --with-control --confirm-authorised
```

`settings.xml` is only the Maven mirror used behind the Great Firewall; drop it elsewhere.
