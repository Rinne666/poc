# C8 verification fixture — reproduction recipe

Runtime proof that `POST /opentelemetry` has no admission control while the
sibling `/v1/traces` path does, executed **against the released artifacts**
(docker image `pinpointdocker/pinpoint-collector:4.0.0-metric`), not a
source build. Lab-only: binds `127.0.0.1:18091`, 128 MiB heap ceiling, a
process the researcher owns.

## Why a fixture instead of the full stack

The metric collector image requires Pinot/Kafka (and the quickstart stack
requires HBase, which deadlocks on arm64 in `pinpoint-hbase:4.0.0`). The
claim under test lives entirely between the socket and the parsed message —
servlet chain + `ProtobufHttpMessageConverter` + the real controller — so
the fixture wires those exact 4.0.0 classes onto embedded Tomcat and stubs
only the storage service (`OtlpMetricCollectorService.save`). The sibling
control uses the real `OtlpTraceHttpAdmissionFilter` with the shipped
defaults (4 MiB / 256 MiB / 64 / Retry-After 1), registered exactly as
`OtlpTraceCollectorHttpModule` does.

## Steps (macOS + Docker Desktop, arm64)

```sh
# 1. obtain the image (daocloud mirror does not proxy third-party repos;
#    plain docker.io worked here — your mileage may vary)
docker pull pinpointdocker/pinpoint-collector:4.0.0-metric

# 2. extract the exploded Jib layout
mkdir -p /tmp/c8libs
c=$(docker create pinpointdocker/pinpoint-collector:4.0.0-metric true)
docker cp "$c:/app/libs" /tmp/c8libs
docker rm "$c"

# 3. compile the fixture against the image's own jars
FIX="$(dirname "$0")"
docker run --rm -v /tmp/c8libs:/libs:ro -v "$FIX":/fixture \
  maven:3.9-eclipse-temurin-17 \
  sh -c 'mkdir -p /fixture/build && javac -cp "/libs/libs/*" \
         -d /fixture/build /fixture/src/main/java/c8fixture/*.java'

# 4. run (128 MiB heap; spring-shell/jline jars excluded — their
#    ApplicationRunner otherwise shuts the context down)
docker rm -f c8-fixture 2>/dev/null
docker run -d --name c8-fixture -v /tmp/c8libs:/libs:ro -v "$FIX":/fixture \
  -p 127.0.0.1:18091:18091 -w /tmp maven:3.9-eclipse-temurin-17 \
  sh -c 'C=$(ls /libs/libs/*.jar | grep -vE "spring-shell|jline|ST4|antlr-runtime" | paste -sd: -); \
         exec java -Xmx128m -cp "$C:/fixture/build" c8fixture.App \
              --server.port=18091 --spring.main.banner-mode=off'

# 5. payloads + probes
python3 -I gen_payload.py --mib 1  --out /tmp/pb1.pb
python3 -I gen_payload.py --mib 8  --out /tmp/pb8.pb
python3 -I gen_payload.py --mib 32 --out /tmp/pb32.pb
python3 -I gen_payload.py --mib 64 --out /tmp/pb64.pb
python3 -I probe.py                        # sizes + sibling control
python3 -I ../adjudication/poc/poc_c8_otlp_metric_unbounded_body.py \
  --base http://127.0.0.1:18091 --with-control --confirm-authorised

docker rm -f c8-fixture
```

## Observed (2026-11-06, full capture: ../adjudication/evidence-c8/runtime-differential.txt)

| request | /opentelemetry (metric, claim: no cap) | /v1/traces (real filter, 4 MiB cap) |
|---|---|---|
| 1 MiB | **200** | 200 |
| 8 MiB | **200** | **413** |
| 32 MiB | **200** (heap → ~86 MiB) | — |
| 64 MiB | **200** (heap → ~113 MiB of 128 MiB) | connection aborted after reject (Tomcat swallow) |
| 3×64 MiB sequential | all **200**, heap pinned at ~84–88% of ceiling | — |
| 3×32 MiB **concurrent** | 1×**200** + 2×**500** — log: `java.lang.OutOfMemoryError: Java heap space`, stack inside `ExportMetricsServiceRequest$Builder.mergeFrom` → `Arrays.copyOfRange` (the parse itself) | — |

Honest limitations:

- The synthetic payloads omit `pinpoint.agentId` in the resource attributes,
  so the mapper skips the datapoints (`savedDatapoints=0`, visible as an
  INFO log). Irrelevant to the observation: the OOM stack is inside the
  protobuf parse, upstream of any mapping.
- The heap ceiling (128 MiB) is a fixture choice; production `-Xmx` values
  differ. What is proven is the ABSENCE of any per-request/in-flight/
  concurrency bound on this path (no 413/503 at any size up to 64 MiB, OOM
  under three concurrent bodies), not a specific production threshold.
- The metric controller bean graph, converter, filter and Tomcat are the
  shipped 4.0.0 classes unmodified; storage (Pinot/Kafka) is the stub.
