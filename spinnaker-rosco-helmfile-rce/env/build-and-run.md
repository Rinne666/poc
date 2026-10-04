# Build and run rosco to reproduce

Everything here is from a clean checkout of [`spinnaker/spinnaker`](https://github.com/spinnaker/spinnaker).
Record the commit you use; the two branches that matter behave differently and the
difference is the whole finding.

```bash
git clone https://github.com/spinnaker/spinnaker.git
cd spinnaker

# vulnerable: every released version through 2026.3.0 (2026-09-07)
git checkout rosco-2026.3.0

# fixed: ships the hardened guard
git checkout rosco-2026.3.1

git rev-parse HEAD        # <- record this in evidence/
```

## Layout

`rosco` is a **composite build**: the root `settings.gradle` contains only
`includeBuild 'rosco'`, and the service's own build lives in `rosco/build.gradle`
(`group = "io.spinnaker.rosco"`). Subprojects include `rosco-manifests` (where the
vulnerable class is) and `rosco-web` (the Spring Boot application).

| Path | Role |
|---|---|
| `rosco/rosco-manifests/src/main/java/com/netflix/spinnaker/rosco/manifests/helmfile/HelmfileTemplateUtils.java` | the guard and the bake command |
| `rosco/rosco-web/config/rosco.yml` | service config; `server.port: 8087` |

## Build

Gradle composite build, JDK 17:

```bash
cd rosco
./gradlew :rosco-web:bootJar        # or: ./gradlew build
```

If your checkout has no `gradlew` wrapper in `rosco/`, use a local Gradle 8.x against
`rosco/settings.gradle`.

## The file that decides everything

rosco listens on **8087** and has Swagger enabled (`rosco.yml`, patterns
`/api/v1.*`, `/api/v2.*`, `/bakeOptions.*`, `/status.*`), so the API surface is
self-describing once the service is up.

## Confirm which branch you have

The guard is a single method, so a jar inspection is decisive and needs no run:

```bash
cd rosco
./gradlew :rosco-manifests:jar
unzip -p rosco-manifests/build/libs/rosco-manifests-*.jar \
  com/netflix/spinnaker/rosco/manifests/helmfile/HelmfileTemplateUtils.class \
  | strings | grep -c rejectHooksAndPostRenderers
```

| hits | meaning |
|---|---|
| **0** | no guard — `hooks:` in the entry file executes, no bypass needed |
| **1** | guard present |

Measured values from the original run:

| Build | hits | class size |
|---|---|---|
| `rosco-2026.3.0` and earlier | 0 | 11 334 B |
| `main-latest` @ 2026-09-19 (carries #8015) | 1 | 19 189 B |

> A hit count of 1 tells you the guard exists. It does **not** tell you the guard is
> complete — on 2026-09-19 a build with the guard still executed the payload. For that
> distinction, read the `catch` in `validateHelmfileYamlFile`: if it returns instead of
> throwing, the guard fails open on unparseable input.

## Prerequisites for a working reproduction

| # | Requirement | Why |
|---|---|---|
| 1 | `helmfile` **1.7.0** on the rosco image | post-renderer form differs across versions |
| 2 | `--helm-binary helm3` (rosco's default) | the image also ships Helm 2.17.0; with Helm 2, helmfile fails at the Tiller check **before** hooks run and the payload looks like a rejection |
| 3 | an `http/file` artifact account | on the tested build `HttpArtifactCredentials` advertises that one literal; `http` and `file` both 404 at the resolver |
| 4 | redis reachable | `rosco.jobs.local` needs it |
| 5 | payloads written **LF-only** | CRLF turns `id` into `id\r` inside the shell and fails in a way that mimics a guard rejection |

## Run it

```bash
# control: parseable helmfile with hooks:  -> expect 400 (guard rejects)
# payload: same bytes plus one value nested >50 levels -> expect 200 + marker (guard fails open)
python3 poc/entry_hook_marker.py \
    --base http://localhost:18087 \
    --container <your-rosco-container> \
    --confirm-authorised
echo "exit=$?"     # 0 = reproduced, 2 = guard blocked it, 3 = inconclusive
```

Read the marker from **inside** the container. The hook writes to rosco's own `/tmp`; a
host-side check always reports "not executed".

## Full-stack route (the supply-chain shape)

The service-level route above skips gate, orca and front50. To reproduce the variant
where the attacker never contacts Spinnaker, you need the full stack — deck, gate, orca,
rosco, clouddriver, front50, echo, plus redis and mysql — and a victim pipeline whose
bake stage references a URL you control. The original run used 10 containers; see
`../report.md` §4.3. Two things bite every time:

- Echo's pipeline-config cache polls every ~30 s. Save the pipeline, wait a full cycle,
  then trigger. Otherwise the event is dropped silently — `202`, no execution, no logs.
- `202` from gate is optimistic. It means the event was queued, not that orca created an
  execution. Confirm with `GET /pipelines/{id}`; the first `GET` often returns `404`.
