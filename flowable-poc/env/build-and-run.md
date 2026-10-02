# Build and run the target

Everything below was executed on macOS 26.5.2 (arm64), JDK 17.0.20.1, Maven 3.9.16. The build is
from a clean checkout of the commit under test; nothing is patched.

---

## 1. Build

```bash
git clone https://github.com/flowable/flowable-engine.git
cd flowable-engine
git checkout 74fdb349c134e96e1f10592020ccca6e2e4b85f0

mvn -B -Pdistro -pl modules/flowable-app-rest -am install -DskipTests
```

Result: `BUILD SUCCESS`, 95 modules, ~3 min 21 s.

> **`-Pdistro` is required.** `modules/flowable-app-rest` is not in the default reactor; it exists
> only inside the `distro` and `deploy` profiles. Without the profile Maven reports
> `Could not find the selected project in the reactor`.

Artifact: `modules/flowable-app-rest/target/flowable-rest.war` (~95 MB, executable Spring Boot war).

## 2. Run

```bash
java -jar modules/flowable-app-rest/target/flowable-rest.war
```

Wait for `Started FlowableRestApplication` (about 3 s) and for this line, which confirms the
bootstrap administrator was created from the shipped defaults:

```
o.f.rest.conf.BootstrapConfiguration : No rest admin user found, initializing default entities
```

The application listens on port 8080 with context path `/flowable-rest`, and the shipped demo
process definitions are deployed automatically
(`flowable.rest.app.create-demo-definitions=true`).

To keep the database inside a scratch directory rather than `~/flowable-db`:

```bash
java -jar .../flowable-rest.war \
  --spring.datasource.url="jdbc:h2:/tmp/poc-db/ossdb;AUTO_SERVER=TRUE;AUTO_SERVER_PORT=9091;DB_CLOSE_DELAY=-1"
```

> The default datasource enables H2's `AUTO_SERVER`, which makes the database listen on all
> interfaces on port 9091 and write a connection key to `ossdb.lock.db` beside the database file.
> That is a separate finding, tracked as an issue rather than a vulnerability because reaching it
> requires local file access rather than end-user input. It is worth knowing about while building
> a lab, not while running one on a shared host.

## 3. Servlet prefixes

Discovered from `GET /actuator/mappings` with the default credential — do not assume these, they are
not all the values a reader would expect from the documentation:

| API | Prefix |
|---|---|
| BPMN / process | `/flowable-rest/service/` |
| CMMN | `/flowable-rest/cmmn-api/` |
| DMN | `/flowable-rest/dmn-api/` |
| IDM | `/flowable-rest/idm-api/` |
| App | `/flowable-rest/app-api/` |
| External worker | `/flowable-rest/external-job-api/` |
| Docs (anonymous) | `/flowable-rest/docs/` |

**The BPMN prefix is `/service/`, not `/process-api/`.** `flowable-default.properties:43` sets
`flowable.process.servlet.path=/service`, overriding the `FlowableProcessProperties` default of
`/process-api`. The documented path returns `404`. Every PoC here uses the path the artifact
actually answers on.

## 4. Run the proofs

```bash
cd flowable-poc

python3 poc/v1_deployment_rce.py       --base http://localhost:8080/flowable-rest --confirm-authorised
python3 poc/v2_serializable_deser.py   --base http://localhost:8080/flowable-rest --confirm-authorised
python3 poc/v3_worker_impersonation.py --base http://localhost:8080/flowable-rest --confirm-authorised
```

Each script:

- refuses to run without `--confirm-authorised`
- creates a throwaway principal holding only `access-rest-api`, confirms it is refused by
  `/actuator` with `403`, and **deletes the principal on exit**
- creates only objects it names `flowable-poc-*`
- prints the observed server response for each step
- exits non-zero if the finding does not reproduce

Pass `--no-provision` to supply your own scoped account instead of the throwaway one.

Python 3.8+, standard library only. No dependencies to install.

## 5. Verify the payloads independently

The V2 payload is a plain Java serialization stream. To confirm it is well-formed without running
the PoC:

```bash
base64 -d > /tmp/payload.ser <<'EOF'
rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdAAWZmxvd2FibGUtcG9jLXYyLW1hcmtlcng=
EOF

cat > /tmp/Check.java <<'EOF'
import java.io.ObjectInputStream; import java.io.FileInputStream;
public class Check { public static void main(String[] a) throws Exception {
  try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(a[0]))) {
    System.out.println("class = " + in.readObject().getClass().getName());
  }}}
EOF
javac -d /tmp /tmp/Check.java && java -cp /tmp Check /tmp/payload.ser
# class = java.util.ArrayList
```

The V1 payload is `env/payloads/flowable-poc-v1-groovy.bpmn20.xml` and is readable in full. It writes
one file under `java.io.tmpdir` and contains no network calls, process execution or data access.

## 6. Clean up

```bash
pkill -f flowable-rest.war
```

Remove the scratch database directory. Each PoC's own artifacts — the temporary account, the
deployed definitions, the process instances — are listed above and are safe to leave; none of them
affects a rebuilt database.

To reset completely, delete the database directory and start again. Note that the built war, the
`.m2` cache and the build tree are all in the checkout, so `git clean -xdf` from the repository root
removes the build outputs if you want a truly clean slate.
