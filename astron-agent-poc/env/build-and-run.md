# Building and running the target

All three findings were reproduced against a local, unmodified deployment of
`iflytek/astron-agent`. Nothing here touches a third-party deployment.

## Target

```
git clone https://github.com/iflytek/astron-agent
cd astron-agent
git checkout b4f8ed57460cbfb32016a4afd3fd7212987d33c3   # main commit tested
# release v1.1.2 was verified to contain the same code paths
```

## Starting the stack

```
cd docker/astronAgent
docker compose -f docker-compose.yaml -f docker-compose.override.yaml up -d
```

Notes recorded during testing:

- The stock stack was used unmodified, with one image override pinning `minio` to a
  locally available image. No security-relevant setting was changed.
- The PostgreSQL service ships `POSTGRES_USER=spark` / `POSTGRES_PASSWORD=spark123`
  (docker-compose.yaml:145); the official postgres image creates that role as a
  superuser. This matters for V1's context, and it is a stock setting of this
  repository, not a test modification.
- Service DNS names inside the compose network (`astron-agent-network`):
  `core-database:7990`, `core-workflow:7880`, `console-hub:8080`, `nginx` (public
  entry). None of `core-database`'s or `core-workflow`'s ports are published to the
  host by default.
- The PoC scripts use only the Python standard library. Run them inside the network,
  e.g.:

```
docker run --rm -i --network astron-agent-network -v "$PWD/../poc":/poc:ro \
    python:3-alpine python /poc/v1_ddl_whitelist_comment_smuggling.py \
    --base http://core-database:7990 --confirm-authorised
```

or `docker exec` into any container on the network with python available.

## V1 — DDL whitelist bypass

No preparation beyond the running stack: the PoC creates its own database through
the unauthenticated `/xingchen-db/v1/create_database` route and drops it on exit.

## V2 — space-id knowledge read

On the target deployment, using the Console:

1. Create two ordinary (non-admin) test users, A (attacker) and B (victim).
2. As B, upload a knowledge file whose parsed content contains the benign marker
   `TEST_KNOWLEDGE_MARKER`. Record B's file id.
3. Obtain A's Console JWT by signing in as A through the deployment's normal login.
4. Run:

```
python3 poc/v2_knowledge_space_id_bypass.py --base http://<console-api> \
    --jwt "$JWT_OF_A" --victim-file-id <B's file id> --confirm-authorised
```

Expect: step 1 (no header) does not return B's knowledge; step 2 (`space-id: 1`)
does.

## V3 — resume cross-app ownership gap

Heavier preparation, all on your own deployment:

1. Register two applications against the tenant service (for example through the
   Console's application management). Record each app's key and secret:
   one is the victim app, the other the attacker app.
2. Seed the victim flow with `env/payloads/seed_victim_flow.sql` (fill in the
   placeholders), owned by the victim app. The question-answer node must have
   `needReply: true` and `directAnswer.handleResponse: false` so the run pauses with
   an INTERRUPT event.
3. Release the flow (re-save it from the Console designer on your build so
   `release_status`/`release_data` are produced), and bind the victim app's license
   for the flow group the way your deployment does it.
4. Run:

```
python3 poc/v3_workflow_resume_event_authz.py --base http://core-workflow:7880 \
    --victim-credential "$VICTIM_KEY:$VICTIM_SECRET" \
    --attacker-credential "$ATTACKER_KEY:$ATTACKER_SECRET" \
    --flow-id <seeded flow id> --confirm-authorised
```

Expect: the victim's stream shows the INTERRUPT frame with `event_id`; the attacker
app's `/workflow/v1/resume` with that id is accepted and the engine's post-resume
output flows on the attacker's connection.

The production-path reproduction requires the model domain configured for the
question-answer node (placeholder in the seed). The pause-then-resume mechanics are
the finding; the model behind the node is not.
