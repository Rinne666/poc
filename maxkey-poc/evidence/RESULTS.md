# RESULTS — what is actually proven, and what is not

Audit target: MaxKey, commit `3e5662b1a91291c0d85de826544119c86e77d8e6`.
Source tree: `/Users/rinne/Desktop/github/MaxKey`, treated as **read only**.

This document separates three things that are easy to blur together:

1. **RUNTIME-PROVEN** — executed here, output captured, reproducible.
2. **SOURCE-CONFIRMED** — read directly out of the code or SQL, quoted below.
3. **NOT PROVEN** — the gap, and exactly what closes it.

Nothing in section 2 or 3 should be described as demonstrated. Where a harness
initially failed, that is recorded rather than hidden.

---

## Environment constraints that shaped this pack

* The full MaxKey application **is not run here**. It is not buildable in this
  environment: no `~/.gradle`, and the application needs a packaged frontend
  plus a running Spring context. Harnesses A–C and D therefore drive the
  product's **own compiled classes** rather than the packaged application.
* **Network access was used for harness D only**, to fetch build-time
  dependencies from Maven Central (notably
  `org.dromara.mybatis-jpa-extra:3.4.6`, which was believed unavailable
  earlier in the audit — that belief was wrong and is corrected below).
  Harnesses A–C need no network: their jars come from the local `~/.m2`.
* **Docker was used for harness D only**, to run two **local** containers: a
  throwaway `mysql:8.0` loaded with MaxKey's own `maxkey.sql`, and a throwaway
  `osixia/openldap:1.5.0` holding two synthetic employees. Both are removed by
  the script on exit. No third-party or production system was contacted, and no
  real MaxKey deployment was targeted at any point.
* The MaxKey checkout was **never modified**. `git status --porcelain` was
  empty at the end of the work. Harness D compiles the project's classes
  **in place, read-only**, writing only to `harness-d/classes*`; harness A–C
  use sources copied *out* into `harness-lib/`, verified byte-identical by
  SHA-1.
* **The JVMs ran unsandboxed.** `sandbox-exec` cannot confine a JVM in this
  environment — it aborts with `SIGABRT`. No OS-level isolation was applied to
  any harness. The harnesses perform only string comparisons, local crypto and
  database writes against their own throwaway containers, but no sandbox claim
  is made.
* The `repro-*.sh` scripts and the seed SQL were **never executed against a
  real MaxKey instance**. Their safety guards, syntax and control flow *were*
  exercised, against a local mock server on `127.0.0.1` (see "Script
  validation" below).

### Correction: `mybatis-jpa-extra` was available

The audit originally recorded that `org.dromara.mybatis-jpa-extra` was absent
from the local Maven cache and that this blocked compiling MaxKey's real
classes. The artifact is in fact published on Maven Central
(`mybatis-jpa-extra:3.4.6`); the earlier 404s came from probing wrong version
numbers. Once downloaded, MaxKey's entity, synchroniser, persistence and
authentication classes all compiled cleanly, which is what made harness D
possible. Harness D's result therefore rests on the product's own compiled code
rather than on a reimplementation.

---

## Harness execution summary

| Harness | Checks | Failures | Exit | Captured output |
|---|---|---|---|---|
| A — DelegatingPasswordEncoder prefix semantics | 8 | 0 | 0 | `harness-results/harness-A-delegating-password-encoder.txt` |
| B — decipherable key inversion | 9 | 0 | 0 | `harness-results/harness-B-decipherable-inversion.txt` |
| C — redirect_uri prefix matching | 10 | 0 | 0 | `harness-results/harness-C-redirect-prefix.txt` |
| D — synchroniser-assigned local password (2 parts) | 8 + 8 | 0 | 0 | `harness-results/harness-D-sync-default-password.txt` |

Reproduce A–C with `./run-harnesses.sh` (no network, no running MaxKey
needed). Reproduce D with `harness-d/run-harness-d.sh` (needs Docker and
network on first run to fetch dependencies; starts and removes its own local
MySQL and OpenLDAP containers; needs no MaxKey instance).

### Two failures that occurred and were fixed

Recorded because a pack that only shows its final green run is not a
trustworthy pack.

1. **Harness A, first run: `ASSERTION 4` FAILED.** The positive control used a
   bcrypt test vector recalled from memory. It was simply the wrong constant —
   `BCrypt.checkpw("password", <vector>)` returned `false`, while a freshly
   generated hash round-tripped correctly. The library was not at fault. The
   control is now generated at runtime, which removes the dependency on a
   recalled constant entirely.
2. **Harness B, first run: `ASSERTION 5` and `ASSERTION 8` FAILED** with
   `IllegalBlockSizeException`. My independent decryptor decoded the ciphertext
   as Base64; `ReciprocalUtils.encode2Hex` hex-encodes it. After switching to
   hex, both assertions pass. The failure was in the harness, not the product —
   but it is worth noting that the *first* independent implementation did not
   work, and that MaxKey's own round-trip passing was never treated as
   sufficient evidence on its own.

---

## Finding 1 — `maxkey-20261002-seeded-admin-default-credential`

### RUNTIME-PROVEN

**The encoder semantics**, which is the one inference the whole finding rests
on. Real output, from `harness-results/harness-A-delegating-password-encoder.txt`:

```
[INFO] PasswordEncoder bean class : org.springframework.security.crypto.password.DelegatingPasswordEncoder
[INFO] 'plain' resolves to        : org.dromara.maxkey.crypto.password.NoOpPasswordEncoder
[INFO] default encode id          : bcrypt
[INFO] registered encoder ids     : [bcrypt, ldap, md4, md5, pbkdf2, plain, scrypt, sha1, sha256, sha384, sha512, sm3]
[INFO] seeded stored value        : {plain}maxkey

PASS  ASSERTION 1  matches("maxkey", "{plain}maxkey") == true
PASS  ASSERTION 2  matches("wrongpass", "{plain}maxkey") == false
PASS  ASSERTION 3  matches("maxkey", "{bcrypt}$2a$10$...") == false   (control)
PASS  ASSERTION 4  matches("DummyNotTheSeeded0", its {bcrypt} hash) == true  (positive control)
PASS  ASSERTION 5  fresh encode() is prefixed {bcrypt}
PASS  ASSERTION 6  fresh encode() round-trips through matches()
PASS  ASSERTION 7  a fresh {bcrypt} value differs from the seeded {plain} value
PASS  ASSERTION 8  "{plain}maxkey" minus its prefix is literally the login password
 checks run: 8, failures: 0
 RESULT: PASS
```

Two things make this evidence rather than a restatement of the claim:

* It uses **MaxKey's own** `org.dromara.maxkey.crypto.password.NoOpPasswordEncoder`,
  not Spring's built-in. `ApplicationAutoConfiguration` imports MaxKey's copy,
  and MaxKey's is a bare `rawPassword.toString().equals(encodedPassword)`.
  Substituting Spring's class would have been an unfaithful test.
* Assertions 3 and 4 are controls in opposite directions. Assertion 3 shows the
  `{bcrypt}` id rejects the raw string, which isolates the `{id}` prefix as the
  cause. Assertion 4 shows the matcher succeeds in the true direction, so
  assertion 3 is a real rejection and not a dead harness.

**Also proven:** assertion 8 shows the exposure is specific to the `{plain}` id.
Under every other registered id the stored value is an opaque digest:

```
[INFO]   id=md5     stored-value-contains-plaintext=false  matches("maxkey")=true
[INFO]   id=sha256  stored-value-contains-plaintext=false  matches("maxkey")=true
[INFO]   id=ldap    stored-value-contains-plaintext=false  matches("maxkey")=true
[INFO]   id=bcrypt  stored-value-contains-plaintext=false  matches("maxkey")=true
[INFO]   id=pbkdf2  stored-value-contains-plaintext=false  matches("maxkey")=true
[INFO]   id=scrypt  stored-value-contains-plaintext=false  matches("maxkey")=true
```

And `encode()` uses the *configured* default id, so **newly created users are
not affected** (assertion 5). The finding is correctly scoped to the pre-seeded
row. `upgradeEncoding("{plain}maxkey")` returns `true`, meaning the row is
flagged for upgrade but nothing upgrades it automatically.

### SOURCE-CONFIRMED (not executed)

* The seed row itself. `deployment/docker/docker-mysql/docker-entrypoint-initdb.d/latest/maxkey.sql:1665`:
  `INSERT INTO \`mxk_userinfo\` VALUES ('1','admin','{plain}maxkey','',0,...)`.
  Read directly; that line is ~893 KB because of an embedded avatar blob.
* The bean wiring. `maxkey-starter/maxkey-starter-web/.../autoconfigure/ApplicationAutoConfiguration.java`
  registers `encoders.put("plain", NoOpPasswordEncoder.getInstance());` and
  constructs `new DelegatingPasswordEncoder(idForEncode, encoders)` with
  `idForEncode = ${maxkey.crypto.password.encoder:bcrypt}`.
* `STATUS=1`, `ISLOCKED=1` on the seeded row, and membership of
  `ROLE_ADMINISTRATORS`.

### NOT PROVEN — and what closes it

**That the running product actually accepts this credential end to end.** The
harness proves the encoder would accept it; it never starts MaxKey, never reads
a live database, and never performs a login.

To close the gap, on a disposable instance:

```sh
POC_I_HAVE_AUTHORIZATION=1 POC_TARGET_HOST=http://127.0.0.1:8080 \
  ./repro-default-admin.sh
```

And confirm the instance still carries the shipped row first:

```sql
SELECT ID, USERNAME, PASSWORD, STATUS, ISLOCKED, INSTID
  FROM mxk_userinfo WHERE ID = '1';
-- PASSWORD must be '{plain}maxkey' for the test to mean anything.
```

---

## Finding 2 — `maxkey-20261002-sync-default-password`

### RUNTIME-PROVEN

**Executed end to end by harness D.** Output:
`harness-results/harness-D-sync-default-password.txt` (2 parts, 8/8 PASS
each). Reproduce with `harness-d/run-harness-d.sh`.

Harness D starts a throwaway MySQL loaded with MaxKey's **own** `maxkey.sql`
(44 tables) and a throwaway OpenLDAP holding two synthetic employees, then
compiles the product's **own** classes at commit `3e5662b` — 108 classes,
including `LdapUsersService`, `UserInfoServiceImpl`, `LoginServiceImpl` and
`JdbcAuthenticationRealm` — and drives them.

Part 1, a newly synced account:

```
[sync] new local row for zhangsan (hashed by the product's UserInfoServiceImpl.insert())
[sync] new local row for lisi    (hashed by the product's UserInfoServiceImpl.insert())

PASS  bcrypt hash in the DB equals bcrypt("zhangsanMaxKey@888")
        -- the derived password IS the stored password
PASS  decipherable column decodes back to the same predictable string
        -- decoded = "zhangsanMaxKey@888"
PASS  LoginServiceImpl.find() returns the synchronised account
        -- loaded status=1 isLocked=0
PASS  account is ACTIVE (ConstsStatus.ACTIVE == 1)
PASS  account is not locked
PASS  bad-password count does not block the attempt
PASS  JdbcAuthenticationRealm.passwordMatches() accepts the derived password
        -- passwordMatches() returned true
PASS  a wrong password is still rejected (control)
        -- BadCredentialsException: login.error.password
RESULT: 8 passed, 0 failed
```

What this closes, and what it does not:

* The synchroniser really does run end to end against a live directory, and
  `UserInfoServiceImpl.passwordEncoder()` really does turn
  `username + "MaxKey@888"` into the stored bcrypt hash. No reimplementation:
  those are the product's compiled classes.
* `decipherable` stores the same string, recoverable with MaxKey's own
  `PasswordReciprocal` — so the predictable value is not merely derivable, it
  is *stored* reversibly.
* **No first-login rotation intervenes.** The account is `ACTIVE`, not locked,
  bad-password count is 0, and `passwordMatches()` accepts the derived value.
  This was the specific open question, and it is now answered by execution
  rather than by absence of code.
* The **last assertion is a control**: a wrong password is still rejected, so
  the acceptance above is a real match and not a permissive harness.

Part 2 bounds the blast radius, and is equally important:

```
PASS  on re-sync, an already-existing account keeps its own password
        (update() does not re-apply the derived default)
        -- scope is NEWLY synced accounts
PASS  re-sync mode: the derived password is correctly REJECTED now
        -- rejected with BadCredentialsException
RESULT: 8 passed, 0 failed
```

An account that already has a user-chosen password is **not** reset by a
subsequent sync, because `UserInfoServiceImpl.update()` calls
`clearPassword()`. So the exposure is confined to accounts that have never
changed their MaxKey-local password — in practice, **every account a
synchroniser has ever created**, since the derived password is what the
synchroniser hands them.

### Scope of the harness

Real: the LDAP search and user build, `UserInfo.DEFAULT_PASSWORD_SUFFIX`,
`passwordEncoder()`, `PasswordReciprocal`, the `DelegatingPasswordEncoder`
built by `ApplicationAutoConfiguration`, `LoginServiceImpl.find()`,
`JdbcAuthenticationRealm.passwordMatches()`, the schema, the seed data.
Replaced with plumbing: the MyBatis mapper layer (plain JDBC against the same
`mxk_userinfo` table), `OrganizationsService` (a JDBC read of the real
`mxk_organizations`), and the sync/audit bookkeeping services (no-op proxies
that never touch the password). The Spring context is not started. Full detail
in `harness-d/README.md`.

### NOT PROVEN

* That any particular deployment has a synchroniser enabled. This is a
  configuration-dependent issue; the finding describes what the code does
  when one is configured.
* End-to-end login through the packaged application (HTTP `/signin` → JWT).
  Harness D calls the same `passwordMatches()` the provider calls, but does
  not boot the Spring application. `repro-sync-default-password.sh` closes
  this against a real instance you control:

```sh
POC_I_HAVE_AUTHORIZATION=1 POC_TARGET_HOST=http://127.0.0.1:8080 \
  POC_SYNC_USERNAME=<a genuinely synced dummy user> \
  ./repro-sync-default-password.sh
```

Distinguish "never synced" from "synced then rotated" with:

```sql
SELECT USERNAME, LEFT(PASSWORD,7), PASSWORDSETTYPE, PASSWORDLASTSETTIME
  FROM mxk_userinfo WHERE USERNAME = '<user>';
```

A `PASSWORDSETTYPE` of 0 with an old `PASSWORDLASTSETTIME` is the fingerprint
of an account still sitting on the synchroniser's default.

---

## Finding 3 — `maxkey-20261002-rest-cross-tenant-no-instid`

### RUNTIME-PROVEN

**Nothing about the live system.** Harness C is *not* evidence for this finding;
it concerns OAuth2 redirect matching and is listed separately below.

### SOURCE-CONFIRMED (not executed)

* Both mapper methods exist, and only one is scoped.
  `maxkey-persistence/src/main/java/org/dromara/maxkey/persistence/mapper/UserInfoMapper.java`:
  * line 42 — `@Select("select * from mxk_userinfo where username = #{username} and status = ACTIVE")`
    `UserInfo findByUsername(String username);`  ← **no `instid` predicate**
  * line 45 — `... and instid = #{instId} and status = ACTIVE`
    `UserInfo findByUsernameAndInstId(String username, String instId);`  ← scoped, and unused by the REST path
* The REST controller uses the unscoped one:
  `maxkey-web-apis/maxkey-web-api-rest/.../rest/RestUserInfoController.java:62` (create)
  and `:75` (update), both `userInfoService.findByUsername(userInfo.getUsername())`.
* The list endpoint trusts a caller-supplied tenant:
  `RestUserInfoController.java:91-98` — `if (StringUtils.isBlank(userInfo.getInstId())) { userInfo.setInstId("1"); }`.
  The tenant is only *defaulted* when absent; a supplied `instId` is believed.
* Schema context from `sql/v4.2.0/maxkey.sql:1588`: `mxk_userinfo` has a NOT
  NULL `INSTID` **and** `UNIQUE KEY USERNAME_UNIQUE (USERNAME)`. So the tenant
  boundary is a real column, but the unscoped query ignores it. The globally
  unique username is what makes the unscoped lookup unambiguous — and is also
  why the flaw cannot be dismissed as "it would be ambiguous anyway".

### NOT PROVEN — and what closes it

That a tenant-A operator can actually reach tenant-B data. Needs a
multi-institution instance and a genuinely lower-privileged tenant-A
credential. With the built-in superadmin the test proves only the missing
filter, **not** privilege separation — this caveat is repeated inside the
script.

To close the gap:

```sh
mysql -h HOST -u USER -p DBNAME < seed/two-tenant-seed.sql

POC_I_HAVE_AUTHORIZATION=1 POC_TARGET_HOST=http://127.0.0.1:8080 \
  POC_ADMIN_USER=<tenant-A operator> POC_ADMIN_PASS=... \
  ./repro-cross-tenant.sh
```

The strongest evidence needs no HTTP at all — run the unscoped and scoped
statements by hand and show the first returns a tenant-B row while the second
returns none. The script prints this pair.

---

## Finding 4 — `maxkey-20261002-oauth2-password-grant-no-lockout`

### RUNTIME-PROVEN

**Nothing about the live system.**

### SOURCE-CONFIRMED (not executed)

* The interactive login stack calls the policy/lockout hook:
  * `NormalAuthenticationProvider.java:90`
  * `MfaAuthenticationProvider.java:91`
  * `AppAuthenticationProvider.java:87`
    all calling `authenticationRealm.getLoginService().passwordPolicyValid(userInfo);`
  * `LoginServiceImpl.java:139` — `public boolean passwordPolicyValid(UserInfo userInfo)`
  * `TrustedAuthenticationProvider.java:64` — the call is **commented out**
* The OAuth2 password grant uses a different provider that never reaches that
  code:
  * `Oauth20AutoConfiguration.java:335-338` builds
    `OAuth2UserDetailsService` + `DaoAuthenticationProvider`
  * `ResourceOwnerPasswordTokenGranter.java:62-75` calls
    `authenticationManager.authenticate(...)` and throws
    `InvalidGrantException` on failure. No `passwordPolicyValid` appears
    anywhere on this path — confirmed by searching the whole tree for
    `passwordPolicyValid`, which returns only the four provider call sites
    above plus the interface declaration.
* The principal hard-codes the lock flags:
  `maxkey-authentications/maxkey-authentication-core/.../SignPrincipal.java:73-77`
  sets `accountNonLocked = true`, `credentialsNonExpired = true`,
  `enabled = true` unconditionally.

### NOT PROVEN — and what closes it

That the lockout counter is genuinely untouched by this path, and that the
correct password keeps working afterwards. Two distinct sub-claims that a
screenshot of "many failed logins" would not settle.

To close the gap:

```sh
POC_I_HAVE_AUTHORIZATION=1 POC_TARGET_HOST=http://127.0.0.1:8080 \
  POC_OAUTH_CLIENT_ID=... POC_OAUTH_CLIENT_SECRET=... \
  POC_ATTEMPTS=20 ./repro-oauth2-lockout.sh
```

The decisive step is phase 3: re-submitting the **correct** password. Then
cross-check the database, which distinguishes the two mechanisms:

```sql
SELECT USERNAME, BADPASSWORDCOUNT, ISLOCKED FROM mxk_userinfo
 WHERE USERNAME = 'poc_tenant2_user';
```

`unsupported_grant_type` means the grant is disabled — a configuration state,
**not** a fix, and the script reports it as inconclusive.

---

## Finding 5 — `maxkey-20261002-decipherable-selfkeyed-desede`

### RUNTIME-PROVEN

**The key inversion itself**, which is the whole substance of this finding.
Real output, from `harness-results/harness-B-decipherable-inversion.txt`:

```
[INFO] public constant from ReciprocalUtils.java:49 = "l0JqT7NvIzP9oRaG4kFc1QmD_bWu3x8E5yS2h6"
[INFO] dummy password used                      = "DummyPassw0rd!"

[INFO] stored column value = $2a$10$ZaBnv.mH2iZ/Utdttgv9F.4107e33f8cb230d74ca28317167a5a96ab1e02604d3153a1ce5f7af09a8d7c16b0dae9b9779250a5
[INFO] decoder(stored)     = "DummyPassw0rd!"
PASS  ASSERTION 1  encode() then decoder() recovers the plaintext
PASS  ASSERTION 2  the stored value does NOT contain the plaintext verbatim

[INFO] salt.substring(7) (embedded key)   = ZaBnv.mH2iZ/Utdttgv9F.
[INFO] publicKey[0..2]                    = "l0"
[INFO] derived 3DES key (24 bytes)        = ZaBnv.mH2iZ/Utdttgv9F.l0
PASS  ASSERTION 3  derived key is exactly 24 bytes (DESede requirement)
PASS  ASSERTION 4  derived key == salt[7..29] + publicConstant[0..2]

--- SECTION 3: INDEPENDENT decryption (raw javax.crypto, no MaxKey code) ---
[INFO] recovered plaintext     = "DummyPassw0rd!"
PASS  ASSERTION 5  an independent 3DES decryptor recovers the plaintext from the column value + public constant

PASS  ASSERTION 6  three encode() calls on the same plaintext yield three different stored values (random salt)
PASS  ASSERTION 7  all three decode correctly (MaxKey decoder)
PASS  ASSERTION 8  all three decode correctly (independent decryptor)

[INFO] decrypt with a wrong 2-char guess -> "<decryption failed: BadPaddingException>"
PASS  ASSERTION 9  a wrong trailing 2 chars yields garbage, so the constant is the only unknown
 checks run: 9, failures: 0
 RESULT: PASS
```

**Assertion 5 is the load-bearing one, and it is deliberately not circular.**
Section 3 implements the decryption from scratch with raw `javax.crypto` and
references no MaxKey class. MaxKey's own `decode()` round-tripping (assertion
1) would not have been sufficient evidence on its own — a self-consistent but
wrong implementation would also round-trip. Because the independent
implementation succeeds, the key derivation is confirmed.

Assertion 9 shows the trailing two characters are the *only* unknown, and they
are the first two characters of a constant published in the open-source
repository — so they are not a secret in any meaningful sense.

The derived key is `salt[7..29]` (22 chars, carried inside the stored value)
plus `defaultKey[0..2]` (2 chars), truncated to the 24 bytes DESede requires.
Everything needed to decrypt is the column value plus the public constant.

### SOURCE-CONFIRMED (not executed)

* `ReciprocalUtils.java:49` —
  `private static final String defaultKey = "l0JqT7NvIzP9oRaG4kFc1QmD_bWu3x8E5yS2h6";`
* The write path stores the reversible form of the real password:
  * `UserInfoServiceImpl.java:209` —
    `changePassword.setDecipherable(PasswordReciprocal.getInstance().encode(changePassword.getPassword()));`
  * `RegisterController.java:114` — same for self-registration.
* The server itself decrypts it: `AuthorizeBaseEndpoint.java:96` —
  `PasswordReciprocal.getInstance().decoder(userInfo.getDecipherable())`.
* The same primitive protects other secrets, which widens the impact:
  `SocialSignOnProviderService.java:240` (OAuth client secret),
  `SmsOtpAuthnService.java:72/78/84` (SMS provider app secrets),
  `MailOtpAuthnService.java:60` and `SmsOtpAuthnService.java:90` (email
  credentials), `TimeBasedOtpAuthn.java:61` (TOTP shared secrets).

### NOT PROVEN — and what closes it

That any live database contains such a row, and that the write path is reached
in a real deployment.

To close the gap, on a disposable instance, read a real row and decrypt it with
Harness B's section 3 (see README, "Proving finding 5 against your own data"):

```sql
SELECT USERNAME, DECIPHERABLE FROM mxk_userinfo WHERE USERNAME = 'poc_tenant2_user';
```

The seed SQL already ships a real `DECIPHERABLE` value for the dummy user, and
it decrypts to `DummyPassw0rd!` — so this specific instance is already
satisfiable without touching a real user.

Note that `RestUserInfoController.java:55` nulls `decipherable` before
returning a user over REST, so this is **not** reachable through that API
endpoint. The exposure is via direct database access, a SQL-injection
elsewhere, a backup, or a replica — not via the REST API.

---

## Supplementary — OAuth2 `redirect_uri` prefix matching

Not one of the five primary findings; included because it was requested.

### RUNTIME-PROVEN

From `harness-results/harness-C-redirect-prefix.txt`, 10 checks, all PASS:

```
PASS  ASSERTION 1  cleanPath("/callbackXYZ").startsWith(cleanPath("/callback")) == true
PASS  ASSERTION 2  cleanPath("/cb/../x") neutralises traversal to "/x"
[INFO]   match(https://app.example.com/callback             ) = true
[INFO]   match(https://app.example.com/callbackXYZ          ) = true
[INFO]   match(https://app.example.com/callback.evil.test/  ) = true
[INFO]   match(https://app.example.com/callback/../admin    ) = false
[INFO]   match(https://app.example.com/other                ) = false
[INFO]   match(https://evil.test/callback                   ) = false
PASS  ASSERTION 5  a SIBLING path sharing the string prefix also matches  <-- the finding
PASS  ASSERTION 6  a host smuggled after the prefix also matches  <-- the finding
PASS  ASSERTION 8  the same path on a DIFFERENT host does NOT match (host is still checked)
PASS  ASSERTION 9  a traversal path is cleaned first, so it resolves to /admin and does NOT match
PASS  ASSERTION 10 exact-match semantics REJECT the sibling path (String.equals)
```

Faithfully reproduced from
`maxkey-protocols/maxkey-protocol-oauth-2.0/.../DefaultRedirectResolver.java:108`
using spring-core 7.0.8, the version declared in `gradle.properties`.

**Be precise about what this does and does not show.** The harness shows that
a registered `https://app.example.com/callback` also matches
`…/callbackXYZ` and `…/callback.evil.test/`. It does **not** show that
`callback.evil.test` is reachable as a host — assertions 8 and 9 make clear
that the host and traversal are still checked; the weakness is specifically the
*string-prefix* path match, not a full redirect bypass. The class javadoc
states the prefix behaviour is intentional, so the finding is about the
security consequence of that design, not a coding slip.

Incidental: `new URL(String)` is deprecated in Java 26 and the compiler warns
on it at the exact line the product uses. `StringUtils.cleanPath` itself is
not deprecated.

### NOT PROVEN

That any deployed client registration is exploitable. That needs a real
authorization request against a live instance.

---

## Script validation (what *was* tested about the unexecuted scripts)

The `repro-*.sh` scripts were never run against MaxKey, but they were not
merely eyeballed either. Verified here:

* `bash -n` syntax check on all five shell files — clean.
* **All three safety-guard branches**, each exiting 2 with `REFUSING TO RUN`:
  no opt-in, opt-in without host, and opt-in against a routable public host.
* **A local mock HTTP server on `127.0.0.1`** (a throwaway Python file, not
  MaxKey) to prove the scripts read bodies and classify verdicts correctly:
  * a token-bearing 200 → `[VULNERABLE]`
  * a 401 → `[FIXED]`
  * a captcha error → `[INCONCLUSIVE]`, **not** `[FIXED]`
  * an unreachable port → `[INCONCLUSIVE]` with "NO VERDICT WAS REACHED", exit 4

Three real defects were found and fixed this way, all of which would have
produced a **misleading report**:

1. `poc_curl` is invoked as `CODE=$(poc_curl ...)`, so it runs in a subshell
   and every variable it assigned was lost in the parent — `poc_body()` was
   reading an empty path, so **no body-based assertion was working at all**.
   Fixed by writing body, stderr and reachability to deterministic per-PID
   files that survive the subshell.
2. A refused TCP connection was scored as `[FIXED]`. A harness that reports
   "fixed" because nothing was listening is worse than no harness. Fixed with
   an explicit reachability check.
3. A captcha error was scored as `[FIXED]`. Now `[INCONCLUSIVE]`.

The mock server is retained at
`harness-results/_mock_login_server.py` for re-testing. It is **not** MaxKey.

---

## Honest bottom line

| Finding | RUNTIME-PROVEN | SOURCE-CONFIRMED | Needs a live instance |
|---|---|---|---|
| 1 — seeded admin default credential | **Encoder semantics** (8/8) | Seed row, bean wiring, role membership | The login itself |
| 2 — sync default password | **harness D (16/16)** | Constant + 5 call sites | A synced account's live login response |
| 3 — REST cross-tenant, no instId | none | Unscoped mapper + controller + schema | Two-tenant reachability |
| 4 — OAuth2 password grant, no lockout | none | Missing policy call + SignPrincipal flags | N attempts + counter state |
| 5 — decipherable self-keyed 3DES | **Key inversion** (9/9, independent) | Constant, write path, read path | A real row in a real DB |
| (redirect prefix) | **Prefix semantics** (10/10) | Resolver source | A live authorization request |

Findings 1 and 5 — the two with the strongest technical content — now have
genuine runtime evidence for their decisive mechanisms. Findings 2, 3 and 4
remain **entirely source-inferred**; for those the honest statement is that the
code paths were read and the call graph confirmed, not that behaviour was
observed.

No finding should be reported to a vendor or a CVE programme as demonstrated
end-to-end until the corresponding `repro-*.sh` has been run against a
disposable instance and its output pasted in.
