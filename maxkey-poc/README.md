# MaxKey — proof-of-concept material

**Target** `dromara/MaxKey` — IAM / SSO platform (OAuth2 · OIDC · SAML 2.0 · CAS · JWT · SCIM)
**Versions tested** 4.2.0
**Commit tested** `3e5662b1a91291c0d85de826544119c86e77d8e6` (clean worktree)
**Disclosure state** **three findings reported to the vendor** via
[GitHub private vulnerability reporting](https://github.com/dromara/MaxKey/security/advisories/new);
**one finding not yet reported**. MaxKey publishes a `SECURITY.md` and has enabled private reporting, so
there is a private channel and a stated ~90 day coordination window. The `cve/*.cve.json` files carry
`CVE-PENDING-*` identifiers and `state: RESERVED`; **no CVE number has been allocated**.

> **If you run MaxKey, treat findings 1, 2 and 3 as live.** No fix has shipped for them, so there is
> nothing to upgrade to. The most urgent operator action is finding 1: any instance created from the
> shipped `deployment/docker/docker-compose.yml` and not rotated since is running with a public
> administrator credential. Finding 3 is a password dictionary — every directory-synced account in the
> deployment is affected at once.

MaxKey is not affected by findings 1, 3 or 4 unless a directory synchroniser is configured. Finding 2
requires the shipped database init script, which the documented installation path uses.

---

## Findings

| ID | Title | CWE | CVSS v3.1 | CVE | State |
|---|---|---|---|---|---|
| V1 | OAuth2 authorization endpoint matches `redirect_uri` by path prefix, leaking authorization codes to an attacker-chosen path on the relying party's own host | CWE-20 | **8.1** (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N) | *pending* | **reported** |
| V2 | Official MySQL init script provisions a working default administrator credential `admin`/`maxkey` | CWE-1188 | **9.8** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) | *pending* | **reported** |
| V3 | Directory-synced accounts are provisioned with a password that is a deterministic function of the username | CWE-1188 | **9.1** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) | *pending* | **reported** |
| V4 | OAuth2 password grant bypasses account lockout and ignores locked or deactivated account state | CWE-307 | **6.5** (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) | *pending* | **reported** |

The CVSS scores here are the reporter's own scoring of the source-traced impact. The vendor triages
severity independently; V1 was submitted as Moderate because the demonstrated precondition is weaker
than the base score suggests (see below).

### V1 — OAuth2 `redirect_uri` path-prefix match

`DefaultRedirectResolver.redirectMatches` requires protocol and host equality, then accepts the request
when the requested **path** is a string prefix of a registered path. RFC 6749 §3.1.2.3 and RFC 9700
§4.1.1 both require exact string comparison. A conforming `ExactMatchRedirectResolver` exists in the
same package and is dead code — the resolver is hardcoded and its setter has zero call sites.

Concretely, with a client registered at `https://rp.example.com/oauth/callback`, a request for
`https://rp.example.com/oauth/callback/attacker-controlled` is accepted and receives a real
authorization code. **This is not an arbitrary-host open redirect**: `URL.getPath()` excludes query and
fragment, and `cleanPath` neutralises `..`, so the attacker must already control some path on the
relying party's own registered domain. A client registered as a bare origin with no path is the worst
case, because the check degenerates to matching every path on that host.

**Severity note:** submitted as Moderate rather than the 8.1 the vector implies. The code is bound to
its client, the token endpoint requires client authentication, and PKCE neutralises the attack
entirely — but PKCE is auto-enabled only for the `OAUTH21` protocol while new applications default to
`OAUTH20`, so the unprotected case is the default one.

### V2 — default administrator credential

`maxkey.sql:1665` seeds the administrator with the stored password `{plain}maxkey`. The application
configures bcrypt, but the real `PasswordEncoder` bean is a `DelegatingPasswordEncoder` that registers
`plain` to `NoOpPasswordEncoder` and selects the validating encoder from the `{id}` prefix **on the
stored value**, so the bcrypt default does not apply. The account is enabled, unlocked, and in
`ROLE_ADMINISTRATORS`.

Only the pre-seeded row is affected — `encode()` uses the configured bcrypt default, so accounts
created through the application are hashed normally.

### V3 — deterministic password for directory-synced accounts

Every synchroniser sets `password = username + "MaxKey@888"`. The value **is** correctly bcrypt-hashed;
the weakness is that the plaintext is a pure function of two public values. The account is created
active, local login does not distinguish synchronised accounts, and re-synchronisation calls
`clearPassword()` so the derived hash persists indefinitely.

**This is the one finding now demonstrated by execution (harness D, 16/16 assertions).** It is
reproduced by running the product's *own* compiled classes — `LdapUsersService`,
`UserInfoServiceImpl`, `LoginServiceImpl`, `JdbcAuthenticationRealm`, 108 classes at commit `3e5662b`
— against a throwaway MySQL loaded with MaxKey's own `maxkey.sql` and a throwaway OpenLDAP holding
synthetic employees:

- `sync()` really provisions the account from a live directory.
- The stored hash is exactly `bcrypt(username + "MaxKey@888")`; `passwordEncoder.matches()` returns true.
- The `decipherable` column decodes, via MaxKey's own `PasswordReciprocal`, back to that same
  predictable string — the value is not only derivable, it is stored reversibly.
- The account comes back `ACTIVE`, unlocked, `badPasswordCount=0`, and **`passwordMatches()` accepts
  the derived password**. A wrong-password control is still rejected, so this is a real match.
- **No first-login rotation intervenes.** The `INITIAL_PASSWORD` marker is set, but the token is
  still issued and the marker only reaches the login response.

Part 2 of the same harness bounds the impact: an account whose password was already changed keeps
it across re-synchronisation, because `update()` calls `clearPassword()`. The exposure is therefore
confined to accounts that have never changed their MaxKey-local password — in practice, **every
account a synchroniser has ever created**.

### V4 — OAuth2 password grant bypasses lockout

The grant authenticates through a separate stack that never evaluates the lockout policy and never
increments the failure counter, so guessing is unbounded. Sharper still: `SignPrincipal` hard-codes
`accountNonLocked` and `enabled` to `true`, so Spring's own account-status check cannot reject a locked
or deactivated account. **Locking a compromised account does not stop token issuance for it.**

---

## Evidence

`evidence/` holds the verbatim captured output backing each claim, plus `RESULTS.md` which states
per-finding what is **runtime-proven** and what remains **source-inferred only**.

Reproduced locally (27/27 assertions, `evidence/harness-results/`):

- **Harness A** — `{plain}maxkey` is accepted by the real `DelegatingPasswordEncoder`; bcrypt
  controls behave correctly; `upgradeEncoding("{plain}maxkey")` returns `true`. Covers V2.
- **Harness B** — an independently written `javax.crypto` decryptor (referencing no MaxKey class)
  recovers a plaintext password from the `decipherable` column value plus the public constant.
- **Harness C** — the prefix-matching semantics: a sibling path sharing the prefix is accepted, while
  traversal and a foreign host are both rejected. Covers V1.
- **Harness D** — the synchroniser-to-login chain, end to end against real MySQL and real OpenLDAP,
  driving MaxKey's own compiled classes. Covers V3. Reproduce with `poc/harness-d/run-harness-d.sh`
  (needs Docker and network on first run; starts and removes its own containers).

**Not reproduced at the HTTP layer.** No finding is demonstrated through a booted MaxKey
application — the packaged app was never started, so `/signin` and JWT issuance were not exercised.
V1, V2 and V4 remain source-traced; V3 is runtime-proven one layer below HTTP, in the product's own
synchroniser, persistence and authentication classes. The `repro-*.sh` scripts exist to close the
HTTP gap and require a disposable instance.

> **Execution context.** These JVMs ran **unsandboxed**. `sandbox-exec` cannot confine a JVM in this
> environment (it aborts with SIGABRT), so no OS-level isolation was applied to any harness, and the
> absence of a sandbox is stated here rather than implied.
>
> **Correction to an earlier claim in this bundle.** A previous version of this README said the
> application "cannot be built offline: there is no Gradle cache and `org.dromara.mybatis-jpa-extra` is
> absent from every local repository", and treated that as the reason V3 had no runtime evidence. That
> was wrong. `mybatis-jpa-extra:3.4.6` **is** published on Maven Central — the earlier 404s came from
> probing the wrong version numbers. Once fetched, MaxKey's own classes compiled and ran, which is
> what produced harness D. The packaged application is still not booted here, so the HTTP layer remains
> unexercised, and the tenant-isolation findings that depend on `@PartitionKey` SQL generation remain
> unverified.

## Inertness

Every PoC here obeys the repository rule in `../README.md`: **a PoC demonstrates that a vulnerability is
reachable, it does not exploit it.**

- No shell execution, no reverse shell, no persistence.
- The harness decrypts **a dummy password the test itself generated** (`DummyPassw0rd!`), never a real
  one, and only to prove the cipher is invertible.
- The `repro-*.sh` scripts target **whatever host you point them at** and require
  `POC_I_HAVE_AUTHORIZATION=1` plus an explicit `MAXKEY_BASE_URL`; they refuse to run otherwise, and
  they classify an unreachable host or a captcha error as `INCONCLUSIVE` rather than "fixed" so a
  failed run can never be misread as a result.
- `env/two-tenant-seed.sql` creates **dummy** institutions and users for the cross-tenant test.

## Layout

```
maxkey-poc/
├── README.md      this file
├── cve/           CVE JSON 5.1 records, state RESERVED, CVE-PENDING-* identifiers
├── poc/           runnable proofs
│   ├── harness-a/ DelegatingPasswordEncoder probe      (V2)
│   ├── harness-b/ decipherable inversion probe        (background research)
│   ├── harness-c/ OAuth2 redirect prefix probe        (V1)
│   ├── harness-lib/ byte-identical MaxKey sources + portable classpath
│   ├── repro-*.sh  integration checks, need a running instance
│   ├── _lib.sh, run-harnesses.sh
├── env/           two-tenant seed SQL for the cross-tenant test
└── evidence/      verbatim captured output + RESULTS.md
```

## Running

The harnesses need a JDK and the jars named in `poc/harness-lib/classpath.txt` in a local Maven cache.
They contact no network and need no MaxKey instance:

```bash
cd poc && ./run-harnesses.sh
```

The `repro-*.sh` scripts need a disposable MaxKey instance. Read each script's header first.

## Credits

Reported privately to the MaxKey maintainers under their `SECURITY.md`. This repository is public by the
reporter's choice; the disclosure state above is the authoritative one — if it says "not yet reported",
the vendor has not been told.
