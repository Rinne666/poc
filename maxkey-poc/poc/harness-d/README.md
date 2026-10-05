# Harness D — synchroniser-assigned local password

**Finding:** every user pulled in by a synchroniser (LDAP / AD / Dingtalk /
Feishu / WeCom) is given a local MaxKey password of
`username + "MaxKey@888"`, and that account is immediately usable for an
ordinary local login.

**This harness was executed by the audit.** Its output is in
`../harness-results/harness-D-sync-default-password.txt` (2 parts, all
assertions PASS). Unlike harness C, this one does not need a running MaxKey
instance — it needs two local containers, which the harness itself starts.

## What actually runs

| Component | Real or replaced |
| --- | --- |
| `LdapUsersService.sync()` — the LDAP search and user build | **real**, MaxKey source |
| `LdapUsersService.buildUserInfo()` — attribute mapping | **real** |
| `UserInfo.DEFAULT_PASSWORD_SUFFIX = "MaxKey@888"` | **real** |
| `UserInfoServiceImpl.passwordEncoder(UserInfo)` — the hashing step | **real** |
| `PasswordReciprocal` — the `decipherable` column | **real** |
| `DelegatingPasswordEncoder("bcrypt", …)` — as built by `ApplicationAutoConfiguration` | **real** |
| `LoginServiceImpl.find()` — the login lookup | **real** |
| `JdbcAuthenticationRealm.passwordMatches()` — the password check | **real** |
| `mxk_userinfo` schema + seed data | **real**, the project's own `maxkey.sql` |
| MySQL / OpenLDAP | local containers started by `run-harness-d.sh` |
| `UserInfoServiceImpl.saveOrUpdate` row plumbing (MyBatis mapper) | replaced with plain JDBC against the same table |
| `OrganizationsService.find()` | replaced with a JDBC read of the real `mxk_organizations` |
| `SynchroRelatedService`, `HistorySynchronizerService`, `HistoryLoginService` | no-op proxies (bookkeeping only; they never touch the password) |
| Spring context / MyBatis bootstrap | not started |

The replacements are plumbing only. Every line that decides **what password is
stored** and **whether a password is accepted** is MaxKey's own compiled code at
commit `3e5662b`, unmodified.

## Result

Part 1 — a newly synced account:

```
[sync] new local row for zhangsan (hashed by the product's UserInfoServiceImpl.insert())
password column : {bcrypt}$2a$10$xhtH0MrOlapqgTFF2YTSYO9DpUhmD0Jx4WVO4fz.3/9n64OQLZqz2
[PASS] bcrypt hash in the DB equals bcrypt("zhangsanMaxKey@888")
[PASS] decipherable column decodes back to the same predictable string
[PASS] LoginServiceImpl.find() returns the synchronised account
[PASS] account is ACTIVE (ConstsStatus.ACTIVE == 1)
[PASS] account is not locked
[PASS] JdbcAuthenticationRealm.passwordMatches() accepts the derived password
[PASS] a wrong password is still rejected (control)
RESULT: 8 passed, 0 failed
```

Part 2 — an account whose password the user already changed: the re-sync
leaves the stored hash alone, because `UserInfoServiceImpl.update()` calls
`clearPassword()`. **The exposure is therefore scoped to accounts that have
never changed their MaxKey-local password** — in practice, every account the
synchroniser has ever created.

## Running it

```bash
./run-harness-d.sh
```

Needs: a JDK 17+, Docker, and network access to Maven Central on first run
(it downloads `mybatis-jpa-extra` and friends into `harness-d/lib/`). No MaxKey
instance, no third-party system, and no credentials are required.

## Scope and honesty

- The MySQL and OpenLDAP instances are **local containers started by this
  script**. No production or third-party MaxKey deployment was contacted.
- The probe proves what the code does when a synchroniser is configured. It
  does not claim that any particular deployment has an LDAP synchroniser
  enabled.
- The `update()` finding in Part 2 bounds the impact; it is not a mitigation of
  the finding, only a scope limit.
