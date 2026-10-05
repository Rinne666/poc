-- =============================================================================
--  two-tenant-seed.sql
--
--  ###########################################################################
--  #  NOT EXECUTED BY THE AUDIT.                                          #
--  #  This SQL was WRITTEN but NEVER RUN. The audit environment had no     #
--  #  MaxKey instance and no database. Nothing in this file has been       #
--  #  applied to any system, and none of the expected outcomes below have  #
--  #  been observed.                                                       #
--  ###########################################################################
--
--  PURPOSE
--    Creates a SECOND institution ("tenant") plus a dummy user inside it, so
--    that finding maxkey-20261002-rest-cross-tenant-no-instid has something
--    concrete to act on.
--
--      finding 3: the REST /api/idm/Users handler resolves users through the
--                 UNSCOPED mapper method
--                   UserInfoMapper.java:42
--                     @Select("select * from mxk_userinfo where username = #{username}
--                              and status = ACTIVE")
--                     UserInfo findByUsername(@Param("username") String username);
--                 while a correctly scoped sibling exists and is NOT used by
--                 the controller:
--                   UserInfoMapper.java:45
--                     ... where username = #{username} and instid = #{instId} ...
--                     UserInfo findByUsernameAndInstId(username, instId);
--                 and RestUserInfoController.java:62 / :75 call the unscoped one.
--                 The .search handler (RestUserInfoController.java:91-98)
--                 additionally accepts a caller-supplied `instId` and only
--                 DEFAULTS it to "1" when blank.
--
--  SCHEMA BASIS
--    Column lists and types are taken from the real schema in
--      sql/v4.2.0/maxkey.sql
--        mxk_institutions     (line 916)
--        mxk_organizations    (line 997)
--        mxk_userinfo         (line 1588)
--        mxk_roles            (line 1315)
--        mxk_role_member      (line 1286)
--    NOT NULL columns verified against that DDL:
--        mxk_institutions  : ID, NAME
--        mxk_organizations : ID, ORGNAME, INSTID
--        mxk_userinfo      : ID, USERNAME, PASSWORD, DECIPHERABLE, INSTID
--        mxk_roles         : ID, INSTID
--        mxk_role_member   : ID, ROLEID, MEMBERID, TYPE, INSTID
--
--  IMPORTANT SCHEMA NOTE
--    mxk_userinfo has  UNIQUE KEY USERNAME_UNIQUE (USERNAME)  — usernames are
--    GLOBALLY unique across every institution, and every row carries a NOT NULL
--    INSTID. So the tenant boundary is a column, but the unscoped lookup does
--    not filter on it. That is precisely the gap this seed is built to expose.
--
--  ALL CREDENTIALS BELOW ARE THROWAWAY DUMMY VALUES.
--    Username            : poc_tenant2_user
--    Password            : DummyPassw0rd!        (a throwaway string, not a secret)
--    PASSWORD column     : a real bcrypt hash of that dummy string
--    DECIPHERABLE column : a real PasswordReciprocal ciphertext of that string,
--                          i.e. the reversible form described in finding 5. It is
--                          included deliberately so the row is fully realistic.
--    Both were generated locally by the audit harness, not copied from any real
--    system. Neither value grants access to anything.
--
--  HOW TO APPLY (disposable instance only)
--      mysql -h <host> -u <user> -p <dbname> < poc/seed/two-tenant-seed.sql
--    or paste into a client. Run it BEFORE repro-cross-tenant.sh.
--
--  RE-RUN SAFETY
--    Every statement is DELETE-then-INSERT, so the script is idempotent and
--    safe to run more than once.
-- =============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------------------------------
-- Remove any previous run of this PoC seed.
-- -----------------------------------------------------------------------------
DELETE FROM `mxk_role_member` WHERE `ID` = 'poc-rm-tenant2-user';
DELETE FROM `mxk_roles`       WHERE `ID` = 'poc-role-tenant2';
DELETE FROM `mxk_userinfo`    WHERE `ID` = 'poc-user-tenant2';
DELETE FROM `mxk_organizations` WHERE `ID` = 'poc-org-tenant2';
DELETE FROM `mxk_institutions`  WHERE `ID` = 'poc-inst-2';

-- -----------------------------------------------------------------------------
-- 1. Second institution (tenant B).
--    ID 'poc-inst-2' keeps this row visually distinct from the shipped
--    institution whose ID is '1'.
-- -----------------------------------------------------------------------------
INSERT INTO `mxk_institutions`
  (`ID`, `NAME`, `FULLNAME`, `SORTINDEX`, `STATUS`, `INSTID`,
   `CREATEDBY`, `CREATEDDATE`, `captcha`)
VALUES
  ('poc-inst-2', 'POC Tenant B', 'PoC Institution Two (disposable)', 2, '1', 'poc-inst-2',
   'poc-seed', NOW(), 'NONE');

-- -----------------------------------------------------------------------------
-- 2. An organisation inside tenant B.
--    mxk_organizations.INSTID is NOT NULL, so the user cannot exist without an
--    organisation that names its tenant.
-- -----------------------------------------------------------------------------
INSERT INTO `mxk_organizations`
  (`ID`, `ORGCODE`, `ORGNAME`, `TYPE`, `STATUS`, `INSTID`,
   `CREATEDBY`, `CREATEDDATE`, `HASCHILD`)
VALUES
  ('poc-org-tenant2', 'POCORG2', 'PoC Tenant B Root Org', 'Department', '1', 'poc-inst-2',
   'poc-seed', NOW(), 'false');

-- -----------------------------------------------------------------------------
-- 3. The dummy user in tenant B.
--    PASSWORD     = bcrypt hash of "DummyPassw0rd!"  (one-way, correct design)
--    DECIPHERABLE = PasswordReciprocal ciphertext of the same string, which is
--                   reversible from the column value plus the public constant at
--                   ReciprocalUtils.java:49 (finding 5).
--    STATUS=1 (active) and ISLOCKED=1 (not locked) mirror the shipped admin row so
--    the account can actually authenticate.
-- -----------------------------------------------------------------------------
INSERT INTO `mxk_userinfo`
  (`ID`, `USERNAME`, `PASSWORD`, `DECIPHERABLE`, `AUTHNTYPE`,
   `EMAIL`, `DISPLAYNAME`, `NICKNAME`, `TIMEZONE`, `LOCALE`,
   `STATUS`, `ISLOCKED`, `UNLOCKTIME`, `PASSWORDLASTSETTIME`,
   `USERTYPE`, `USERSTATE`, `INSTID`,
   `CREATEDBY`, `CREATEDDATE`, `DESCRIPTION`)
VALUES
  ('poc-user-tenant2', 'poc_tenant2_user',
   '$2a$10$9a/U4fcabBFd0iubr6CA2OMkyzJjTB3E22EZtkg5FnbNisIHIGVoy',
   '$2a$10$xYnh0U/YCFaVgAAxz8PJHu7bf1f010e7a04627f5203411be8ac9bcad405c34f3c1ad5889172928d0d351822b3b96df19b69285',
   1,
   'poc_tenant2_user@example.invalid', 'PoC Tenant B User', 'poc-tenant2',
   'Asia/Shanghai', 'zh_CN',
   1, 1, '2020-01-01 01:01:01', '2020-01-01 01:01:01',
   'Customer', 'RESIDENT', 'poc-inst-2',
   'poc-seed', NOW(), 'PoC seed user for cross-tenant check. Disposable.');

-- -----------------------------------------------------------------------------
-- 4. A role in tenant B and its membership, so the user is a real member of
--    tenant B rather than a floating row.
-- -----------------------------------------------------------------------------
INSERT INTO `mxk_roles`
  (`ID`, `NAME`, `STATUS`, `INSTID`, `CREATEDBY`, `CREATEDDATE`)
VALUES
  ('poc-role-tenant2', 'PoC Tenant B Role', '1', 'poc-inst-2', 'poc-seed', NOW());

INSERT INTO `mxk_role_member`
  (`ID`, `ROLEID`, `MEMBERID`, `TYPE`, `INSTID`, `CREATEDDATE`)
VALUES
  ('poc-rm-tenant2-user', 'poc-role-tenant2', 'poc-user-tenant2', 'USER', 'poc-inst-2', NOW());

SET FOREIGN_KEY_CHECKS = 1;

-- =============================================================================
-- VERIFICATION QUERIES (run after applying, before repro-cross-tenant.sh)
-- =============================================================================
-- 1. Confirm the seed landed:
--
--      SELECT ID, USERNAME, INSTID, STATUS, ISLOCKED FROM mxk_userinfo
--       WHERE ID = 'poc-user-tenant2';
--    EXPECTED: one row, INSTID = 'poc-inst-2', STATUS = 1, ISLOCKED = 1.
--
-- 2. Confirm the tenant boundary really does differ between the two users
--    (this is the precondition the cross-tenant check depends on):
--
--      SELECT USERNAME, INSTID FROM mxk_userinfo
--       WHERE USERNAME IN ('admin', 'poc_tenant2_user');
--    EXPECTED: admin is in institution 1, poc_tenant2_user is in 'poc-inst-2'.
--
-- 3. CONFIRM THE UNSCOPED LOOKUP IS UNSCOPED. Run this directly in SQL. If it
--    returns the tenant-B row, the unscoped WHERE clause is confirmed to ignore
--    INSTID, which is the entire mechanism of finding 3:
--
--      SELECT USERNAME, INSTID FROM mxk_userinfo
--       WHERE USERNAME = 'poc_tenant2_user' AND STATUS = 1;
--    EXPECTED: returns the row, with no institution predicate in the query.
--    Contrast with the scoped variant the code does NOT use:
--
--      SELECT USERNAME, INSTID FROM mxk_userinfo
--       WHERE USERNAME = 'poc_tenant2_user' AND INSTID = '1' AND STATUS = 1;
--    EXPECTED: zero rows, because the user is not in institution 1.
--
-- 4. Demonstrate finding 5 against your own data (optional but recommended).
--    Take the DECIPHERABLE value and paste it into Harness B's key derivation to
--    recover "DummyPassw0rd!". See README.md section "Proving finding 5".
--
-- 5. TEARDOWN when finished:
--
--      mysql -h <host> -u <user> -p <dbname> <<'SQL'
--      SET FOREIGN_KEY_CHECKS = 0;
--      DELETE FROM `mxk_role_member`   WHERE `ID` = 'poc-rm-tenant2-user';
--      DELETE FROM `mxk_roles`         WHERE `ID` = 'poc-role-tenant2';
--      DELETE FROM `mxk_userinfo`      WHERE `ID` = 'poc-user-tenant2';
--      DELETE FROM `mxk_organizations` WHERE `ID` = 'poc-org-tenant2';
--      DELETE FROM `mxk_institutions`  WHERE `ID` = 'poc-inst-2';
--      SET FOREIGN_KEY_CHECKS = 1;
--      SQL
-- =============================================================================
