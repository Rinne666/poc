/*
 * Harness A — DelegatingPasswordEncoder prefix semantics
 *
 * Finding under test:
 *   maxkey-20261002-seeded-admin-default-credential
 *
 * Claim under test: MaxKey's PasswordEncoder bean is a Spring DelegatingPasswordEncoder
 * whose encoder map registers the id "plain" -> NoOpPasswordEncoder
 * (maxkey-starter/maxkey-starter-web/src/main/java/org/dromara/maxkey/autoconfigure/
 *  ApplicationAutoConfiguration.java: "encoders.put(\"plain\", NoOpPasswordEncoder.getInstance())"
 *  and "new DelegatingPasswordEncoder(idForEncode, encoders)" with
 *  idForEncode = ${maxkey.crypto.password.encoder:bcrypt}).
 *
 * Because DelegatingPasswordEncoder selects the VALIDATING encoder from the {id} PREFIX OF THE
 * STORED VALUE, the shipped seed row
 *   mxk_userinfo.PASSWORD = '{plain}maxkey'   (user id 1, username 'admin')
 *   deployment/docker/docker-mysql/docker-entrypoint-initdb.d/latest/maxkey.sql:1665
 * is validated with NoOpPasswordEncoder, i.e. the stored literal IS the login password.
 *
 * FIDELITY NOTE — the encoder classes below are MaxKey's OWN classes, copied byte-identically
 * out of the read-only repo into ../harness-lib (org.dromara.maxkey.crypto.password.*), NOT
 * Spring's built-ins. ApplicationAutoConfiguration.java imports
 *   org.dromara.maxkey.crypto.password.NoOpPasswordEncoder          <- MaxKey's, not Spring's
 *   org.dromara.maxkey.crypto.password.StandardPasswordEncoder      <- MaxKey's
 *   org.dromara.maxkey.crypto.password.LdapShaPasswordEncoder       <- MaxKey's
 *   org.dromara.maxkey.crypto.password.Md4PasswordEncoder           <- MaxKey's
 *   org.dromara.maxkey.crypto.password.SM3PasswordEncoder           <- MaxKey's
 *   org.dromara.maxkey.crypto.password.MessageDigestPasswordEncoder <- MaxKey's
 *   org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
 *   org.springframework.security.crypto.password.DelegatingPasswordEncoder
 *   org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
 *   org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
 * The encoder map below is a line-for-line reproduction of the bean method.
 *
 * SCOPE LIMIT (stated honestly):
 * This harness proves the ENCODER SEMANTICS ONLY. It does NOT start MaxKey, does NOT read a
 * live database, and does NOT by itself prove the seeded row exists. The existence and content
 * of the seeded row is a separate source-level fact, established by reading the SQL file
 * (see repro-default-admin.sh for the end-to-end check against a running instance).
 *
 * DUMMY DATA ONLY. No real credential or user is involved.
 */

import java.util.HashMap;
import java.util.Map;

import org.dromara.maxkey.crypto.password.LdapShaPasswordEncoder;
import org.dromara.maxkey.crypto.password.Md4PasswordEncoder;
import org.dromara.maxkey.crypto.password.MessageDigestPasswordEncoder;
import org.dromara.maxkey.crypto.password.NoOpPasswordEncoder;
import org.dromara.maxkey.crypto.password.SM3PasswordEncoder;
import org.dromara.maxkey.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

public final class DelegatingPasswordEncoderProbe {

    private static int failures = 0;
    private static int checks = 0;

    /**
     * Exact value stored by the shipped init SQL for user id 1 / username 'admin'.
     * Source: deployment/docker/docker-mysql/docker-entrypoint-initdb.d/latest/maxkey.sql:1665
     *         INSERT INTO `mxk_userinfo` VALUES ('1','admin','{plain}maxkey',...)
     */
    private static final String SEEDED_ADMIN_STORED_PASSWORD = "{plain}maxkey";

    /**
     * Control secret, deliberately different from the seeded admin password so that the
     * control hash differs from the seeded row in exactly one respect: the stored FORM
     * ({bcrypt}$2a$... instead of {plain}...).
     */
    private static final String CONTROL_SECRET = "DummyNotTheSeeded0";

    /**
     * The control hash is GENERATED AT RUNTIME rather than hardcoded. An earlier revision
     * of this harness hardcoded a remembered public bcrypt test vector and its
     * positive-control assertion FAILED; the cause was the incorrect constant, not the
     * library. Generating the vector at runtime removes any dependence on a recalled
     * constant and makes the control reproducible by construction.
     */
    private static String controlHash;

    public static void main(String[] args) {
        System.out.println("=========================================================================");
        System.out.println(" Harness A - DelegatingPasswordEncoder prefix semantics");
        System.out.println(" finding  : maxkey-20261002-seeded-admin-default-credential");
        System.out.println("=========================================================================");
        System.out.println();

        // --- Reproduction of ApplicationAutoConfiguration#passwordEncoder --- //
        String idForEncode = "bcrypt";   // ${maxkey.crypto.password.encoder:bcrypt}
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("plain", NoOpPasswordEncoder.getInstance());
        encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put("scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
        encoders.put("md4", new Md4PasswordEncoder());
        encoders.put("md5", new MessageDigestPasswordEncoder("MD5"));
        encoders.put("sha1", new StandardPasswordEncoder("SHA-1", ""));
        encoders.put("sha256", new StandardPasswordEncoder());
        encoders.put("sha384", new StandardPasswordEncoder("SHA-384", ""));
        encoders.put("sha512", new StandardPasswordEncoder("SHA-512", ""));
        encoders.put("sm3", new SM3PasswordEncoder());
        encoders.put("ldap", new LdapShaPasswordEncoder());

        PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(idForEncode, encoders);

        System.out.println("[INFO] PasswordEncoder bean class : " + passwordEncoder.getClass().getName());
        System.out.println("[INFO] 'plain' resolves to        : "
                + NoOpPasswordEncoder.getInstance().getClass().getName());
        System.out.println("[INFO] default encode id          : " + idForEncode);
        System.out.println("[INFO] registered encoder ids     : " + encoders.keySet().stream().sorted().toList());
        System.out.println("[INFO] seeded stored value        : " + SEEDED_ADMIN_STORED_PASSWORD);
        controlHash = "{bcrypt}" + new BCryptPasswordEncoder().encode(CONTROL_SECRET);
        System.out.println("[INFO] control stored value       : " + controlHash
                + "   (bcrypt of \"" + CONTROL_SECRET + "\")");
        System.out.println();

        // ---------------------------------------------------------------------
        // ASSERTION 1 — the decisive link in the finding.
        // The {id} prefix is read from the STORED value, not from the configured
        // default. "{plain}maxkey" routes to NoOpPasswordEncoder, so the raw login
        // string "maxkey" matches the stored literal.
        // ---------------------------------------------------------------------
        check("ASSERTION 1  matches(\"maxkey\", \"{plain}maxkey\") == true",
                passwordEncoder.matches("maxkey", SEEDED_ADMIN_STORED_PASSWORD));

        // ---------------------------------------------------------------------
        // ASSERTION 2 — NoOp is a genuine equality check, not an always-true stub.
        // ---------------------------------------------------------------------
        check("ASSERTION 2  matches(\"wrongpass\", \"{plain}maxkey\") == false",
                !passwordEncoder.matches("wrongpass", SEEDED_ADMIN_STORED_PASSWORD));

        // ---------------------------------------------------------------------
        // ASSERTION 3 — control. Under the {bcrypt} id the seeded admin password
        // does NOT match. This isolates the {id} prefix as the cause of assertion 1.
        // ---------------------------------------------------------------------
        check("ASSERTION 3  matches(\"maxkey\", \"{bcrypt}$2a$10$...\") == false   (control)",
                !passwordEncoder.matches("maxkey", controlHash));

        // ---------------------------------------------------------------------
        // ASSERTION 4 — positive control. The matcher succeeds in the true
        // direction, so assertion 3 is a real rejection and not a dead harness.
        // ---------------------------------------------------------------------
        check("ASSERTION 4  matches(\"" + CONTROL_SECRET + "\", its {bcrypt} hash) == true  (positive control)",
                passwordEncoder.matches(CONTROL_SECRET, controlHash));

        // ---------------------------------------------------------------------
        // ASSERTION 5/6 — encode() uses the CONFIGURED default id, so newly created
        // users are unaffected. This correctly SCOPES the finding to the pre-seeded
        // row rather than to all passwords in the system.
        // ---------------------------------------------------------------------
        String freshHash = passwordEncoder.encode("maxkey");
        System.out.println("[INFO] encode(\"maxkey\") -> " + freshHash);
        check("ASSERTION 5  fresh encode() is prefixed {bcrypt}",
                freshHash.startsWith("{bcrypt}"));
        check("ASSERTION 6  fresh encode() round-trips through matches()",
                passwordEncoder.matches("maxkey", freshHash));
        check("ASSERTION 7  a fresh {bcrypt} value differs from the seeded {plain} value",
                !freshHash.equals(SEEDED_ADMIN_STORED_PASSWORD));

        // ---------------------------------------------------------------------
        // ASSERTION 8 — the crispest statement of the finding, independent of Spring:
        // strip the {id} prefix from the value the shipped SQL stores, and the remainder
        // IS the literal login password. Nothing else is required to recover it.
        // ---------------------------------------------------------------------
        String afterPrefix = SEEDED_ADMIN_STORED_PASSWORD.substring("{plain}".length());
        System.out.println("[INFO] stored value minus the {plain} prefix = \"" + afterPrefix + "\"");
        check("ASSERTION 8  \"{plain}maxkey\" minus its prefix is literally the login password",
                "maxkey".equals(afterPrefix));

        // ---------------------------------------------------------------------
        // Informational, NOT assertions. For each other id, re-hash the SAME password
        // and show that the stored form is an opaque digest: it does NOT contain the
        // plaintext, so the {plain} row is distinguishable from every other id.
        // (These matching=true results are expected: they are hashes OF "maxkey".)
        // ---------------------------------------------------------------------
        System.out.println();
        System.out.println("[INFO] contrast — the same password stored under other ids "
                + "(these are hashes OF \"maxkey\", so matching=true is EXPECTED):");
        for (String id : new String[]{"md5", "sha256", "ldap", "bcrypt", "pbkdf2", "scrypt"}) {
            String stored = encoders.get(id).encode("maxkey");
            boolean containsPlaintext = stored.contains("maxkey");
            boolean accepted = passwordEncoder.matches("maxkey", "{" + id + "}" + stored);
            System.out.println("[INFO]   id=" + String.format("%-7s", id)
                    + " stored-value-contains-plaintext=" + containsPlaintext
                    + "  matches(\"maxkey\")=" + accepted);
        }
        System.out.println("[INFO]   -> under every other id the stored value is an opaque digest.");
        System.out.println("[INFO]   -> under {plain} the stored value IS the password (assertion 8).");

        // ---------------------------------------------------------------------
        // Informational: upgradeEncoding reports the seeded row as upgradable.
        // This is the mechanism that would remediate it IF the row were ever
        // re-encoded through the encoder. Reported, not asserted.
        // ---------------------------------------------------------------------
        System.out.println("[INFO] upgradeEncoding(\"{plain}maxkey\") = "
                + passwordEncoder.upgradeEncoding(SEEDED_ADMIN_STORED_PASSWORD));

        System.out.println();
        System.out.println("-------------------------------------------------------------------------");
        System.out.printf(" checks run: %d, failures: %d%n", checks, failures);
        System.out.println(failures == 0 ? " RESULT: PASS" : " RESULT: FAIL");
        System.out.println("-------------------------------------------------------------------------");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static void check(String label, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
        }
        System.out.println((condition ? "PASS  " : "FAIL  ") + label);
    }
}
