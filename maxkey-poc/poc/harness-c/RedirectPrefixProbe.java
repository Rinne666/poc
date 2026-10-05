/*
 * Harness C — OAuth2 redirect_uri prefix matching semantics
 *
 * SUPPORTS the redirect finding. This is supplementary evidence: it is NOT one of the five
 * primary findings, and it does not by itself prove any live endpoint accepts a bad redirect.
 *
 * Claim under test: MaxKey's DefaultRedirectResolver.redirectMatches() accepts a requested
 * redirect_uri whose PATH merely has the registered path as a string PREFIX, because it uses
 *   StringUtils.cleanPath(req.getPath()).startsWith(StringUtils.cleanPath(reg.getPath()))
 * (maxkey-protocols/maxkey-protocol-oauth-2.0/src/main/java/org/dromara/maxkey/authz/oauth2/
 *  provider/endpoint/DefaultRedirectResolver.java:108).
 *
 * A registered https://app.example.com/callback therefore also matches
 * https://app.example.com/callbackXYZ and https://app.example.com/callback.evil.test/,
 * which are different endpoints. The class javadoc states this prefix behaviour is
 * intentional ("this implementation tests if the user requested redirect starts with the
 * registered redirect"), so the finding is about the SECURITY CONSEQUENCE of that design,
 * not about an accidental coding slip.
 *
 * cleanPath is reproduced from spring-core 7.0.8, the version declared in the project's
 * gradle.properties (springVersion = 7.0.8). The class org.springframework.util.StringUtils
 * is the one DefaultRedirectResolver.java:31 imports.
 *
 * The matching routine below is a faithful reimplementation of the product method so that
 * the assertions exercise the real control flow, not just cleanPath in isolation.
 *
 * DUMMY DATA ONLY. No real endpoint, host or credential is contacted; these are string
 * operations on RFC 2606 reserved example domains.
 */

import java.net.MalformedURLException;
import java.net.URL;

import org.springframework.util.StringUtils;

public final class RedirectPrefixProbe {

    private static int failures = 0;
    private static int checks = 0;

    public static void main(String[] args) {
        System.out.println("=========================================================================");
        System.out.println(" Harness C - OAuth2 redirect_uri prefix matching semantics");
        System.out.println(" supports : the OAuth2 redirect_uri prefix-matching finding");
        System.out.println("=========================================================================");
        System.out.println();

        // =====================================================================
        // SECTION 1 — raw StringUtils.cleanPath semantics, as asked.
        // =====================================================================
        System.out.println("--- SECTION 1: StringUtils.cleanPath semantics ---");
        String base = StringUtils.cleanPath("/callback");
        System.out.println("[INFO] cleanPath(\"/callback\")       = \"" + base + "\"");
        check("ASSERTION 1  cleanPath(\"/callbackXYZ\").startsWith(cleanPath(\"/callback\")) == true",
                StringUtils.cleanPath("/callbackXYZ").startsWith(base));

        String traversal = StringUtils.cleanPath("/cb/../x");
        System.out.println("[INFO] cleanPath(\"/cb/../x\")        = \"" + traversal + "\"");
        check("ASSERTION 2  cleanPath(\"/cb/../x\") neutralises traversal to \"/x\"",
                "/x".equals(traversal));
        check("ASSERTION 3  cleanPath(\"/cb/../x\") does NOT start with \"/callback\"",
                !traversal.startsWith(StringUtils.cleanPath("/callback")));

        // =====================================================================
        // SECTION 2 — the product's redirectMatches() logic on real URI pairs.
        // =====================================================================
        System.out.println();
        System.out.println("--- SECTION 2: DefaultRedirectResolver.redirectMatches() semantics ---");
        String registered = "https://app.example.com/callback";
        System.out.println("[INFO] registered redirect = " + registered);

        String[] requested = {
            "https://app.example.com/callback",              // intended: exact
            "https://app.example.com/callbackXYZ",           // sibling path sharing the prefix
            "https://app.example.com/callback.evil.test/",   // attacker-controlled host segment
            "https://app.example.com/callback/../admin",     // traversal, cleaned away
            "https://app.example.com/other",                 // unrelated path
            "https://evil.test/callback",                    // different host
        };
        for (String r : requested) {
            boolean m = redirectMatches(r, registered);
            System.out.println("[INFO]   match(" + pad(r) + ") = " + m);
        }

        check("ASSERTION 4  the exact registered URI matches",
                redirectMatches(registered, registered));
        check("ASSERTION 5  a SIBLING path sharing the string prefix also matches  <-- the finding",
                redirectMatches("https://app.example.com/callbackXYZ", registered));
        check("ASSERTION 6  a host smuggled after the prefix also matches  <-- the finding",
                redirectMatches("https://app.example.com/callback.evil.test/", registered));
        check("ASSERTION 7  an unrelated path on the same host does NOT match",
                !redirectMatches("https://app.example.com/other", registered));
        check("ASSERTION 8  the same path on a DIFFERENT host does NOT match (host is still checked)",
                !redirectMatches("https://evil.test/callback", registered));
        check("ASSERTION 9  a traversal path is cleaned first, so it resolves to /admin and does NOT match",
                !redirectMatches("https://app.example.com/callback/../admin", registered));

        // =====================================================================
        // SECTION 3 — contrast with the exact-match resolver that ships alongside it.
        // =====================================================================
        System.out.println();
        System.out.println("--- SECTION 3: contrast with ExactMatchRedirectResolver ---");
        String sibling = "https://app.example.com/callbackXYZ";
        check("ASSERTION 10 exact-match semantics REJECT the sibling path (String.equals)",
                !sibling.equals(registered));
        System.out.println("[INFO] ExactMatchRedirectResolver.redirectMatches() is `requestedRedirect.equals(redirectUri)`,");
        System.out.println("[INFO] which rejects the same request that DefaultRedirectResolver accepts.");
        System.out.println("[INFO] => the two shipped resolvers disagree on the same input; the permissive one is in use.");

        System.out.println();
        System.out.println("-------------------------------------------------------------------------");
        System.out.printf(" checks run: %d, failures: %d%n", checks, failures);
        System.out.println(failures == 0 ? " RESULT: PASS" : " RESULT: FAIL");
        System.out.println("-------------------------------------------------------------------------");
        System.exit(failures == 0 ? 0 : 1);
    }

    /**
     * Faithful reimplementation of
     * DefaultRedirectResolver.redirectMatches(String requestedRedirect, String redirectUri)
     * at DefaultRedirectResolver.java:102-114.
     */
    private static boolean redirectMatches(String requestedRedirect, String redirectUri) {
        try {
            URL req = new URL(requestedRedirect);
            URL reg = new URL(redirectUri);

            if (reg.getProtocol().equals(req.getProtocol()) && hostMatches(reg.getHost(), req.getHost())) {
                return StringUtils.cleanPath(req.getPath()).startsWith(StringUtils.cleanPath(reg.getPath()));
            }
        } catch (MalformedURLException e) {
            // fall through, exactly as the product does
        }
        return requestedRedirect.equals(redirectUri);
    }

    /** DefaultRedirectResolver.hostMatches(). */
    private static boolean hostMatches(String registeredHost, String requestedHost) {
        if (registeredHost == null) {
            return true;
        }
        if ("localhost".equalsIgnoreCase(requestedHost)) {
            return "localhost".equalsIgnoreCase(registeredHost);
        }
        String normalizedRegistered = stripPort(registeredHost);
        String normalizedRequested = stripPort(requestedHost);
        if (normalizedRegistered.endsWith(".")) {
            normalizedRegistered = normalizedRegistered.substring(0, normalizedRegistered.length() - 1);
        }
        return normalizedRequested.equalsIgnoreCase(normalizedRegistered);
    }

    private static String stripPort(String host) {
        int idx = host.indexOf(':');
        return idx < 0 ? host : host.substring(0, idx);
    }

    private static String pad(String s) {
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < 45) {
            sb.append(' ');
        }
        return sb.toString();
    }

    private static void check(String label, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
        }
        System.out.println((condition ? "PASS  " : "FAIL  ") + label);
    }
}
