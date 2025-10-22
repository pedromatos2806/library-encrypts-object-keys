package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ObjectObfuscatorInitKeyIfNeededTest {

    @AfterEach
    void cleanupProps() throws Exception {
        System.clearProperty("APP_ENCRYPTION_KEYS");
        System.clearProperty("APP_ENCRYPTION_KEY");
        // limpar campos em cache
        idhash.KeyManager.resetarParaTestes();
    }

    @Test
    void testInitWithAppEncryptionKeysProperty() throws Exception {
        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        new java.security.SecureRandom().nextBytes(k1);
        new java.security.SecureRandom().nextBytes(k2);
        String s1 = java.util.Base64.getEncoder().encodeToString(k1);
        String s2 = java.util.Base64.getEncoder().encodeToString(k2);

        System.setProperty("APP_ENCRYPTION_KEYS", s1 + ";" + s2);
        // também definir chave única em env/propriedade porque initKeyIfNeeded
        // atualmente requer
        // APP_ENCRYPTION_KEY
        System.setProperty("APP_ENCRYPTION_KEY", s1);

        // clear caches
        idhash.KeyManager.resetarParaTestes();

        String plain = "init-test";
        String c = ObjectObfuscator.criptografar(plain);
        assertNotNull(c);
        assertEquals(plain, ObjectObfuscator.descriptografar(c));
    }

    @Test
    void testInitWithSingleAppEncryptionKeyPropertyPlaintext() throws Exception {
        // plaintext key (16 chars)
        String plainKey = "ABCDEFGHIJKLMNOP";
        System.setProperty("APP_ENCRYPTION_KEY", plainKey);

        idhash.KeyManager.resetarParaTestes();

        String p = "single-init";
        String c = ObjectObfuscator.criptografar(p);
        assertNotNull(c);
        assertEquals(p, ObjectObfuscator.descriptografar(c));
    }

}
