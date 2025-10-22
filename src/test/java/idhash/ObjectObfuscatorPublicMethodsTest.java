package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ObjectObfuscatorPublicMethodsTest {

    @AfterEach
    void cleanup() {
        // reiniciar KEYS para uma chave única aleatória
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);
    }

    @Test
    void testEncryptDecryptRoundTrip() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        String plain = "hello-world";
        String cipher = ObjectObfuscator.criptografar(plain);
        assertNotNull(cipher);

        String out = ObjectObfuscator.descriptografar(cipher);
        assertEquals(plain, out);
    }

    @Test
    void testEncryptLegacyCbcAndMigrate() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        String plain = "legacy-test";
        String legacy = ObjectObfuscator.criptografarLegadoCBC(plain);
        assertNotNull(legacy);
        // descriptografar legada usando a chave atual
        String dec = ObjectObfuscator.descriptografar(legacy);
        assertEquals(plain, dec);

        // migrar e validar novo decrypt GCM
        String migrated = ObjectObfuscator.migrarParaGcm(legacy);
        assertNotNull(migrated);
        assertEquals(plain, ObjectObfuscator.descriptografar(migrated));
    }

    @Test
    void testSetKeysFromStringAndAddPrimaryKeyApis() {
        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        new java.security.SecureRandom().nextBytes(k1);
        new java.security.SecureRandom().nextBytes(k2);
        String s1 = java.util.Base64.getEncoder().encodeToString(k1);
        String s2 = java.util.Base64.getEncoder().encodeToString(k2);

        ObjectObfuscator.setKeysFromString(s1 + ";" + s2);

        String p = "val-1";
        String c = ObjectObfuscator.criptografar(p);
        assertNotNull(c);

        // add primary as s2
        ObjectObfuscator.addPrimaryKey(s2);
        String c2 = ObjectObfuscator.criptografar(p);
        assertNotNull(c2);
        assertNotEquals(c, c2);
    }

    @Test
    void testInstanceEncodeDecode() {
        // create small example class
        class Model extends ObjectObfuscator {
            @ResourceId(showValue = true)
            private String id;

            Model(String id) {
                this.id = id;
            }

            String getId() {
                return id;
            }
        }

        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        Model m = new Model("X-123");
        m.encode();
        String token = m.getResourceId();
        assertNotNull(token);

        Model m2 = new Model(null);
        m2.setResourceId(token);
        m2.decode();
        assertEquals("X-123", m2.getId());
    }

}
