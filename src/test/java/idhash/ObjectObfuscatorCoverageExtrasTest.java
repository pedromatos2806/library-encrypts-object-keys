package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

class ObjectObfuscatorCoverageExtrasTest {

    @Test
    void testShowValueFalseClearsField() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        class Model extends ObjectObfuscator {
            @ResourceId(showValue = false)
            String secret = "SENSITIVE";
        }

        Model m = new Model();
        m.encode();
        // após encode o campo deve ser limpo porque showValue=false
        try {
            java.lang.reflect.Field f = m.getClass().getDeclaredField("secret");
            f.setAccessible(true);
            Object val = f.get(m);
            assertNull(val);
        } catch (Exception e) {
            fail("Reflection failed: " + e.getMessage());
        }
    }

    @Test
    void testInheritedIdFields() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        class Parent extends ObjectObfuscator {
            @ResourceId(showValue = true)
            String a = "P";
        }
        class Child extends Parent {
            @ResourceId(showValue = true)
            String b = "C";
        }

        Child c = new Child();
        c.encode();
        String token = c.getResourceId();
        assertNotNull(token);

        Child c2 = new Child();
        c2.setResourceId(token);
        c2.decode();
        // verificar que os campos foram restaurados
        try {
            java.lang.reflect.Field fa = c2.getClass().getSuperclass().getDeclaredField("a");
            fa.setAccessible(true);
            assertEquals("P", fa.get(c2));
            java.lang.reflect.Field fb = c2.getClass().getDeclaredField("b");
            fb.setAccessible(true);
            assertEquals("C", fb.get(c2));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testDecryptTriesKeysInOrder() {
        // criar duas chaves: primary falhará, secondary terá sucesso
        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        new java.security.SecureRandom().nextBytes(k1);
        new java.security.SecureRandom().nextBytes(k2);
        String s1 = java.util.Base64.getEncoder().encodeToString(k1);
        String s2 = java.util.Base64.getEncoder().encodeToString(k2);

        // definir primary = k2, secondary = k1 (vamos encriptar com k1 então primary
        // falha
        // primeiro)
        ObjectObfuscator.setKeysFromString(s2 + ";" + s1);

        // forçar encriptação com a chave secondary temporariamente tornando-a primary
        // via
        // setKeysFromString
        ObjectObfuscator.setKeysFromString(s1 + ";" + s2);
        String plain = "try-order";
        String cipher = ObjectObfuscator.criptografar(plain);

        // agora restaurar a ordem configurada (primary primeiro vai falhar para este
        // ciphertext)
        ObjectObfuscator.setKeysFromString(s2 + ";" + s1);

        String decrypted = ObjectObfuscator.descriptografar(cipher);
        assertEquals(plain, decrypted);
    }

}
