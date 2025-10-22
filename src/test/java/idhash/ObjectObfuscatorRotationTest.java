package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ObjectObfuscatorRotationTest {

    @AfterEach
    void cleanup() {
        // reiniciar chaves baseadas em ambiente definindo uma chave única válida
        // chave aleatória de 16 bytes em Base64
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        System.setProperty("APP_ENCRYPTION_KEY", b64);
        // forçar re-inicialização limpando KEYS por reflexão
        // limpar chaves em cache
        idhash.KeyManager.resetarParaTestes();
    }

    @Test
    void testSetKeysFromStringAndDecryptWithOldKey() {
        // criar duas chaves: oldKey e newKey (ambas 16 bytes)
        byte[] oldKey = new byte[16];
        byte[] newKey = new byte[16];
        new java.security.SecureRandom().nextBytes(oldKey);
        new java.security.SecureRandom().nextBytes(newKey);

        String b64Old = java.util.Base64.getEncoder().encodeToString(oldKey);
        String b64New = java.util.Base64.getEncoder().encodeToString(newKey);

        // definir chaves: primary = old, secondary = new (simular primary antigo)
        ObjectObfuscator.setKeysFromString(b64Old + ";" + b64New);

        String plain = "user|*|12345";
        String cipher = ObjectObfuscator.criptografar(plain);
        assertNotNull(cipher);

        // rotacionar: adicionar newKey como primaria
        ObjectObfuscator.addPrimaryKey(b64New);

        // o decrypt ainda deve funcionar (tenta primary primeiro => pode falhar, então
        // a chave antiga
        // tem sucesso)
        String decrypted = ObjectObfuscator.descriptografar(cipher);
        assertEquals(plain, decrypted);
    }

    @Test
    void testAddPrimaryKeyUpdatesSecret() {
        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        new java.security.SecureRandom().nextBytes(k1);
        new java.security.SecureRandom().nextBytes(k2);
        String s1 = java.util.Base64.getEncoder().encodeToString(k1);
        String s2 = java.util.Base64.getEncoder().encodeToString(k2);

        ObjectObfuscator.setKeysFromString(s1);
        // initial encrypt with k1
        String p = "abc";
        String c = ObjectObfuscator.criptografar(p);
        assertNotNull(c);

        // add k2 as primary
        ObjectObfuscator.addPrimaryKey(s2);
        // now SECRET_KEY_BYTES should be k2 -> encrypt new value with k2
        String c2 = ObjectObfuscator.criptografar(p);
        assertNotNull(c2);
        // c and c2 should be different
        assertNotEquals(c, c2);
    }
}
