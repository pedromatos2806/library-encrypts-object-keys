package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

class ObjectObfuscatorIntegrationTest {

    @Test
    void testMigrateLegacyCbcToGcmAndDecryptWithNewPrimary() {
        // preparar chaves old e new
        byte[] oldKey = new byte[16];
        byte[] newKey = new byte[16];
        new java.security.SecureRandom().nextBytes(oldKey);
        new java.security.SecureRandom().nextBytes(newKey);

        String b64Old = java.util.Base64.getEncoder().encodeToString(oldKey);
        String b64New = java.util.Base64.getEncoder().encodeToString(newKey);

        // definir chave única como oldKey para encriptação legada
        ObjectObfuscator.setKeysFromString(b64Old);

        String plain = "integration|*|value";
        // gerar ciphertext CBC legada usando a chave atual (old)
        String legacy = ObjectObfuscator.criptografarLegadoCBC(plain);
        assertNotNull(legacy);

        // Agora configurar chaves: primary = newKey, secondary = oldKey
        ObjectObfuscator.setKeysFromString(b64New + ";" + b64Old);

        // migrar o ciphertext legada para o formato GCM
        String migrated = ObjectObfuscator.migrateToGcm(legacy);
        assertNotNull(migrated);

        // o migrado deve ser descriptografável com a primary (newKey)
        String decrypted = ObjectObfuscator.descriptografar(migrated);
        assertEquals(plain, decrypted);
    }

}
