package idhash;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ObjectObfuscatorEdgeCasesTest {

    @Test
    void testEncryptNullOrEmpty() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        assertNull(ObjectObfuscator.criptografar(null));
        assertNull(ObjectObfuscator.criptografar("   "));
    }

    @Test
    void testDecryptNullOrEmpty() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        assertNull(ObjectObfuscator.descriptografar(null));
        assertNull(ObjectObfuscator.descriptografar("   "));
    }

    @Test
    void testSetKeysFromStringInvalidKeyLength() {
        // preparar uma chave inválida (não 16/24/32 bytes)
        String shortKey = "short";
        Exception ex = assertThrows(IllegalArgumentException.class, () -> ObjectObfuscator.setKeysFromString(shortKey));
        assertTrue(ex.getMessage().contains("tamanho inválido") || ex.getMessage().toLowerCase().contains("invalid"));
    }

    @Test
    void testDecryptWithBadBase64ThrowsCryptoException() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        // pass malformed base64 to decrypt
        assertThrows(CryptoException.class, () -> ObjectObfuscator.descriptografar("!!not-base64!!"));
    }

}
