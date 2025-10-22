package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Teste de integração ponta-a-ponta cobrindo:
 * - encode/decode com AES-GCM (CryptoService)
 * - fallback legacy CBC (LegacyCrypto)
 * - rotação simples de chaves (addPrimaryKey)
 */
class ObjectObfuscatorEndToEndTest {

    static class Sample extends ObjectObfuscator {
        @ResourceId(showValue = true)
        private Long id;

        @ResourceId(showValue = true)
        private String code;

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }
    }

    @AfterEach
    void teardown() {
        // resetar estado do KeyManager entre os testes
        KeyManager.resetarParaTestes();
    }

    @Test
    void endToEnd_encryptDecrypt_withGcm_roundtrip() {
        // configurar uma chave única de 16 bytes (texto puro)
        ObjectObfuscator.setKeysFromString("abcdefghijklmnop"); // 16 bytes

        Sample s = new Sample();
        s.setId(42L);
        s.setCode("ABC123");

        // encode -> define resourceId
        s.encode();
        String token = s.getResourceId();
        assertNotNull(token);

        // criar uma nova instância, garantir campos nulos, então decode
        Sample s2 = new Sample();
        s2.setResourceId(token);
        s2.decode();
        assertEquals(42L, s2.getId());
        assertEquals("ABC123", s2.getCode());
    }

    @Test
    void fallback_legacyCbc_and_migrate() {
        ObjectObfuscator.setKeysFromString("abcdefghijklmnop");
        // criar uma concatenação em plaintext semelhante ao ResourceIdProcessor
        String concatenated = "42" + ObjectObfuscator.TOKEN + "ABC123" + ObjectObfuscator.TOKEN;
        // produzir ciphertext CBC legado com a chave primary existente
        String legacy = LegacyCrypto.criptografarCBCComChave(concatenated, KeyManager.obterChavePrimaria());

        // decode via ObjectObfuscator.decode (deve fazer fallback e parsear campos)
        Sample s = new Sample();
        s.setResourceId(legacy);
        s.decode();
        assertEquals(42L, s.getId());
        assertEquals("ABC123", s.getCode());

        // migrar legado para GCM usando helper e então garantir que o novo decode
        // funciona
        String migrated = ObjectObfuscator.migrateToGcm(legacy);
        Sample s2 = new Sample();
        s2.setResourceId(migrated);
        s2.decode();
        assertEquals(42L, s2.getId());
        assertEquals("ABC123", s2.getCode());
    }

    @Test
    void rotation_oldCiphertext_stillDecryptable_afterAddPrimary() {
        ObjectObfuscator.setKeysFromString("abcdefghijklmnop");
        Sample s = new Sample();
        s.setId(9001L);
        s.setCode("ROTATE");
        s.encode();
        String oldToken = s.getResourceId();

        // adicionar uma nova chave primary (16 bytes diferente)
        ObjectObfuscator.addPrimaryKey("qrstuvwxyzABCDEF");

        // nova encriptação deve usar a nova primary
        Sample sNew = new Sample();
        sNew.setId(9002L);
        sNew.setCode("NEW");
        sNew.encode();
        String newToken = sNew.getResourceId();
        assertNotEquals(oldToken, newToken);

        // old token should still decrypt (KeyManager tries all keys)
        Sample oldDecoded = new Sample();
        oldDecoded.setResourceId(oldToken);
        oldDecoded.decode();
        assertEquals(9001L, oldDecoded.getId());
        assertEquals("ROTATE", oldDecoded.getCode());
    }

}
