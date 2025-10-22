package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;

import org.junit.jupiter.api.Test;

class ObjectObfuscatorMoreCoverageTest {

    @Test
    void testDecodeNumericTypesParsing() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        class NumModel extends ObjectObfuscator {
            @ResourceId(showValue = true)
            Integer i;
            @ResourceId(showValue = true)
            Long l;
            @ResourceId(showValue = true)
            Byte b;
            @ResourceId(showValue = true)
            BigInteger bi;
            @ResourceId(showValue = true)
            BigDecimal bd;
        }

        NumModel m = new NumModel();
        String tokenSep = "|*|";
        String token = ObjectObfuscator.criptografar("42" + tokenSep + "10000000000" + tokenSep + "7" + tokenSep
                + "12345678901234567890" + tokenSep + "3.1415");
        m.setResourceId(token);
        m.decode();

        assertEquals(42, m.i.intValue());
        assertEquals(10000000000L, m.l.longValue());
        assertEquals((byte) 7, m.b.byteValue());
        assertEquals(new BigInteger("12345678901234567890"), m.bi);
        assertEquals(new BigDecimal("3.1415"), m.bd);
    }

    @Test
    void testEncodeThrowsOnNullAnnotatedField() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        String b64 = java.util.Base64.getEncoder().encodeToString(key);
        ObjectObfuscator.setKeysFromString(b64);

        class BadModel extends ObjectObfuscator {
            @ResourceId
            String mustNotBeNull;
        }

        BadModel m = new BadModel();
        // encode captura exceções e imprime stack trace; resourceId deve permanecer
        // null
        m.encode();
        assertNull(m.getResourceId());
    }

    @Test
    void testSetKeysFromStringAcceptsPlaintextKey() {
        // 16-character plaintext key
        String plain = "0123456789ABCDEF";
        ObjectObfuscator.setKeysFromString(plain);
        String p = "x";
        String c = ObjectObfuscator.criptografar(p);
        assertEquals(p, ObjectObfuscator.descriptografar(c));
    }

    @Test
    void testAddPrimaryKeyInvalidLengthThrows() {
        Exception ex = assertThrows(IllegalArgumentException.class, () -> ObjectObfuscator.addPrimaryKey("short"));
        assertTrue(
                ex.getMessage().toLowerCase().contains("tamanho") || ex.getMessage().toLowerCase().contains("invalid"));
    }

    @Test
    void testDecryptNoKeyWorksThrowsCryptoException() {
        // configure two valid keys
        byte[] k1 = new byte[16];
        byte[] k2 = new byte[16];
        new java.security.SecureRandom().nextBytes(k1);
        new java.security.SecureRandom().nextBytes(k2);
        String s = java.util.Base64.getEncoder().encodeToString(k1) + ";"
                + java.util.Base64.getEncoder().encodeToString(k2);
        ObjectObfuscator.setKeysFromString(s);

        // create small byte array and base64-encode to make a blob too small for
        // GCM/CBC
        byte[] small = new byte[4];
        new java.security.SecureRandom().nextBytes(small);
        String smallB64 = java.util.Base64.getUrlEncoder().encodeToString(small);

        assertThrows(CryptoException.class, () -> ObjectObfuscator.descriptografar(smallB64));
    }

}
