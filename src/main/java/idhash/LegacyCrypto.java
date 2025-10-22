package idhash;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.Cipher;

/**
 * Operações legadas com AES/CBC (mantidas apenas para compatibilidade e
 * migração).
 */
final class LegacyCrypto {

    private static final String CBC_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int CBC_IV_LENGTH_BYTES = 16;

    private LegacyCrypto() {
    }

    static String criptografarCBCComChave(String plain, byte[] keyBytes) {
        try {
            Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION);
            byte[] iv = new byte[CBC_IV_LENGTH_BYTES];
            java.security.SecureRandom rnd = new java.security.SecureRandom();
            rnd.nextBytes(iv);
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] cipherBytes = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + cipherBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherBytes, 0, combined, iv.length, cipherBytes.length);
            return java.util.Base64.getUrlEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new CryptoException("Erro ao codificar legacy CBC", e);
        }
    }

    static String descriptografarCBCComChave(String encoded, byte[] keyBytes) throws CryptoException {
        byte[] combined;
        try {
            combined = java.util.Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Formato Base64 inválido para CBC", e);
        }
        if (combined.length < CBC_IV_LENGTH_BYTES) {
            throw new CryptoException("Dados CBC inválidos: tamanho insuficiente");
        }
        byte[] iv = Arrays.copyOfRange(combined, 0, CBC_IV_LENGTH_BYTES);
        byte[] cipherBytes = Arrays.copyOfRange(combined, CBC_IV_LENGTH_BYTES, combined.length);
        javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
        try {
            Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION);
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] plain = cipher.doFinal(cipherBytes);
            String candidate = new String(plain, StandardCharsets.UTF_8);
            if (candidate.contains(ObjectObfuscator.TOKEN) || candidate.matches("^[\\p{Print}\\s]*$")) {
                return candidate;
            }
            throw new CryptoException("Decrypted CBC plaintext does not look valid");
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Erro ao decodificar legacy CBC", e);
        }
    }

    static String descriptografarCBC(String encoded) throws CryptoException {
        // tentar todas as chaves do KeyManager
        for (byte[] keyBytes : KeyManager.obterChaves()) {
            try {
                return descriptografarCBCComChave(encoded, keyBytes);
            } catch (CryptoException e) {
                // tentar próxima
            }
        }
        throw new CryptoException("Dados CBC inválidos para todas as chaves");
    }
}
