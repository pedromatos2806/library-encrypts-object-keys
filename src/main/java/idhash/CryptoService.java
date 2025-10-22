package idhash;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementa operações de alto nível de criptografia (GCM + fallback CBC
 * legado).
 */
public final class CryptoService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Logger LOGGER = Logger.getLogger(CryptoService.class.getName());

    private CryptoService() {
    }

    public static String criptografar(String plaintext) {
        if (plaintext == null || plaintext.trim().isEmpty())
            return null;
        byte[] key = KeyManager.obterChavePrimaria();
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            byte[] iv = new byte[IV_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
            return java.util.Base64.getUrlEncoder().encodeToString(combined);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Erro ao codificar os IDs concatenados", e);
            throw new CryptoException("Erro ao codificar os IDs concatenados", e);
        }
    }

    public static String descriptografar(String encoded) {
        if (encoded == null || encoded.trim().isEmpty())
            return null;
        List<byte[]> keys = KeyManager.obterChaves();
        byte[] combined;
        try {
            combined = java.util.Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Formato Base64 inválido", e);
        }

        for (byte[] keyBytes : keys) {
            try {
                if (combined.length < IV_LENGTH_BYTES)
                    continue;
                byte[] iv = Arrays.copyOfRange(combined, 0, IV_LENGTH_BYTES);
                byte[] encryptedBytes = Arrays.copyOfRange(combined, IV_LENGTH_BYTES, combined.length);
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                return new String(decryptedBytes, StandardCharsets.UTF_8);
            } catch (Exception e) {
                LOGGER.log(Level.FINER, "GCM attempt with a key failed: {0}", e.getMessage());
            }
        }

        // fallback para CBC legado
        for (byte[] keyBytes : keys) {
            try {
                return LegacyCrypto.descriptografarCBCComChave(encoded, keyBytes);
            } catch (CryptoException ex) {
                LOGGER.log(Level.FINER, "CBC attempt with a key failed: {0}", ex.getMessage());
            }
        }

        throw new CryptoException("Erro ao decodificar os IDs concatenados: nenhuma chave funcionou");
    }
}
