package idhash;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;

public final class ObjectObfuscator {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH_BYTES = 16;
    private static final SecretKeySpec SECRET_KEY;
    
    // Instância do Gson para ser reutilizada
    private static final Gson gson = new Gson();

    // Bloco estático para carregar a chave de criptografia de forma segura
    static {
        String keyFromEnv = System.getenv("APP_ENCRYPTION_KEY");
        if (keyFromEnv == null || keyFromEnv.trim().isEmpty() ) {
            throw new IllegalStateException("A variável de ambiente APP_ENCRYPTION_KEY não está definida.");
        }
        byte[] keyBytes = keyFromEnv.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException("A chave de criptografia deve ter 16, 24 ou 32 bytes.");
        }
        SECRET_KEY = new SecretKeySpec(keyBytes, ALGORITHM);
    }

    private ObjectObfuscator() {}

    /**
     * Codifica (serializa e criptografa) um objeto Java em uma única String.
     * @param object O objeto a ser codificado.
     * @param <T> O tipo do objeto.
     * @return A String ofuscada representando o objeto.
     */
    public static <T> String encode(T object) {
        if (object == null) {
            return null;
        }

        try {
            // 1. Transformar o objeto em uma String JSON
            String json = gson.toJson(object);

            // 2. Criptografar a String JSON
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(json.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

            return Base64.getUrlEncoder().encodeToString(combined);

        } catch (Exception e) {
            throw new RuntimeException("Erro ao codificar o objeto", e);
        }
    }

    /**
     * Decodifica (descriptografa e desserializa) uma String de volta para um objeto Java.
     * @param encodedString A string ofuscada.
     * @param classOfT A classe do objeto de destino (ex: Usuario.class).
     * @param <T> O tipo do objeto.
     * @return O objeto Java original.
     */
    public static <T> T decode(String encodedString, Class<T> classOfT) {
        if (encodedString == null || encodedString.trim().isEmpty()) {
            return null;
        }

        try {
            // 1. Descriptografar para obter a String JSON
            byte[] combined = Base64.getUrlDecoder().decode(encodedString);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(combined, 0, IV_LENGTH_BYTES);
            byte[] encryptedBytes = new byte[combined.length - IV_LENGTH_BYTES];
            System.arraycopy(combined, IV_LENGTH_BYTES, encryptedBytes, 0, encryptedBytes.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY, ivParameterSpec);
            byte[] decryptedJsonBytes = cipher.doFinal(encryptedBytes);
            String json = new String(decryptedJsonBytes, StandardCharsets.UTF_8);

            // 2. Transformar a String JSON de volta para um objeto Java
            return gson.fromJson(json, classOfT);

        } catch (Exception e) {
            throw new RuntimeException("Erro ao decodificar a string para o objeto: " + classOfT.getSimpleName(), e);
        }
    }
}
