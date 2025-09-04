package idhash;

import java.lang.reflect.Field;
import java.math.BigInteger;
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
		if (keyFromEnv == null || keyFromEnv.trim().isEmpty()) {
			throw new IllegalStateException("A variável de ambiente APP_ENCRYPTION_KEY não está definida.");
		}
		byte[] keyBytes = keyFromEnv.getBytes(StandardCharsets.UTF_8);
		if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
			throw new IllegalArgumentException("A chave de criptografia deve ter 16, 24 ou 32 bytes.");
		}
		SECRET_KEY = new SecretKeySpec(keyBytes, ALGORITHM);
	}

	private ObjectObfuscator() {
	}

	// Criptografa apenas os campos anotados com @ResourceId
	public static <T> T encodeResourceIds(T object) {
		if (object == null)
			return object;
		try {
			for (Field field : object.getClass().getDeclaredFields()) {
				if (field.isAnnotationPresent(ResourceId.class)) {
					field.setAccessible(true);
					Object value = field.get(object);
					if (value != null) {
						String encrypted = encode(value.toString());
						field.set(object, encrypted);
					}
				}
			}
			return object;
		} catch (Exception e) {
			throw new RuntimeException("Erro ao codificar campos @ResourceId", e);
		}
	}

	// Descriptografa apenas os campos anotados com @ResourceId
	public static <T> T decodeResourceIds(T object) {
		if (object == null)
			return object;
		try {
			for (Field field : object.getClass().getDeclaredFields()) {
				if (field.isAnnotationPresent(ResourceId.class)) {
					field.setAccessible(true);
					Object value = field.get(object);
					if (value != null) {
						String decrypted = decode(value.toString(), String.class);
						Object converted = convertToFieldType(field.getType(), decrypted);
						field.set(object, converted);
					}
				}
			}
			return object;
		} catch (Exception e) {
			throw new RuntimeException("Erro ao decodificar campos @ResourceId", e);
		}
	}

	// Codifica (serializa e criptografa) um objeto Java em uma única String.
	public static <T> String encode(T object) {
		if (object == null) {
			return null;
		}
		try {
			String json = gson.toJson(object);
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

	// Decodifica (descriptografa e desserializa) uma String de volta para um objeto
	// Java.
	public static <T> T decode(String encodedString, Class<T> classOfT) {
		if (encodedString == null || encodedString.trim().isEmpty()) {
			return null;
		}
		try {
			byte[] combined = Base64.getUrlDecoder().decode(encodedString);

			IvParameterSpec ivParameterSpec = new IvParameterSpec(combined, 0, IV_LENGTH_BYTES);
			byte[] encryptedBytes = new byte[combined.length - IV_LENGTH_BYTES];
			System.arraycopy(combined, IV_LENGTH_BYTES, encryptedBytes, 0, encryptedBytes.length);

			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY, ivParameterSpec);
			byte[] decryptedJsonBytes = cipher.doFinal(encryptedBytes);
			String json = new String(decryptedJsonBytes, StandardCharsets.UTF_8);

			return gson.fromJson(json, classOfT);

		} catch (Exception e) {
			throw new RuntimeException("Erro ao decodificar a string para o objeto: " + classOfT.getSimpleName(), e);
		}
	}

	private static Object convertToFieldType(Class<?> type, String value) {
		if (type == String.class)
			return value;
		if (type == Long.class || type == long.class)
			return Long.valueOf(value);
		if (type == Integer.class || type == int.class)
			return Integer.valueOf(value);
		if (type == Short.class || type == short.class)
			return Short.valueOf(value);
		if (type == Double.class || type == double.class)
			return Double.valueOf(value);
		if (type == Float.class || type == float.class)
			return Float.valueOf(value);
		if (type == Boolean.class || type == boolean.class)
			return Boolean.valueOf(value);
		if (type == BigInteger.class)
			return new BigInteger(value);

		return value;
	}
}
