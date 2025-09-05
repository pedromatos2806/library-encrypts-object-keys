package idhash;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;

public class ObjectObfuscator {

	private static final String ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private static final int IV_LENGTH_BYTES = 16;
	private static final SecretKeySpec SECRET_KEY;
	private static final String TOKEN = "|*|";
	
	private String resourceId;

	static {
		String keyFromEnv = System.getenv("APP_ENCRYPTION_KEY");
		if (keyFromEnv == null || StringUtils.isBlank(keyFromEnv)) {
			throw new IllegalStateException("A variável de ambiente APP_ENCRYPTION_KEY não está definida.");
		}
		byte[] keyBytes = keyFromEnv.getBytes(StandardCharsets.UTF_8);
		if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
			throw new IllegalArgumentException("A chave de criptografia deve ter 16, 24 ou 32 bytes.");
		}
		SECRET_KEY = new SecretKeySpec(keyBytes, ALGORITHM);
	}

	public String getResourceId() {
		return resourceId;
	}

	public void setResourceId(String resourceId) {
		this.resourceId = resourceId;
	}

	public void encode() {
		List<Field> idFields = getIdFields(getClass());
		try {
			setResourceId(encodeIds(idFields));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private List<Field> getIdFields(Class<?> classe) {
		List<Field> idFields = new ArrayList<>();

		Class<?> classePai = classe.getSuperclass();
		if (!classePai.equals(ObjectObfuscator.class)) {
			idFields.addAll(getIdFields(classePai));
		}
		Field[] attributes = classe.getDeclaredFields();
		for (Field field : attributes) {
			if (field.getAnnotation(ResourceId.class) != null) {
				idFields.add(field);
			}
		}

		return idFields;
	}

	private String encodeIds(List<Field> idFields) throws IllegalAccessException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String encoded = null;

		String idConcatenado = descobrirValor(idFields, this);
		encoded = encode(idConcatenado);

		return encoded;
	}
	
	private String encode(String ids) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String encoded = null;
		if (ids != null) {
			encoded = encrypt(ids);
		}
		return encoded;
	}
	
	

	private String descobrirValor(List<Field> idFields, Object referencia) throws IllegalAccessException {
		StringBuilder idConcatenado = new StringBuilder("");
		for (Field field : idFields) {
			field.setAccessible(true);
			Object fieldInstance = field.get(referencia);

			boolean ignoredField = false;

			if (fieldInstance instanceof ObjectObfuscator) {
				List<Field> fieldInstanceFields = ((ObjectObfuscator) fieldInstance).getIdFields(fieldInstance.getClass());
				idConcatenado.append(descobrirValor(fieldInstanceFields, fieldInstance));
			} else {
				if (fieldInstance != null) {
					idConcatenado.append(fieldInstance.toString());
				} else {
					throw new IllegalArgumentException("O atributo " + field.getName() + " está null.");
				}
				if (!ignoredField) {
					idConcatenado.append(TOKEN);
				}
			}
			if (!showValue(field)) {
				field.set(referencia, null);
			}
		}
		return idConcatenado.toString();
	}
	
	private boolean showValue(Field field) {

		boolean retorno = false;
		ResourceId lResourceId = field.getAnnotation(ResourceId.class);

		if (lResourceId != null) {
			retorno = lResourceId.showValue();
		} else {
			// Unreachable code...
			assert false;
		}

		return retorno;
	}

	public void decode() {
		String values = null;
		try {
			values = decode(getResourceId());
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
				| BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		List<Field> fields = getIdFields(getClass());
		try {
			decodeIds(fields, values);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		setResourceId(null);
	}
	
	private String decode(String ids) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String decoded = null;
		if (ids != null) {
			decoded = decrypt(ids);
		}
		
		return decoded;
	}
	
	private void decodeIds(List<Field> fields, String values) throws Exception {
		try {
			StringTokenizer st = null;
			if (org.apache.commons.lang3.StringUtils.isNotBlank(values)) {
				st = new StringTokenizer(values, TOKEN);
			}
			atribuirValor(fields, st, this);
		} catch (Exception e) {
			throw new Exception("Problemas ao decodificar resource IDs: " + values, e);
		}
	}
	
	private void atribuirValor(List<Field> fields, StringTokenizer st, Object referencia) throws IllegalArgumentException, Exception {
		for (Field field : fields) {
			field.setAccessible(true);
			if (st == null) {
				if (ObjectObfuscator.class.isAssignableFrom(field.getType())) {
					((ObjectObfuscator) field.get(this)).decode();
				}
			} else if (ObjectObfuscator.class.isAssignableFrom(field.getType())) {
				Object fieldInstance = field.get(referencia);
				if (fieldInstance == null) {
					fieldInstance = field.getType().newInstance();
				}
				List<Field> fieldInstanceFields = ((ObjectObfuscator) fieldInstance).getIdFields(fieldInstance.getClass());
				atribuirValor(fieldInstanceFields, st, fieldInstance);
				field.set(referencia, fieldInstance);
			} else {
				field.set(referencia, parseId(field, st.nextElement().toString()));
			}
		}
	}
	
	private Object parseId(Field field, String value) {
		if ("[NULL_ID]".equals(value)) {

			throw new IllegalArgumentException("O atributo " + field.getName() + " está null.");
		}
		if (field.getType().equals(Integer.class)) {
			return Integer.parseInt(value);
		}
		if (field.getType().equals(Long.class)) {
			return Long.parseLong(value);
		}
		if (field.getType().equals(Byte.class)) {
			return (byte) Integer.parseInt(value);
		}
		if (field.getType().equals(java.math.BigInteger.class)) {
			return new java.math.BigInteger(value);
		}
		if (field.getType().equals(java.math.BigDecimal.class)) {
			return new java.math.BigDecimal(value);
		}

		return value;
	}
	
	
	public static String encrypt(String idsConcatenados) {
	    if (idsConcatenados == null || idsConcatenados.trim().isEmpty()) {
	        return null;
	    }
	    try {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        byte[] iv = new byte[IV_LENGTH_BYTES];
	        new SecureRandom().nextBytes(iv);
	        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

	        cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, ivParameterSpec);
	        byte[] encryptedBytes = cipher.doFinal(idsConcatenados.getBytes(StandardCharsets.UTF_8));

	        byte[] combined = new byte[iv.length + encryptedBytes.length];
	        System.arraycopy(iv, 0, combined, 0, iv.length);
	        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

	        return java.util.Base64.getUrlEncoder().encodeToString(combined);

	    } catch (Exception e) {
	        throw new RuntimeException("Erro ao codificar os IDs concatenados", e);
	    }
	}
	
	
	public static String decrypt(String encodedIds) {
	    if (encodedIds == null || encodedIds.trim().isEmpty()) {
	        return null;
	    }
	    try {
	        byte[] combined = java.util.Base64.getUrlDecoder().decode(encodedIds);

	        IvParameterSpec ivParameterSpec = new IvParameterSpec(combined, 0, IV_LENGTH_BYTES);
	        byte[] encryptedBytes = new byte[combined.length - IV_LENGTH_BYTES];
	        System.arraycopy(combined, IV_LENGTH_BYTES, encryptedBytes, 0, encryptedBytes.length);

	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY, ivParameterSpec);
	        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

	        return new String(decryptedBytes, StandardCharsets.UTF_8);
	    } catch (Exception e) {
	        throw new RuntimeException("Erro ao decodificar os IDs concatenados", e);
	    }
	}
	

	
}