package idhash;

import java.lang.reflect.Field;
import java.util.List;
import java.util.StringTokenizer;

public class ObjectObfuscator {

	// token usado pela codificação de ResourceId
	public static final String TOKEN = "|*|";

	private String resourceId;
	// chave agora gerenciada por KeyManager

	public String getResourceId() {
		return resourceId;
	}

	public void setResourceId(String resourceId) {
		this.resourceId = resourceId;
	}

	public void encode() {
		List<Field> idFields = ResourceIdProcessor.obterCamposId(getClass());
		try {
			String concatenated = ResourceIdProcessor.obterValor(idFields, this);
			if (concatenated != null) {
				setResourceId(CryptoService.criptografar(concatenated));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void decode() {
		String values = getResourceId();
		List<Field> fields = ResourceIdProcessor.obterCamposId(getClass());
		try {
			String decoded = values;
			if (decoded != null) {
				decoded = CryptoService.descriptografar(decoded);
			}
			ResourceIdProcessor.atribuirValor(fields,
					(decoded != null && !decoded.trim().isEmpty()) ? new StringTokenizer(decoded, TOKEN) : null, this);
		} catch (Exception e) {
			e.printStackTrace();
		}
		setResourceId(null);
	}

	// APIs estáticas compatíveis retroativamente para crypto/keys delegando aos
	// novos serviços
	public static String criptografar(String idsConcatenados) {
		return CryptoService.criptografar(idsConcatenados);
	}

	public static String descriptografar(String encodedIds) {
		return CryptoService.descriptografar(encodedIds);
	}

	public static String criptografarLegadoCBC(String plain) {
		return LegacyCrypto.criptografarCBCComChave(plain, KeyManager.obterChavePrimaria());
	}

	public static String migrarParaGcm(String legacyEncoded) throws CryptoException {
		String plain = LegacyCrypto.descriptografarCBC(legacyEncoded);
		return CryptoService.criptografar(plain);
	}

	// Compatibilidade: nome antigo em inglês usado por alguns testes/consumidores
	public static String migrateToGcm(String legacyEncoded) throws CryptoException {
		return migrarParaGcm(legacyEncoded);
	}

	public static String recriptografarParaPrimaria(String ciphertext) throws CryptoException {
		if (ciphertext == null || ciphertext.trim().isEmpty())
			return null;
		String plain = CryptoService.descriptografar(ciphertext);
		return CryptoService.criptografar(plain);
	}

	public static synchronized void setKeysFromString(String keysList) {
		KeyManager.definirChavesAPartirDeString(keysList);
	}

	public static synchronized void addPrimaryKey(String keyOrBase64) {
		KeyManager.adicionarChavePrimaria(keyOrBase64);
	}

}