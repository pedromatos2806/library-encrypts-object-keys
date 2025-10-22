package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ObjectObfuscatorTest {

	@BeforeAll
	public static void setupKey() {
		// usar uma chave de 16 bytes para os testes
		String key = Base64.getEncoder().encodeToString("0123456789abcdef".getBytes());
		System.setProperty("APP_ENCRYPTION_KEY", key);
	}

	@Test
	public void testGcmRoundTrip() {
		String original = "mensagem-teste-çãó";
		String enc = ObjectObfuscator.criptografar(original);
		assertNotNull(enc);
		String dec = ObjectObfuscator.descriptografar(enc);
		assertEquals(original, dec);
	}

	@Test
	public void testLegacyCbcFallbackAndMigrate() throws Exception {
		// criar um ciphertext CBC legada manualmente
		String original = "legacy-mensagem";

		// criar ciphertext CBC usando o helper
		String legacyEncoded = ObjectObfuscator.criptografarLegadoCBC(original);

		// o decrypt deve fazer fallback e retornar o plaintext
		String dec = ObjectObfuscator.descriptografar(legacyEncoded);
		assertEquals(original, dec);

		// migrar deve re-encriptar para GCM e o novo decrypt deve retornar o mesmo
		// valor
		String migrated = ObjectObfuscator.migrarParaGcm(legacyEncoded);
		assertNotNull(migrated);
		assertNotEquals(legacyEncoded, migrated);
		String dec2 = ObjectObfuscator.descriptografar(migrated);
		assertEquals(original, dec2);
	}
}
