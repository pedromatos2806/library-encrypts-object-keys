package idhash;

import static com.github.stefanbirkner.systemlambda.SystemLambda.withEnvironmentVariable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class ObjectObfuscatorTest {

    static final String TEST_KEY = "1234567890123456"; // 16 bytes para AES-128

    @BeforeAll
    static void setupEnv() {
        System.setProperty("APP_ENCRYPTION_KEY", TEST_KEY);
    }

    static class TestModel {
        @ResourceId
        public String id;
        @ResourceId
        public String idLong; 
        public String nome;
    }

    @Test
    void testEncodeResourceIds() throws Exception {
        withEnvironmentVariable("APP_ENCRYPTION_KEY", TEST_KEY)
            .execute(() -> {
                TestModel model = new TestModel();
                model.id = "abc";
                model.idLong = Long.toString(123L);
                model.nome = "Pedro";

                ObjectObfuscator.encodeResourceIds(model);

                assertNotEquals("abc", model.id);
                assertNotEquals(123L, model.idLong);
                assertEquals("Pedro", model.nome);
            });
    }

    @Test
    void testDecodeResourceIds() {
       
    	try {
			withEnvironmentVariable("APP_ENCRYPTION_KEY", TEST_KEY)
			.execute(() -> {
				TestModel model = new TestModel();
			    model.id = "abc";
			    model.idLong = Long.toString(123L);
			    model.nome = "Pedro";

			    ObjectObfuscator.encodeResourceIds(model);
			    ObjectObfuscator.decodeResourceIds(model);

			    assertEquals("abc", model.id);
			    assertEquals( Long.toString(123L), model.idLong);
			    assertEquals("Pedro", model.nome);
			});
		} catch (Exception e) {
			e.printStackTrace();
		}
    	
    }

    @Test
    void testEncode() {
        TestModel model = new TestModel();
        model.id = "abc";
        model.idLong = Long.toString(123L);
        model.nome = "Pedro";

        String encoded = ObjectObfuscator.encode(model);
        assertNotNull(encoded);
        assertNotEquals("", encoded);
        assertNotEquals("abc", encoded);
    }

    @Test
    void testDecode() {
        TestModel model = new TestModel();
        model.id = "abc";
        model.idLong = Long.toString(123L);
        model.nome = "Pedro";

        String encoded = ObjectObfuscator.encode(model);
        TestModel decoded = ObjectObfuscator.decode(encoded, TestModel.class);

        assertEquals(model.id, decoded.id);
        assertEquals(model.idLong, decoded.idLong);
        assertEquals(model.nome, decoded.nome);
    }
}
