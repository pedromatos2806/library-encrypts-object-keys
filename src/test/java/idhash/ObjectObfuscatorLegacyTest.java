package idhash;

import static com.github.stefanbirkner.systemlambda.SystemLambda.withEnvironmentVariable;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ObjectObfuscatorLegacyTest {

    static final String TEST_KEY = "1234567890123456"; // 16 bytes para AES-128

    @DisplayName("Classe de teste simulando uma classe presenter com vários tipos de id's.")
    static class TestModel extends ObjectObfuscator {
        @ResourceId
        public String id;

        @ResourceId
        public Long idLong;

        @ResourceId
        public Integer idInt;

        @ResourceId
        public BigInteger idBigInt;

        private TestModel() {
        }

        public TestModel(String id, Long idLong, Integer idInt, BigInteger idBigInt) {
            this.id = id;
            this.idLong = idLong;
            this.idInt = idInt;
            this.idBigInt = idBigInt;
            this.encode();
        }

        public static TestModel valueOf(String resourceId) {
            TestModel vm = new TestModel();
            vm.setResourceId(resourceId);
            vm.decode();
            return vm;
        }

        public String getId() {
            return id;
        }

        public Long getIdLong() {
            return idLong;
        }

        public Integer getIdInt() {
            return idInt;
        }

        public BigInteger getIdBigInt() {
            return idBigInt;
        }

    }

    @DisplayName("Esse teste é responsável por fazer criptografia simétrica e descriptografar simulando uma classe Presenter.")
    @Test
    void testEncodeAndDecodeResourceIds() throws Exception {
        withEnvironmentVariable("APP_ENCRYPTION_KEY", TEST_KEY).execute(() -> {
            String id = "abc";
            Long idLong = 123L;
            Integer idInt = 42;
            BigInteger idBigInt = new BigInteger("987654321");

            TestModel model = new TestModel(id, idLong, idInt, idBigInt);

            TestModel valor = TestModel.valueOf(model.getResourceId());

            assertEquals("abc", valor.getId());
            assertEquals(123L, valor.getIdLong());
            assertEquals(42, valor.getIdInt());
            assertEquals(new BigInteger("987654321"), valor.getIdBigInt());
        });
    }

}
