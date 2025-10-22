package idhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.Test;

class ObjectObfuscatorReencryptTest {

    @Test
    void testReencryptToPrimary() {
        byte[] kOld = new byte[16];
        byte[] kNew = new byte[16];
        new java.security.SecureRandom().nextBytes(kOld);
        new java.security.SecureRandom().nextBytes(kNew);
        String sOld = java.util.Base64.getEncoder().encodeToString(kOld);
        String sNew = java.util.Base64.getEncoder().encodeToString(kNew);

        // encriptar com a chave antiga
        ObjectObfuscator.setKeysFromString(sOld);
        String plain = "reencrypt-me";
        String cipherOld = ObjectObfuscator.criptografar(plain);

        // configurar nova primary e old como secondary
        ObjectObfuscator.setKeysFromString(sNew + ";" + sOld);

        String re = ObjectObfuscator.recriptografarParaPrimaria(cipherOld);
        assertNotNull(re);
        // garantir que re-decrypt retorna o plain
        assertEquals(plain, ObjectObfuscator.descriptografar(re));
    }

    @Test
    void testReencryptRunnerIntegration() throws Exception {
        byte[] kOld = new byte[16];
        byte[] kNew = new byte[16];
        new java.security.SecureRandom().nextBytes(kOld);
        new java.security.SecureRandom().nextBytes(kNew);
        String sOld = java.util.Base64.getEncoder().encodeToString(kOld);
        String sNew = java.util.Base64.getEncoder().encodeToString(kNew);

        ObjectObfuscator.setKeysFromString(sOld);
        String plain = "line1";
        String cipherOld = ObjectObfuscator.criptografar(plain);

        ObjectObfuscator.setKeysFromString(sNew + ";" + sOld);

        // simular stdin com a linha do cipher antigo
        ByteArrayInputStream in = new ByteArrayInputStream((cipherOld + "\n").getBytes());
        ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();

        PrintStream oldOut = System.out;
        PrintStream oldErr = System.err;
        java.io.InputStream oldIn = System.in;
        System.setIn(in);
        try (PrintStream psOut = new PrintStream(outBuf); PrintStream psErr = new PrintStream(errBuf)) {
            System.setOut(psOut);
            System.setErr(psErr);

            ReencryptRunner.main(new String[] {});

            String output = outBuf.toString().trim();
            assertFalse(output.isEmpty());
            // decrypted value should match plain
            String re = output.split("\\r?\\n")[0];
            assertEquals(plain, ObjectObfuscator.descriptografar(re));
        } finally {
            System.setIn(oldIn);
            System.setOut(oldOut);
            System.setErr(oldErr);
        }
    }

}
