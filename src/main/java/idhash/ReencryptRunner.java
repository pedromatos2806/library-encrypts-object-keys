package idhash;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;

public class ReencryptRunner {

    /**
     * Simple CLI that reads ciphertexts (one per line) from stdin and writes the
     * re-encrypted
     * ciphertext (using primary key) to stdout. If a line cannot be decrypted,
     * prints a warning
     * to stderr and (optionally) prints the original line.
     */
    public static void main(String[] args) throws Exception {
        boolean dryRun = false;
        for (String a : args) {
            if ("--dry-run".equals(a))
                dryRun = true;
        }

        BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
        PrintStream out = System.out;
        PrintStream err = System.err;
        String line;
        while ((line = r.readLine()) != null) {
            if (line.trim().isEmpty())
                continue;
            try {
                String re = ObjectObfuscator.recriptografarParaPrimaria(line.trim());
                if (dryRun) {
                    out.println("DRY-RUN: " + re);
                } else {
                    out.println(re);
                }
            } catch (Exception e) {
                err.println("Failed to reencrypt line: " + e.getMessage());
                out.println(line);
            }
        }
    }

}
