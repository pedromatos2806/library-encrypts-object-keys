package idhash;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Responsável pelo carregamento/rotação das chaves de criptografia.
 * API em português: definirChavesAPartirDeString, adicionarChavePrimaria,
 * obterChaves, obterChavePrimaria.
 */
public final class KeyManager {
    private KeyManager() {
    }

    // internal storage for keys (primary first)
    private static volatile java.util.List<byte[]> KEYS = null;
    private static volatile byte[] PRIMARY = null;

    public static synchronized void inicializarSeNecessario() {
        if (KEYS != null && !KEYS.isEmpty())
            return;
        String keyFromEnv = System.getenv("APP_ENCRYPTION_KEY");
        if (keyFromEnv == null || keyFromEnv.trim().isEmpty()) {
            keyFromEnv = System.getProperty("APP_ENCRYPTION_KEY");
        }
        if (keyFromEnv == null || keyFromEnv.trim().isEmpty()) {
            throw new IllegalStateException(
                    "A variável de ambiente ou propriedade APP_ENCRYPTION_KEY não está definida.");
        }

        String keysList = System.getenv("APP_ENCRYPTION_KEYS");
        if (keysList == null || keysList.trim().isEmpty()) {
            keysList = System.getProperty("APP_ENCRYPTION_KEYS");
        }

        List<byte[]> keys = new ArrayList<>();
        if (keysList != null && !keysList.trim().isEmpty()) {
            String[] parts = keysList.split("[;,]");
            for (String p : parts) {
                String s = p.trim();
                if (s.isEmpty())
                    continue;
                byte[] candidate = null;
                try {
                    candidate = java.util.Base64.getDecoder().decode(s);
                } catch (IllegalArgumentException e) {
                    candidate = null;
                }
                byte[] keyBytes = null;
                if (candidate != null && (candidate.length == 16 || candidate.length == 24 || candidate.length == 32)) {
                    keyBytes = candidate;
                } else {
                    keyBytes = s.getBytes(StandardCharsets.UTF_8);
                }
                if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
                    throw new IllegalArgumentException(
                            "A chave de criptografia fornecida na lista tem tamanho inválido: " + keyBytes.length);
                }
                keys.add(Arrays.copyOf(keyBytes, keyBytes.length));
                Arrays.fill(keyBytes, (byte) 0);
            }
        } else {
            byte[] candidate = null;
            try {
                candidate = java.util.Base64.getDecoder().decode(keyFromEnv);
            } catch (IllegalArgumentException e) {
                candidate = null;
            }
            byte[] keyBytes = null;
            if (candidate != null && (candidate.length == 16 || candidate.length == 24 || candidate.length == 32)) {
                keyBytes = candidate;
            } else {
                keyBytes = keyFromEnv.getBytes(StandardCharsets.UTF_8);
            }
            if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
                throw new IllegalArgumentException(
                        "A chave de criptografia (APP_ENCRYPTION_KEY) deve ter 16, 24 ou 32 bytes (aceita Base64 ou texto). Tamanho fornecido: "
                                + keyBytes.length);
            }
            keys.add(Arrays.copyOf(keyBytes, keyBytes.length));
            Arrays.fill(keyBytes, (byte) 0);
        }

        // store internally
        KEYS = keys;
        PRIMARY = KEYS.get(0);
    }

    public static synchronized void definirChavesAPartirDeString(String keysList) {
        if (keysList == null || keysList.trim().isEmpty()) {
            throw new IllegalArgumentException("keysList não pode ser vazio");
        }
        String[] parts = keysList.split("[;,]");
        List<byte[]> keys = new ArrayList<>();
        for (String p : parts) {
            String s = p.trim();
            if (s.isEmpty())
                continue;
            byte[] candidate = null;
            try {
                candidate = java.util.Base64.getDecoder().decode(s);
            } catch (IllegalArgumentException e) {
                candidate = null;
            }
            byte[] keyBytes = null;
            if (candidate != null && (candidate.length == 16 || candidate.length == 24 || candidate.length == 32)) {
                keyBytes = candidate;
            } else {
                keyBytes = s.getBytes(StandardCharsets.UTF_8);
            }
            if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
                throw new IllegalArgumentException(
                        "A chave de criptografia fornecida na lista tem tamanho inválido: " + keyBytes.length);
            }
            keys.add(Arrays.copyOf(keyBytes, keyBytes.length));
            Arrays.fill(keyBytes, (byte) 0);
        }
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("Nenhuma chave válida encontrada em keysList");
        }
        KEYS = keys;
        PRIMARY = KEYS.get(0);
    }

    public static synchronized void adicionarChavePrimaria(String keyOrBase64) {
        if (keyOrBase64 == null || keyOrBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("keyOrBase64 não pode ser vazio");
        }
        byte[] candidate = null;
        try {
            candidate = java.util.Base64.getDecoder().decode(keyOrBase64);
        } catch (IllegalArgumentException e) {
            candidate = null;
        }
        byte[] keyBytes = null;
        if (candidate != null && (candidate.length == 16 || candidate.length == 24 || candidate.length == 32)) {
            keyBytes = candidate;
        } else {
            keyBytes = keyOrBase64.getBytes(StandardCharsets.UTF_8);
        }
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "A chave de criptografia fornecida tem tamanho inválido: " + keyBytes.length);
        }
        byte[] copy = Arrays.copyOf(keyBytes, keyBytes.length);
        Arrays.fill(keyBytes, (byte) 0);
        if (KEYS == null) {
            KEYS = new ArrayList<>();
        }
        KEYS.add(0, copy);
        PRIMARY = KEYS.get(0);
    }

    public static List<byte[]> obterChaves() {
        inicializarSeNecessario();
        return KEYS;
    }

    public static byte[] obterChavePrimaria() {
        inicializarSeNecessario();
        return PRIMARY;
    }

    /**
     * Utility for tests to reset cached keys/state. Package-private on purpose.
     */
    static synchronized void resetarParaTestes() {
        KEYS = null;
        PRIMARY = null;
    }
}
