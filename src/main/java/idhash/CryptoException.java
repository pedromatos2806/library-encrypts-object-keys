package idhash;

/**
 * Exceção unchecked para erros de criptografia/decodificação.
 */
public class CryptoException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoException(String message) {
        super(message);
    }
}
