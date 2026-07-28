package hue.captains.singapura.tao.http.config;

/**
 * Validates resolved JKS material: loads it as a {@code "JKS"} {@link java.security.KeyStore}
 * (which verifies the password and format), then reports each alias with its key/cert status
 * and certificate validity window.
 *
 * <p>JKS is Java's legacy proprietary format; prefer {@link Pkcs12TlsValidator} / PKCS#12 for
 * new keystores.</p>
 */
public final class JksTlsValidator implements TlsCredentialValidator<ResolvedTlsCredential.Jks> {

    static final String STORE_TYPE = "JKS";

    @Override
    public Class<ResolvedTlsCredential.Jks> resolvedType() {
        return ResolvedTlsCredential.Jks.class;
    }

    @Override
    public TlsValidationReport validate(ResolvedTlsCredential.Jks resolved)
            throws TlsValidationException {
        return PasswordProtectedKeyStores.validate(
                STORE_TYPE, resolved.keyStore(), resolved.password());
    }
}
