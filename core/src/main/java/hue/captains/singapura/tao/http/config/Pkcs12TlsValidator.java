package hue.captains.singapura.tao.http.config;

/**
 * Validates resolved PKCS#12 material: loads it as a {@code "PKCS12"}
 * {@link java.security.KeyStore}, then reports each alias with its key/cert status and
 * certificate validity window.
 *
 * <p>PKCS#12 is the industry-standard container and the JDK's default keystore type since
 * Java 9 — the format {@code .p12} / {@code .pfx} files use.</p>
 */
public final class Pkcs12TlsValidator implements TlsCredentialValidator<ResolvedTlsCredential.Pkcs12> {

    static final String STORE_TYPE = "PKCS12";

    @Override
    public Class<ResolvedTlsCredential.Pkcs12> resolvedType() {
        return ResolvedTlsCredential.Pkcs12.class;
    }

    @Override
    public TlsValidationReport validate(ResolvedTlsCredential.Pkcs12 resolved)
            throws TlsValidationException {
        return PasswordProtectedKeyStores.validate(
                STORE_TYPE, resolved.keyStore(), resolved.password());
    }
}
