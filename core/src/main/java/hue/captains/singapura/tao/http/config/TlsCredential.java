package hue.captains.singapura.tao.http.config;

/**
 * The TLS identity material, composed from the orthogonal {@link ByteSourceProvider} and
 * {@link PasswordProvider} axes.
 * <p>
 * Unlike those axes, the set of container <em>formats</em> is bounded by what the host
 * framework knows how to install, so this sum is {@code sealed} and exhaustively matchable.
 * PEM is a planned addition.
 */
public sealed interface TlsCredential permits TlsCredential.Jks, TlsCredential.Pkcs12 {

    /**
     * A Java KeyStore (JKS), supplied as two provider functions: one yielding the keystore
     * bytes, one yielding its password. The credential is self-sufficient — starting a server
     * needs only these functions, no resolver registry. Build them however you like (a plain
     * lambda, or via the {@link TlsResolvers} spec/resolver utility suite).
     *
     * <p>JKS is Java's legacy proprietary format; prefer {@link Pkcs12} for new keystores.</p>
     *
     * @param store    supplies the keystore bytes
     * @param password supplies the keystore password
     */
    record Jks(ByteSourceProvider store, PasswordProvider password) implements TlsCredential {
    }

    /**
     * A PKCS#12 keystore ({@code .p12} / {@code .pfx}) — the industry-standard container and
     * the JDK's default since Java 9. Same two-provider shape as {@link Jks}.
     *
     * @param store    supplies the keystore bytes
     * @param password supplies the keystore password
     */
    record Pkcs12(ByteSourceProvider store, PasswordProvider password) implements TlsCredential {
    }
}
