package hue.captains.singapura.tao.http.config;

import java.io.IOException;

/**
 * Supplies a secret (e.g. a keystore password) on demand. The function a
 * {@link TlsCredential} carries directly; orthogonal to {@link ByteSourceProvider}.
 *
 * <p>The {@link PasswordSpec} / {@link PasswordResolver} / {@link TlsResolvers} suite is an
 * optional utility for <em>building</em> one of these (see
 * {@link TlsResolvers#passwordProvider}); downstream may also supply any other lambda.</p>
 */
@FunctionalInterface
public interface PasswordProvider {

    /**
     * Produces the secret. Returned as a {@code char[]} so the caller can overwrite it
     * once the material has been used.
     *
     * @return the secret characters
     * @throws IOException if the secret cannot be obtained
     */
    char[] get() throws IOException;
}
