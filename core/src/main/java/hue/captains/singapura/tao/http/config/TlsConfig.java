package hue.captains.singapura.tao.http.config;

/**
 * Pure value object describing the TLS configuration for a host.
 * <p>
 * Holds no bytes or secrets of its own: the {@link TlsCredential} carries provider
 * functions that are invoked at server-start time (or by {@link TlsConfigResolver}) to
 * obtain the material. Kept as a wrapper (rather than exposing {@link TlsCredential}
 * directly) so future TLS options — client auth, enabled protocols, cipher suites — can be
 * added without changing host signatures.
 *
 * @param credential the TLS identity material to serve
 */
public record TlsConfig(TlsCredential credential) {
}
