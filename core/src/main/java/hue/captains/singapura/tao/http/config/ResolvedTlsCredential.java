package hue.captains.singapura.tao.http.config;

/**
 * The concrete material produced by Stage A (resolution) — the {@link TlsCredential}'s
 * provider functions invoked to yield bytes and secret. This is the input to Stage B
 * (validation). Mirrors the {@link TlsCredential} sum, one resolved variant per format.
 *
 * @see TlsConfigResolver
 * @see TlsValidator
 */
public sealed interface ResolvedTlsCredential
        permits ResolvedTlsCredential.Jks, ResolvedTlsCredential.Pkcs12 {

    /** A resolved JKS keystore: the raw keystore bytes plus the store password. */
    record Jks(byte[] keyStore, char[] password) implements ResolvedTlsCredential {
    }

    /** A resolved PKCS#12 keystore: the raw keystore bytes plus the store password. */
    record Pkcs12(byte[] keyStore, char[] password) implements ResolvedTlsCredential {
    }
}
