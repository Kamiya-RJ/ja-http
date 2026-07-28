package hue.captains.singapura.tao.http.vertx;

import hue.captains.singapura.tao.http.config.ByteSourceProvider;
import hue.captains.singapura.tao.http.config.HostConfig;
import hue.captains.singapura.tao.http.config.PasswordProvider;
import hue.captains.singapura.tao.http.config.TlsCredential;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JksOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.KeyStoreOptionsBase;
import io.vertx.core.net.PfxOptions;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;

/**
 * Maps the framework-agnostic {@link HostConfig} TLS settings onto Vert.x
 * {@link HttpServerOptions} by invoking the credential's provider functions. No resolver
 * registry is involved — the credential is self-sufficient.
 */
public final class VertxTls {

    private VertxTls() {
    }

    /**
     * Returns server options for {@code config}. Plain HTTP yields default options;
     * HTTPS yields SSL-enabled options with the key/cert material the credential supplies.
     */
    public static HttpServerOptions serverOptions(HostConfig config) {
        var options = new HttpServerOptions();
        if (!config.isTls()) {
            return options;
        }
        return options
                .setSsl(true)
                .setKeyCertOptions(keyCertOptions(config.tls().credential()));
    }

    private static KeyCertOptions keyCertOptions(TlsCredential credential) {
        try {
            return switch (credential) {
                case TlsCredential.Jks jks ->
                        keyStore(new JksOptions(), jks.store(), jks.password());
                case TlsCredential.Pkcs12 p12 ->
                        keyStore(new PfxOptions(), p12.store(), p12.password());
            };
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to obtain TLS material", e);
        }
    }

    /** Installs provider-supplied bytes + password into a keystore-backed options object. */
    private static KeyCertOptions keyStore(KeyStoreOptionsBase options,
                                           ByteSourceProvider store,
                                           PasswordProvider password) throws IOException {
        char[] secret = password.get();
        try {
            return options
                    .setValue(Buffer.buffer(store.get()))
                    .setPassword(new String(secret));
        } finally {
            Arrays.fill(secret, '\0');
        }
    }
}
