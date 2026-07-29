package hue.captains.singapura.tao.http.config;

import hue.captains.singapura.tao.http.config.builtin.FileByteSource;
import hue.captains.singapura.tao.http.config.builtin.LiteralPassword;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The optional spec/resolver utility suite — the registry, the built-ins, and the bridge
 * that turns a spec into the provider function a {@link TlsCredential} consumes.
 */
class TlsResolversTest {

    /** A downstream-defined spec, proving the sums stay open. */
    private record InMemoryBytes(byte[] bytes) implements ByteSourceSpec {
    }

    private record ConstantPassword(String value) implements PasswordSpec {
    }

    private static ByteSourceResolver<InMemoryBytes> inMemoryResolver() {
        return new ByteSourceResolver<>() {
            @Override
            public Class<InMemoryBytes> specType() {
                return InMemoryBytes.class;
            }

            @Override
            public byte[] resolve(InMemoryBytes spec) {
                return spec.bytes();
            }
        };
    }

    private static PasswordResolver<ConstantPassword> constantResolver() {
        return new PasswordResolver<>() {
            @Override
            public Class<ConstantPassword> specType() {
                return ConstantPassword.class;
            }

            @Override
            public char[] resolve(ConstantPassword spec) {
                return spec.value().toCharArray();
            }
        };
    }

    @Test
    void defaults_resolveFileAndLiteralBuiltins(@TempDir Path dir) throws IOException {
        var file = dir.resolve("keystore.bin");
        Files.write(file, new byte[]{1, 2, 3});
        var resolvers = TlsResolvers.defaults();

        assertArrayEquals(new byte[]{1, 2, 3},
                resolvers.resolveByteSource(new FileByteSource(file.toString())));
        assertArrayEquals("changeit".toCharArray(),
                resolvers.resolvePassword(LiteralPassword.of("changeit")));
    }

    @Test
    void fileByteSource_missingPathFails() {
        var resolvers = TlsResolvers.defaults();

        assertThrows(IOException.class,
                () -> resolvers.resolveByteSource(new FileByteSource("does/not/exist.p12")));
    }

    @Test
    void downstreamSpecsAreDispatchedToTheirResolvers() throws IOException {
        var resolvers = TlsResolvers.defaults()
                .register(inMemoryResolver())
                .register(constantResolver());

        assertArrayEquals(new byte[]{9},
                resolvers.resolveByteSource(new InMemoryBytes(new byte[]{9})));
        assertArrayEquals("s3cret".toCharArray(),
                resolvers.resolvePassword(new ConstantPassword("s3cret")));
    }

    @Test
    void unregisteredSpecFailsFastAndNamesTheType() {
        var resolvers = TlsResolvers.defaults();

        var byteFailure = assertThrows(IllegalStateException.class,
                () -> resolvers.resolveByteSource(new InMemoryBytes(new byte[0])));
        assertTrue(byteFailure.getMessage().contains("InMemoryBytes"),
                "message should name the unresolved spec, was: " + byteFailure.getMessage());

        var passwordFailure = assertThrows(IllegalStateException.class,
                () -> resolvers.resolvePassword(new ConstantPassword("x")));
        assertTrue(passwordFailure.getMessage().contains("ConstantPassword"),
                "message should name the unresolved spec, was: " + passwordFailure.getMessage());
    }

    @Test
    void providerBridge_buildsCredentialProviders(@TempDir Path dir) throws IOException {
        var file = dir.resolve("keystore.bin");
        Files.write(file, new byte[]{7, 7});
        var resolvers = TlsResolvers.defaults();

        var credential = new TlsCredential.Pkcs12(
                resolvers.byteSourceProvider(new FileByteSource(file.toString())),
                resolvers.passwordProvider(LiteralPassword.of("changeit")));

        var resolved = (ResolvedTlsCredential.Pkcs12) new TlsConfigResolver().resolve(credential);
        assertArrayEquals(new byte[]{7, 7}, resolved.keyStore());
        assertArrayEquals("changeit".toCharArray(), resolved.password());
    }

    @Test
    void providerBridge_isDeferredUntilInvoked() throws IOException {
        var calls = new AtomicInteger();
        var resolvers = TlsResolvers.defaults().register(new ByteSourceResolver<InMemoryBytes>() {
            @Override
            public Class<InMemoryBytes> specType() {
                return InMemoryBytes.class;
            }

            @Override
            public byte[] resolve(InMemoryBytes spec) {
                calls.incrementAndGet();
                return spec.bytes();
            }
        });

        var provider = resolvers.byteSourceProvider(new InMemoryBytes(new byte[]{4}));
        assertEquals(0, calls.get(), "building a provider must not resolve anything yet");

        provider.get();
        assertEquals(1, calls.get(), "resolution happens on get()");
    }
}
