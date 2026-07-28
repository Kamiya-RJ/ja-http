package hue.captains.singapura.tao.http.config;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The two TLS stages: {@link TlsConfigResolver} (resolve) then {@link TlsValidator} (validate). */
class TlsValidatorTest {

    private static byte[] jksBytes;
    private static byte[] p12Bytes;

    @BeforeAll
    static void loadFixtures() throws IOException {
        jksBytes = fixture("/test-keystore.jks");
        p12Bytes = fixture("/test-keystore.p12");
    }

    private static byte[] fixture(String resource) throws IOException {
        try (var in = TlsValidatorTest.class.getResourceAsStream(resource)) {
            assertNotNull(in, resource + " fixture must be on the test classpath");
            return in.readAllBytes();
        }
    }

    private static TlsCredential.Jks jksCredential() {
        return new TlsCredential.Jks(() -> jksBytes, () -> "testpass".toCharArray());
    }

    private static TlsCredential.Pkcs12 pkcs12Credential() {
        return new TlsCredential.Pkcs12(() -> p12Bytes, () -> "testpass".toCharArray());
    }

    @Test
    void resolveThenValidate_jks_reportsEntry() throws Exception {
        // Stage A — invoke the credential's providers to get concrete material.
        ResolvedTlsCredential resolved = new TlsConfigResolver().resolve(jksCredential());

        // Stage B — validate the resolved material.
        TlsValidationReport report = new TlsValidator().validate(resolved);

        assertEquals("JKS", report.storeType());
        assertEquals(1, report.entries().size());
        var entry = report.entries().get(0);
        assertEquals("testcert", entry.alias());
        assertTrue(entry.keyEntry(), "fixture alias is a private-key entry");
        assertTrue(entry.keyRecoverable(), "key must be recoverable with the store password");
        assertNotNull(entry.notAfter());
        assertTrue(report.validAt(Instant.now()), "fixture cert is valid for ~10 years");
    }

    @Test
    void resolveThenValidate_pkcs12_reportsEntry() throws Exception {
        ResolvedTlsCredential resolved = new TlsConfigResolver().resolve(pkcs12Credential());

        TlsValidationReport report = new TlsValidator().validate(resolved);

        assertEquals("PKCS12", report.storeType());
        assertEquals(1, report.entries().size());
        var entry = report.entries().get(0);
        assertEquals("testcert", entry.alias());
        assertTrue(entry.keyEntry());
        assertTrue(entry.keyRecoverable());
        assertTrue(report.validAt(Instant.now()));
    }

    @Test
    void validate_jksWrongPassword_isClassified() {
        var resolved = new ResolvedTlsCredential.Jks(jksBytes, "wrong".toCharArray());

        var ex = assertThrows(TlsValidationException.class,
                () -> new TlsValidator().validate(resolved));
        assertEquals(TlsValidationException.Kind.WRONG_PASSWORD, ex.kind());
    }

    @Test
    void validate_pkcs12WrongPassword_isClassified() {
        var resolved = new ResolvedTlsCredential.Pkcs12(p12Bytes, "wrong".toCharArray());

        var ex = assertThrows(TlsValidationException.class,
                () -> new TlsValidator().validate(resolved));
        assertEquals(TlsValidationException.Kind.WRONG_PASSWORD, ex.kind());
    }

    @Test
    void validate_corruptBytes_isClassified() {
        var resolved = new ResolvedTlsCredential.Pkcs12(
                "definitely not a keystore".getBytes(), "x".toCharArray());

        var ex = assertThrows(TlsValidationException.class,
                () -> new TlsValidator().validate(resolved));
        assertEquals(TlsValidationException.Kind.BAD_FORMAT, ex.kind());
    }

    @Test
    void validAt_isFalseAfterExpiry() throws Exception {
        var resolved = new TlsConfigResolver().resolve(jksCredential());
        var report = new TlsValidator().validate(resolved);

        var farFuture = Instant.now().plusSeconds(20L * 365 * 24 * 3600); // 20 years out
        assertFalse(report.validAt(farFuture));
        assertEquals(1, report.expiredAt(farFuture).size());
    }
}
