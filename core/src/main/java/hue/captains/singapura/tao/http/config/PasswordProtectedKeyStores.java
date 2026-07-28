package hue.captains.singapura.tao.http.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared loading/inspection for the password-protected {@link KeyStore} container formats
 * (JKS, PKCS#12), which differ only by type string. Used by {@link JksTlsValidator} and
 * {@link Pkcs12TlsValidator}; each format keeps its own validator so the per-type seam holds.
 */
final class PasswordProtectedKeyStores {

    private PasswordProtectedKeyStores() {
    }

    /** Loads {@code bytes} as a {@code storeType} keystore and reports every alias. */
    static TlsValidationReport validate(String storeType, byte[] bytes, char[] password)
            throws TlsValidationException {
        var keyStore = load(storeType, bytes, password);
        return new TlsValidationReport(storeType, entries(keyStore, password));
    }

    private static KeyStore load(String storeType, byte[] bytes, char[] password)
            throws TlsValidationException {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(storeType);
        } catch (KeyStoreException e) {
            throw new TlsValidationException(TlsValidationException.Kind.UNSUPPORTED,
                    storeType + " keystore type is unavailable in this JVM", e);
        }
        try (var in = new ByteArrayInputStream(bytes)) {
            keyStore.load(in, password);
        } catch (IOException e) {
            if (e.getCause() instanceof UnrecoverableKeyException) {
                throw new TlsValidationException(TlsValidationException.Kind.WRONG_PASSWORD,
                        "Incorrect keystore password", e);
            }
            throw new TlsValidationException(TlsValidationException.Kind.BAD_FORMAT,
                    "Keystore could not be read (corrupt bytes, wrong password, or not a "
                            + storeType + " keystore)", e);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new TlsValidationException(TlsValidationException.Kind.BAD_FORMAT,
                    "Keystore integrity or certificate check failed", e);
        }
        return keyStore;
    }

    private static List<TlsValidationReport.Entry> entries(KeyStore keyStore, char[] password)
            throws TlsValidationException {
        var entries = new ArrayList<TlsValidationReport.Entry>();
        try {
            for (var aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                boolean keyEntry = keyStore.isKeyEntry(alias);
                boolean keyRecoverable = keyEntry && keyRecoverable(keyStore, alias, password);

                Instant notBefore = null;
                Instant notAfter = null;
                if (keyStore.getCertificate(alias) instanceof X509Certificate x509) {
                    notBefore = x509.getNotBefore().toInstant();
                    notAfter = x509.getNotAfter().toInstant();
                }
                entries.add(new TlsValidationReport.Entry(
                        alias, keyEntry, keyRecoverable, notBefore, notAfter));
            }
        } catch (KeyStoreException e) {
            throw new TlsValidationException(TlsValidationException.Kind.BAD_FORMAT,
                    "Failed to enumerate keystore entries", e);
        }
        return List.copyOf(entries);
    }

    private static boolean keyRecoverable(KeyStore keyStore, String alias, char[] password)
            throws TlsValidationException {
        try {
            keyStore.getKey(alias, password);
            return true;
        } catch (UnrecoverableKeyException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new TlsValidationException(TlsValidationException.Kind.BAD_FORMAT,
                    "Failed to read key for alias " + alias, e);
        }
    }
}
