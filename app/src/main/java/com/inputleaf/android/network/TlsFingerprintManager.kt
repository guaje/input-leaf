package com.inputleaf.android.network

import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.X509TrustManager

object TlsFingerprintManager {

    fun fingerprintOf(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(cert.encoded)
        return hash.joinToString("") { "%02x".format(it) }
    }

    fun buildPinningSSLContext(expectedFingerprint: String): SSLContext =
        SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf(pinningTrustManager(expectedFingerprint)), null)
        }

    internal fun pinningTrustManager(expectedFingerprint: String): X509TrustManager {
        val canonicalExpected = normalizeFingerprint(expectedFingerprint)
        return object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty() || fingerprintOf(chain[0]) != canonicalExpected) {
                    throw SSLException("Certificate fingerprint mismatch")
                }
            }
        }
    }

    internal fun normalizeFingerprint(fingerprint: String): String =
        fingerprint.trim().replace(":", "").lowercase(Locale.ROOT)

    /**
     * Creates an SSLContext for TOFU fingerprint capture.
     * Accepts any server certificate unconditionally — TLS chain validation is intentionally
     * bypassed. Use for exactly one connection to capture the server certificate fingerprint.
     * After the user confirms, build a pinning SSLContext for all subsequent connections.
     */
    fun buildCapturingSSLContext(onCertificate: (X509Certificate) -> Unit): SSLContext =
        SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf(capturingTrustManager(onCertificate)), null)
        }

    internal fun capturingTrustManager(
        onCertificate: (X509Certificate) -> Unit,
    ): X509TrustManager = object : X509TrustManager {
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            if (chain.isEmpty()) {
                throw SSLException("Server did not provide a certificate")
            }
            onCertificate(chain[0])
        }
    }
}
