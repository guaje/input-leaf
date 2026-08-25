package com.inputleaf.android.network

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.net.ServerSocket

class TransportProberTest {
    @Test fun `plain-only endpoint returns plain transport after TLS fails`() = runBlocking {
        LoopbackServer(connectionCount = 2) { socket, _ ->
            socket.soTimeout = 1_000
            socket.inputStream.read()
        }.use { server ->
            assertThat(TransportProber.probe(LOOPBACK_HOST, server.port))
                .isEqualTo(ServerTransport.PLAIN)
        }
    }

    @Test fun `TLS is preferred when plain and TLS probes both connect`() = runBlocking {
        val identity = TestTlsIdentity.create()
        TlsLoopbackServer(identity.context, connectionCount = 2) { socket, _ ->
            try {
                socket.startHandshake()
            } catch (_: Exception) {
                // The concurrent plain probe connects and closes without a TLS handshake.
            }
        }.use { server ->
            assertThat(TransportProber.probe(LOOPBACK_HOST, server.port))
                .isEqualTo(ServerTransport.TLS)
        }
    }

    @Test fun `neither transport returns no result`() = runBlocking {
        val unusedPort = ServerSocket(0).use { it.localPort }

        assertThat(TransportProber.probe(LOOPBACK_HOST, unusedPort)).isNull()
    }

    @Test fun `plain result remains available when TLS reaches its bounded timeout`() = runBlocking {
        LoopbackServer(connectionCount = 2) { socket, _ ->
            socket.soTimeout = 1_000
            while (socket.inputStream.read() != -1) {
                // Keep a TLS attempt open without replying; a plain probe closes immediately.
            }
        }.use { server ->
            assertThat(TransportProber.probe(LOOPBACK_HOST, server.port))
                .isEqualTo(ServerTransport.PLAIN)
        }
    }
}
