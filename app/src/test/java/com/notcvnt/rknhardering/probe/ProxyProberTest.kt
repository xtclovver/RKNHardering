package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

class ProxyProberTest {

    @Test
    fun `detects socks5 no auth proxy`() {
        val result = withScriptedServer(
            listOf(
                { socket ->
                    socket.getInputStream().readNBytes(3)
                    socket.getOutputStream().write(byteArrayOf(0x05, 0x00))
                    socket.getOutputStream().flush()
                },
            ),
        )

        assertEquals(ProxyProber.PortProbeResult.SOCKS5_NO_AUTH, result)
    }

    @Test
    fun `detects http connect proxy`() {
        val result = withScriptedServer(
            listOf(
                { socket ->
                    socket.getInputStream().readNBytes(3)
                    socket.getOutputStream().write("NO".encodeToByteArray())
                    socket.getOutputStream().flush()
                },
                { socket ->
                    socket.getInputStream().read(ByteArray(128))
                    socket.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".encodeToByteArray())
                    socket.getOutputStream().flush()
                },
            ),
        )

        assertEquals(ProxyProber.PortProbeResult.HTTP_CONNECT_PROXY, result)
    }

    @Test
    fun `detects socks5 proxy with auth required (0x05 0xFF no acceptable methods)`() {
        val result = withScriptedServer(
            listOf(
                { socket ->
                    socket.getInputStream().readNBytes(3)
                    socket.getOutputStream().write(byteArrayOf(0x05, 0xFF.toByte()))
                    socket.getOutputStream().flush()
                },
            ),
        )

        assertEquals(ProxyProber.PortProbeResult.SOCKS5_AUTH_REQUIRED, result)
    }

    @Test
    fun `detects socks5 proxy with auth required (0x05 0x02 username-password method)`() {
        val result = withScriptedServer(
            listOf(
                { socket ->
                    socket.getInputStream().readNBytes(3)
                    socket.getOutputStream().write(byteArrayOf(0x05, 0x02))
                    socket.getOutputStream().flush()
                },
            ),
        )

        assertEquals(ProxyProber.PortProbeResult.SOCKS5_AUTH_REQUIRED, result)
    }

    @Test
    fun `detects http connect proxy with 407 auth required`() {
        val result = withScriptedServer(
            listOf(
                { socket ->
                    socket.getInputStream().readNBytes(3)
                    socket.getOutputStream().write("NO".encodeToByteArray())
                    socket.getOutputStream().flush()
                },
                { socket ->
                    socket.getInputStream().read(ByteArray(128))
                    socket.getOutputStream().write(
                        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
                            .encodeToByteArray(),
                    )
                    socket.getOutputStream().flush()
                },
            ),
        )

        assertEquals(ProxyProber.PortProbeResult.HTTP_CONNECT_AUTH_REQUIRED, result)
    }

    @Test
    fun `probeProxyType returns auth required for socks5 with password`() {
        val server = java.net.ServerSocket(0)
        val worker = thread(start = true) {
            server.accept().use { socket ->
                socket.getInputStream().readNBytes(3)
                socket.getOutputStream().write(byteArrayOf(0x05, 0xFF.toByte()))
                socket.getOutputStream().flush()
            }
        }
        val result = ProxyProber.probeProxyType(
            host = "127.0.0.1",
            port = server.localPort,
            connectTimeoutMs = 500,
            readTimeoutMs = 500,
        )
        worker.join(1000)
        server.close()

        assertEquals(ProxyType.SOCKS5, result?.type)
        assertEquals(true, result?.authRequired)
    }

    @Test
    fun `keeps unknown tcp listener out of proxy results`() {
        val result = withScriptedServer(
            listOf(
                { socket ->
                    socket.getInputStream().readNBytes(3)
                    socket.getOutputStream().write("NO".encodeToByteArray())
                    socket.getOutputStream().flush()
                },
                { socket ->
                    socket.getInputStream().read(ByteArray(128))
                    socket.getOutputStream().write("HELLO".encodeToByteArray())
                    socket.getOutputStream().flush()
                },
            ),
        )

        assertEquals(ProxyProber.PortProbeResult.UNKNOWN_TCP_SERVICE, result)
    }

    @Test
    fun `cancelled tcp probe closes socket immediately`() {
        ServerSocket(0).use { server ->
            val accepted = CountDownLatch(1)
            val releaseServer = CountDownLatch(1)
            val failure = AtomicReference<Throwable?>()

            val serverWorker = thread(start = true) {
                server.accept().use {
                    accepted.countDown()
                    releaseServer.await(2, TimeUnit.SECONDS)
                }
            }

            val executionContext = ScanExecutionContext(cancellationSignal = ScanCancellationSignal())
            val probeWorker = thread(start = true) {
                failure.set(
                    runCatching {
                        ProxyProber.probePort(
                            host = "127.0.0.1",
                            port = server.localPort,
                            connectTimeoutMs = 500,
                            readTimeoutMs = 5_000,
                            executionContext = executionContext,
                        )
                    }.exceptionOrNull(),
                )
            }

            assertTrue(accepted.await(1, TimeUnit.SECONDS))
            executionContext.cancellationSignal.cancel()
            probeWorker.join(2_000)
            releaseServer.countDown()
            serverWorker.join(2_000)

            assertFalse(probeWorker.isAlive)
            assertTrue(failure.get() is CancellationException)
        }
    }

    @Test
    fun `socks5 auth probe succeeds on weak credentials`() {
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val port = server.localPort
        val acceptor = Thread {
            server.accept().use { sock ->
                val input = sock.getInputStream()
                val out = sock.getOutputStream()
                val greeting = ByteArray(3); input.read(greeting)
                out.write(byteArrayOf(0x05, 0x02)); out.flush()
                input.read(); val ulen = input.read()
                input.readNBytes(ulen); val plen = input.read(); input.readNBytes(plen)
                out.write(byteArrayOf(0x01, 0x00)); out.flush()
            }
        }
        acceptor.start()
        val cracked = ProxyProber.probeSocks5Auth("127.0.0.1", port, 500, 500, "admin", "admin")
        acceptor.join(2000)
        server.close()
        assertTrue(cracked)
    }

    @Test
    fun `socks5 auth probe fails on rejected credentials`() {
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val port = server.localPort
        val acceptor = Thread {
            server.accept().use { sock ->
                val input = sock.getInputStream(); val out = sock.getOutputStream()
                input.read(ByteArray(3))
                out.write(byteArrayOf(0x05, 0x02)); out.flush()
                input.read(); val ulen = input.read(); input.readNBytes(ulen)
                val plen = input.read(); input.readNBytes(plen)
                out.write(byteArrayOf(0x01, 0x01)); out.flush()
            }
        }
        acceptor.start()
        val cracked = ProxyProber.probeSocks5Auth("127.0.0.1", port, 500, 500, "admin", "admin")
        acceptor.join(2000)
        server.close()
        assertFalse(cracked)
    }

    @Test
    fun `udp associate probe succeeds when proxy grants it`() {
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val port = server.localPort
        val acceptor = Thread {
            server.accept().use { sock ->
                val input = sock.getInputStream(); val out = sock.getOutputStream()
                input.read(ByteArray(3))
                out.write(byteArrayOf(0x05, 0x00)); out.flush()
                input.readNBytes(10)
                // Reply: ver, rep=success, rsv, atyp=ipv4, bnd.addr (4), bnd.port (2)
                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38)); out.flush()
            }
        }
        acceptor.start()
        val open = ProxyProber.probeUdpAssociate("127.0.0.1", port, 500, 500)
        acceptor.join(2000)
        server.close()
        assertTrue(open)
    }

    @Test
    fun `udp associate probe fails when proxy refuses it`() {
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val port = server.localPort
        val acceptor = Thread {
            server.accept().use { sock ->
                val input = sock.getInputStream(); val out = sock.getOutputStream()
                input.read(ByteArray(3))
                out.write(byteArrayOf(0x05, 0x00)); out.flush()
                input.readNBytes(10)
                // Reply: rep=0x07 command not supported
                out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
            }
        }
        acceptor.start()
        val open = ProxyProber.probeUdpAssociate("127.0.0.1", port, 500, 500)
        acceptor.join(2000)
        server.close()
        assertFalse(open)
    }

    private fun withScriptedServer(
        handlers: List<(Socket) -> Unit>,
    ): ProxyProber.PortProbeResult {
        ServerSocket(0).use { server ->
            val worker = thread(start = true) {
                for (handler in handlers) {
                    server.accept().use(handler)
                }
            }

            val result = ProxyProber.probePort(
                host = "127.0.0.1",
                port = server.localPort,
                connectTimeoutMs = 500,
                readTimeoutMs = 500,
            )
            worker.join(1000)
            return result
        }
    }
}
