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
