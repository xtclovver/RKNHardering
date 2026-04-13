package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class Socks5UdpAssociateClientTest {

    @Test
    fun `udp associate relays payload and falls back to proxy host for zero bind address`() {
        FakeSocks5UdpServer(
            bindHost = "0.0.0.0",
            responseSourceHost = "198.51.100.99",
            responseSourcePort = 3478,
            responsePayload = "pong".encodeToByteArray(),
        ).use { server ->
            Socks5UdpAssociateClient.open(
                proxyHost = "127.0.0.1",
                proxyPort = server.port,
                connectTimeoutMs = 1_000,
                readTimeoutMs = 1_000,
            ).use { session ->
                val response = session.exchange(
                    targetHost = "stun.example.org",
                    targetPort = 3478,
                    payload = "ping".encodeToByteArray(),
                )

                assertEquals("127.0.0.1", session.relayHost)
                assertEquals(server.relayPort, session.relayPort)
                assertEquals("stun.example.org", requireNotNull(server.lastTargetHost))
                assertEquals(3478, requireNotNull(server.lastTargetPort))
                assertArrayEquals("ping".encodeToByteArray(), requireNotNull(server.lastPayload))
                assertEquals("198.51.100.99", response.sourceHost)
                assertEquals(3478, response.sourcePort)
                assertArrayEquals("pong".encodeToByteArray(), response.payload)
            }
        }
    }

    @Test
    fun `udp associate surfaces auth required during greeting`() {
        FakeSocks5UdpServer(greetingMethod = 0x02).use { server ->
            expectFailure<Socks5UdpAssociateClient.AuthenticationRequiredException> {
                Socks5UdpAssociateClient.open(
                    proxyHost = "127.0.0.1",
                    proxyPort = server.port,
                    connectTimeoutMs = 1_000,
                    readTimeoutMs = 1_000,
                )
            }
        }
    }

    @Test
    fun `udp associate surfaces proxy reject reply`() {
        FakeSocks5UdpServer(associateReplyCode = 0x07).use { server ->
            val error = expectFailure<Socks5UdpAssociateClient.UdpAssociateRejectedException> {
                Socks5UdpAssociateClient.open(
                    proxyHost = "127.0.0.1",
                    proxyPort = server.port,
                    connectTimeoutMs = 1_000,
                    readTimeoutMs = 1_000,
                )
            }

            assertEquals(0x07, error.replyCode)
        }
    }

    @Test
    fun `udp associate encodes ipv4 destination in relay packet`() {
        FakeSocks5UdpServer(
            responseSourceHost = "203.0.113.10",
            responseSourcePort = 3480,
            responsePayload = byteArrayOf(0x01, 0x02),
        ).use { server ->
            Socks5UdpAssociateClient.open(
                proxyHost = "127.0.0.1",
                proxyPort = server.port,
                connectTimeoutMs = 1_000,
                readTimeoutMs = 1_000,
            ).use { session ->
                val response = session.exchange(
                    targetHost = "203.0.113.77",
                    targetPort = 5000,
                    payload = byteArrayOf(0x11, 0x22, 0x33),
                )

                assertEquals("203.0.113.77", requireNotNull(server.lastTargetHost))
                assertEquals(5000, requireNotNull(server.lastTargetPort))
                assertArrayEquals(byteArrayOf(0x11, 0x22, 0x33), requireNotNull(server.lastPayload))
                assertEquals("203.0.113.10", response.sourceHost)
                assertEquals(3480, response.sourcePort)
            }
        }
    }

    private inline fun <reified T : Throwable> expectFailure(block: () -> Unit): T {
        try {
            block()
            fail("Expected ${T::class.java.simpleName}")
        } catch (error: Throwable) {
            if (error is T) {
                return error
            }
            throw error
        }
        throw AssertionError("Unreachable")
    }

    private class FakeSocks5UdpServer(
        private val greetingMethod: Int = 0x00,
        private val associateReplyCode: Int = 0x00,
        private val bindHost: String = "127.0.0.1",
        private val responseSourceHost: String = "127.0.0.1",
        private val responseSourcePort: Int = 3478,
        private val responsePayload: ByteArray = byteArrayOf(),
    ) : AutoCloseable {
        private val running = AtomicBoolean(true)
        private val tcpServer = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        private val relaySocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        private val tcpWorker = thread(start = true, isDaemon = true, name = "fake-socks5-udp-tcp") {
            try {
                tcpServer.accept().use { socket ->
                    handleHandshake(socket.getInputStream(), socket.getOutputStream())
                    while (running.get() && !socket.isClosed) {
                        if (socket.getInputStream().read() < 0) {
                            return@use
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
        private val udpWorker = thread(start = true, isDaemon = true, name = "fake-socks5-udp-relay") {
            val packet = DatagramPacket(ByteArray(4_096), 4_096)
            while (running.get()) {
                try {
                    relaySocket.receive(packet)
                    val data = packet.data.copyOf(packet.length)
                    val parsed = parseUdpPacket(data)
                    lastTargetHost = parsed.host
                    lastTargetPort = parsed.port
                    lastPayload = parsed.payload

                    val response = buildUdpPacket(
                        host = responseSourceHost,
                        port = responseSourcePort,
                        payload = responsePayload,
                    )
                    relaySocket.send(
                        DatagramPacket(
                            response,
                            response.size,
                            packet.address,
                            packet.port,
                        ),
                    )
                } catch (_: SocketException) {
                    if (!running.get()) return@thread
                } catch (_: Exception) {
                }
            }
        }

        @Volatile
        var lastTargetHost: String? = null

        @Volatile
        var lastTargetPort: Int? = null

        @Volatile
        var lastPayload: ByteArray? = null

        val port: Int
            get() = tcpServer.localPort

        val relayPort: Int
            get() = relaySocket.localPort

        override fun close() {
            running.set(false)
            runCatching { relaySocket.close() }
            runCatching { tcpServer.close() }
            tcpWorker.join(2_000)
            udpWorker.join(2_000)
        }

        private fun handleHandshake(input: InputStream, output: OutputStream) {
            input.readNBytes(3)
            output.write(byteArrayOf(0x05, greetingMethod.toByte()))
            output.flush()
            if (greetingMethod != 0x00) {
                return
            }

            val requestHeader = input.readNBytes(4)
            if (requestHeader.size < 4) {
                return
            }
            parseAddress(input, requestHeader[3].toInt() and 0xFF)
            input.readNBytes(2)

            output.write(
                buildAssociateReply(
                    replyCode = associateReplyCode,
                    host = bindHost,
                    port = relayPort,
                ),
            )
            output.flush()
        }

        private fun buildAssociateReply(
            replyCode: Int,
            host: String,
            port: Int,
        ): ByteArray {
            val address = encodeAddress(host)
            return byteArrayOf(
                0x05,
                replyCode.toByte(),
                0x00,
                address.first.toByte(),
            ) + address.second +
                byteArrayOf(
                    ((port ushr 8) and 0xFF).toByte(),
                    (port and 0xFF).toByte(),
                )
        }

        private fun buildUdpPacket(
            host: String,
            port: Int,
            payload: ByteArray,
        ): ByteArray {
            val address = encodeAddress(host)
            return byteArrayOf(
                0x00,
                0x00,
                0x00,
                address.first.toByte(),
            ) + address.second +
                byteArrayOf(
                    ((port ushr 8) and 0xFF).toByte(),
                    (port and 0xFF).toByte(),
                ) + payload
        }

        private fun parseUdpPacket(data: ByteArray): ParsedUdpPacket {
            val (host, nextOffset) = decodeAddress(data, offset = 3)
            val port = ((data[nextOffset].toInt() and 0xFF) shl 8) or (data[nextOffset + 1].toInt() and 0xFF)
            val payload = data.copyOfRange(nextOffset + 2, data.size)
            return ParsedUdpPacket(host = host, port = port, payload = payload)
        }

        private fun parseAddress(input: InputStream, atyp: Int): String {
            return when (atyp) {
                0x01 -> InetAddress.getByAddress(input.readNBytes(4)).hostAddress
                0x03 -> {
                    val length = input.read()
                    input.readNBytes(length).decodeToString()
                }
                0x04 -> InetAddress.getByAddress(input.readNBytes(16)).hostAddress
                else -> error("Unsupported atyp: $atyp")
            }
        }

        private fun encodeAddress(host: String): Pair<Int, ByteArray> {
            return when {
                host.split('.').size == 4 && host.all { it.isDigit() || it == '.' } -> {
                    0x01 to InetAddress.getByName(host).address
                }
                ':' in host -> {
                    0x04 to InetAddress.getByName(host).address
                }
                else -> {
                    val domain = host.encodeToByteArray()
                    0x03 to (byteArrayOf(domain.size.toByte()) + domain)
                }
            }
        }

        private fun decodeAddress(data: ByteArray, offset: Int): Pair<String, Int> {
            return when (val atyp = data[offset].toInt() and 0xFF) {
                0x01 -> {
                    val end = offset + 5
                    InetAddress.getByAddress(data.copyOfRange(offset + 1, end)).hostAddress to end
                }
                0x03 -> {
                    val length = data[offset + 1].toInt() and 0xFF
                    val start = offset + 2
                    val end = start + length
                    data.decodeToString(start, end) to end
                }
                0x04 -> {
                    val end = offset + 17
                    InetAddress.getByAddress(data.copyOfRange(offset + 1, end)).hostAddress to end
                }
                else -> error("Unsupported atyp: $atyp")
            }
        }

        private data class ParsedUdpPacket(
            val host: String,
            val port: Int,
            val payload: ByteArray,
        )
    }
}
