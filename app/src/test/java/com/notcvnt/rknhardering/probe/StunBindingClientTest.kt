package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.DirectDns
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.network.DnsResolverPreset
import com.notcvnt.rknhardering.network.FakeDnsServer
import com.notcvnt.rknhardering.network.ResolverBinding
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import com.notcvnt.rknhardering.network.ResolverSocketBinder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

class StunBindingClientTest {
    @After
    fun tearDown() {
        ResolverNetworkStack.dnsFactoryOverride = null
        ResolverNetworkStack.resetForTests()
    }

    @Test
    fun `probe returns xor mapped address from local stun server`() {
        FakeStunServer(mappedIp = "198.51.100.7", mappedPort = 54321).use { server ->
            val result = StunBindingClient.probe(
                host = "127.0.0.1",
                port = server.port,
                resolverConfig = DnsResolverConfig.system(),
                timeoutMs = 1_000,
            ).getOrThrow()

            assertEquals(listOf("127.0.0.1"), result.resolvedIps)
            assertEquals("127.0.0.1", result.remoteIp)
            assertEquals(server.port, result.remotePort)
            assertEquals("198.51.100.7", result.mappedIp)
            assertEquals(54321, result.mappedPort)
        }
    }

    @Test
    fun `probe fails on malformed response`() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            val worker = thread(start = true, isDaemon = true) {
                val request = DatagramPacket(ByteArray(512), 512)
                try {
                    server.receive(request)
                    val malformed = byteArrayOf(0x01, 0x01, 0x00, 0x00)
                    server.send(
                        DatagramPacket(
                            malformed,
                            malformed.size,
                            request.address,
                            request.port,
                        ),
                    )
                } catch (_: SocketException) {
                }
            }

            val result = StunBindingClient.probe(
                host = "127.0.0.1",
                port = server.localPort,
                resolverConfig = DnsResolverConfig.system(),
                timeoutMs = 1_000,
            )

            assertTrue(result.isFailure)
            worker.join(2_000)
        }
    }

    @Test
    fun `probe uses os device binding for udp socket`() {
        val boundInterfaces = mutableListOf<String>()
        ResolverSocketBinder.bindDatagramToDeviceOverride = { _, interfaceName ->
            boundInterfaces += interfaceName
        }

        FakeStunServer(mappedIp = "198.51.100.7", mappedPort = 54321).use { server ->
            val result = StunBindingClient.probe(
                host = "127.0.0.1",
                port = server.port,
                resolverConfig = DnsResolverConfig.system(),
                binding = ResolverBinding.OsDeviceBinding("tun0"),
                timeoutMs = 1_000,
            ).getOrThrow()

            assertEquals("198.51.100.7", result.mappedIp)
        }

        assertEquals(listOf("tun0"), boundInterfaces)
    }

    @Test
    fun `probe passes same binding descriptor to dns lookup`() {
        var capturedBinding: ResolverBinding? = null
        val boundInterfaces = mutableListOf<String>()
        ResolverSocketBinder.bindDatagramToDeviceOverride = { _, interfaceName ->
            boundInterfaces += interfaceName
        }

        FakeStunServer(mappedIp = "198.51.100.7", mappedPort = 54321).use { server ->
            FakeDnsServer(
                records = mapOf(
                    "stun-test.local" to FakeDnsServer.Record(ipv4 = "127.0.0.1"),
                ),
            ).use { dnsServer ->
                ResolverNetworkStack.dnsFactoryOverride = { _, binding ->
                    capturedBinding = binding
                    DirectDns(listOf("127.0.0.1"), port = dnsServer.port, timeoutMs = 1_000)
                }

                val result = StunBindingClient.probe(
                    host = "stun-test.local",
                    port = server.port,
                    resolverConfig = DnsResolverConfig(
                        mode = DnsResolverMode.DIRECT,
                        preset = DnsResolverPreset.CUSTOM,
                        customDirectServers = listOf("127.0.0.1"),
                    ),
                    binding = ResolverBinding.OsDeviceBinding("tun0"),
                    timeoutMs = 1_000,
                ).getOrThrow()

                assertEquals("198.51.100.7", result.mappedIp)
            }
        }

        val binding = capturedBinding as ResolverBinding.OsDeviceBinding
        assertEquals("tun0", binding.interfaceName)
        assertEquals(listOf("tun0"), boundInterfaces)
    }

    private class FakeStunServer(
        private val mappedIp: String,
        private val mappedPort: Int,
    ) : AutoCloseable {
        private val running = AtomicBoolean(true)
        private val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        private val worker = thread(start = true, isDaemon = true, name = "fake-stun-server") {
            val request = DatagramPacket(ByteArray(512), 512)
            while (running.get()) {
                try {
                    socket.receive(request)
                    val transactionId = request.data.copyOfRange(8, 20)
                    val response = buildResponse(transactionId)
                    socket.send(DatagramPacket(response, response.size, request.address, request.port))
                } catch (_: SocketException) {
                    if (!running.get()) return@thread
                }
            }
        }

        val port: Int
            get() = socket.localPort

        override fun close() {
            running.set(false)
            socket.close()
            worker.join(2_000)
        }

        private fun buildResponse(transactionId: ByteArray): ByteArray {
            val mappedAddressBytes = InetAddress.getByName(mappedIp).address
            val xorPort = mappedPort xor 0x2112
            val cookieBytes = byteArrayOf(0x21, 0x12, 0xA4.toByte(), 0x42)
            val xorAddress = ByteArray(mappedAddressBytes.size) { index ->
                (mappedAddressBytes[index].toInt() xor cookieBytes[index].toInt()).toByte()
            }

            return ByteArrayOutputStream().use { output ->
                DataOutputStream(output).use { stream ->
                    stream.writeShort(0x0101)
                    stream.writeShort(12)
                    stream.writeInt(0x2112A442)
                    stream.write(transactionId)
                    stream.writeShort(0x0020)
                    stream.writeShort(8)
                    stream.writeByte(0x00)
                    stream.writeByte(0x01)
                    stream.writeShort(xorPort)
                    stream.write(xorAddress)
                }
                output.toByteArray()
            }
        }
    }
}
