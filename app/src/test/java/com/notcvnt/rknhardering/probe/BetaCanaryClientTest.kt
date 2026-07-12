package com.notcvnt.rknhardering.probe

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.AppUiSettings
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.SettingsPrefs
import kotlinx.coroutines.CancellationException
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BetaCanaryClientTest {
    private val closeables = CopyOnWriteArrayList<AutoCloseable>()
    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        closeables.forEach { runCatching { it.close() } }
        AppUiSettings.prefs(context).edit().clear().commit()
    }

    @Test
    fun absentConfigAndNetworkOptOutNeverStartCanary() {
        assertEquals(BetaCanaryStatus.UNAVAILABLE, BetaCanaryClient.run(context, null).status)

        AppUiSettings.prefs(context).edit()
            .putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, false)
            .commit()
        val result = BetaCanaryClient.run(context, endpointConfig(9, 9, 9, 9))

        assertEquals(BetaCanaryStatus.DISABLED, result.status)
        assertTrue(result.observations.isEmpty())
        assertNull(result.runTokenHash)
    }

    @Test
    fun explicitScanNetworkGateOverridesEnabledGlobalPreference() {
        AppUiSettings.prefs(context).edit()
            .putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true)
            .commit()

        val result = BetaCanaryClient.run(
            context,
            endpointConfig(9, 9, 9, 9),
            networkRequestsEnabled = false,
        )

        assertEquals(BetaCanaryStatus.DISABLED, result.status)
        assertTrue(result.observations.isEmpty())
    }

    @Test
    fun invalidConfiguredEndpointFailsInsteadOfPretendingUnavailable() {
        val result = BetaCanaryClient.run(context, endpointConfig(0, 9, 9, 9))

        assertEquals(BetaCanaryStatus.FAILED, result.status)
        assertEquals("ENDPOINT_CONFIG_INVALID", result.reason)
    }

    @Test
    fun realLoopbackServerRoundTripsHttpTcpUdpAndAuthoritativeDns() {
        AppUiSettings.prefs(context).edit()
            .putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true)
            .commit()
        val http = startHttpServer()
        val tcp = startTcpServer()
        val udp = startUdpServer()
        val dns = startDnsServer()

        val result = BetaCanaryClient.run(
            context,
            endpointConfig(http.localPort, tcp.localPort, udp.localPort, dns.localPort),
        )

        assertEquals(BetaCanaryStatus.AVAILABLE, result.status)
        assertEquals(4, result.observations.count { it.status == BetaCanaryStatus.AVAILABLE })
        assertEquals(1, result.observations.count { it.transport == BetaCanaryTransport.QUIC && it.status == BetaCanaryStatus.UNSUPPORTED })
        assertTrue(result.observations.filter { it.status == BetaCanaryStatus.AVAILABLE }.all { it.observedAddressHash?.length == 24 })
        assertTrue(result.observations.none { it.failureKind?.contains("127.0.0.1") == true })
    }

    @Test
    fun runTokensAndPrivacyHashesArePerRun() {
        val first = BetaCanaryClient.newRunToken()
        val second = BetaCanaryClient.newRunToken()

        assertEquals(32, first.length)
        assertNotEquals(first, second)
        assertNotEquals(BetaCanaryClient.privacyHash(first, "192.0.2.1"), BetaCanaryClient.privacyHash(second, "192.0.2.1"))
    }

    @Test(expected = CancellationException::class)
    fun cancelledRunStopsBeforeOpeningSockets() {
        val executionContext = ScanExecutionContext()
        executionContext.cancellationSignal.cancel()
        BetaCanaryClient.run(context, endpointConfig(9, 9, 9, 9), executionContext)
    }

    private fun endpointConfig(http: Int, tcp: Int, udp: Int, dns: Int) = BetaCanaryEndpointConfig(
        ipv4Address = "127.0.0.1",
        httpPort = http,
        tcpPort = tcp,
        udpPort = udp,
        dnsPort = dns,
        dnsZone = "canary.invalid",
        timeoutMs = 2_000,
    )

    private fun startHttpServer(): ServerSocket = serverSocket { socket ->
        val input = socket.getInputStream().bufferedReader()
        val requestLine = input.readLine()
        while (!input.readLine().isNullOrEmpty()) Unit
        val target = requestLine.split(' ')[1]
        val query = target.substringAfter('?').split('&').associate {
            it.substringBefore('=') to it.substringAfter('=')
        }
        val body = observation(query.getValue("token"), "http").toString().toByteArray()
        socket.getOutputStream().write(
            "HTTP/1.1 200 OK\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray() + body,
        )
    }

    private fun startTcpServer(): ServerSocket = serverSocket { socket ->
        val request = JSONObject(socket.getInputStream().bufferedReader().readLine())
        socket.getOutputStream().write((observation(request.getString("token"), "tcp").toString() + "\n").toByteArray())
    }

    private fun serverSocket(handler: (java.net.Socket) -> Unit): ServerSocket {
        val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        closeables += AutoCloseable { server.close() }
        thread(isDaemon = true) {
            runCatching { server.accept().use(handler) }
        }
        return server
    }

    private fun startUdpServer(): DatagramSocket = datagramServer { socket, request, peer ->
        val json = JSONObject(String(request.data, request.offset, request.length))
        val response = observation(json.getString("token"), "udp").toString().toByteArray()
        socket.send(DatagramPacket(response, response.size, peer.address, peer.port))
    }

    private fun startDnsServer(): DatagramSocket = datagramServer { socket, request, peer ->
        val query = request.data.copyOfRange(request.offset, request.offset + request.length)
        val token = readDnsName(query, 12).split('.')[1]
        val questionEnd = skipDnsName(query, 12) + 4
        val text = "v=1;t=$token;src=127.0.0.1;fam=ipv4;srv=test;ts=1".toByteArray()
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { data ->
            data.write(query, 0, 2)
            data.writeShort(0x8180)
            data.writeShort(1)
            data.writeShort(1)
            data.writeShort(0)
            data.writeShort(0)
            data.write(query, 12, questionEnd - 12)
            data.writeShort(0xC00C)
            data.writeShort(16)
            data.writeShort(1)
            data.writeInt(0)
            data.writeShort(text.size + 1)
            data.writeByte(text.size)
            data.write(text)
        }
        val response = output.toByteArray()
        socket.send(DatagramPacket(response, response.size, peer.address, peer.port))
    }

    private fun datagramServer(
        handler: (DatagramSocket, DatagramPacket, DatagramPacket) -> Unit,
    ): DatagramSocket {
        val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        closeables += AutoCloseable { socket.close() }
        thread(isDaemon = true) {
            runCatching {
                val buffer = ByteArray(4096)
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                handler(socket, packet, packet)
            }
        }
        return socket
    }

    private fun observation(token: String, protocol: String) = JSONObject()
        .put("schema", 1)
        .put("token", token)
        .put("protocol", protocol)
        .put("family", "ipv4")
        .put("observed_address", "127.0.0.1")
        .put("local_destination", "127.0.0.1")
        .put("server_instance", "test")
        .put("timestamp", 1)

    private fun readDnsName(data: ByteArray, start: Int): String {
        val labels = mutableListOf<String>()
        var offset = start
        while (data[offset].toInt() != 0) {
            val length = data[offset].toInt() and 0xFF
            offset++
            labels += String(data, offset, length)
            offset += length
        }
        return labels.joinToString(".")
    }

    private fun skipDnsName(data: ByteArray, start: Int): Int {
        var offset = start
        while (data[offset].toInt() != 0) offset += 1 + (data[offset].toInt() and 0xFF)
        return offset + 1
    }
}
