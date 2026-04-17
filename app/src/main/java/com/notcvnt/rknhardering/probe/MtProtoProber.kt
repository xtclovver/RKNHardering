package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.registerSocket
import com.notcvnt.rknhardering.rethrowIfCancellation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Probes whether a SOCKS5 proxy on localhost forwards traffic to Telegram
 * data-center IPs (MTProto proxy detection).
 *
 * The probe connects through the SOCKS5 proxy to a known Telegram DC address
 * and checks whether a TCP connection is established. It does NOT send any
 * MTProto payload — a successful TCP connect is sufficient evidence that the
 * proxy selectively routes Telegram traffic.
 */
object MtProtoProber {

    /** Telegram DC2 (Production, nearest to most users). */
    private val TELEGRAM_DC_TARGETS = listOf(
        InetSocketAddress("149.154.167.51", 443),
        InetSocketAddress("149.154.167.41", 443),
    )

    data class ProbeResult(
        val reachable: Boolean,
        val targetAddress: InetSocketAddress?,
    )

    /**
     * Attempts to connect to a Telegram DC through the given SOCKS5 proxy.
     * Returns [ProbeResult.reachable] = true if the proxy successfully relayed
     * a TCP connection to a Telegram DC.
     */
    suspend fun probe(
        proxyHost: String,
        proxyPort: Int,
        connectTimeoutMs: Int = 3000,
        readTimeoutMs: Int = 3000,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): ProbeResult = withContext(Dispatchers.IO) {
        for (target in TELEGRAM_DC_TARGETS) {
            val reachable = trySocks5Connect(
                proxyHost = proxyHost,
                proxyPort = proxyPort,
                targetHost = target.address.hostAddress!!,
                targetPort = target.port,
                connectTimeoutMs = connectTimeoutMs,
                readTimeoutMs = readTimeoutMs,
                executionContext = executionContext,
            )
            if (reachable) {
                return@withContext ProbeResult(reachable = true, targetAddress = target)
            }
        }
        ProbeResult(reachable = false, targetAddress = null)
    }

    /**
     * Performs a SOCKS5 CONNECT handshake to the target through the proxy.
     * Returns true if the proxy replies with a successful (0x00) status,
     * meaning TCP to the target was established.
     */
    internal fun trySocks5Connect(
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): Boolean {
        return Socket().use { socket ->
            val registration = executionContext.cancellationSignal.registerSocket(socket)
            try {
                executionContext.throwIfCancelled()
                socket.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeoutMs)
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                return false
            }

            socket.soTimeout = readTimeoutMs
            socket.tcpNoDelay = true

            try {
                val out = socket.getOutputStream()
                val inp = socket.getInputStream()

                // SOCKS5 greeting: version 0x05, 1 method, NO AUTH (0x00)
                out.writeSocks5Greeting()

                // Expect: version 0x05, chosen method 0x00
                val greeting = inp.readExactly(2) ?: return false
                if (greeting[0].toInt() and 0xFF != 0x05) return false
                if (greeting[1].toInt() and 0xFF != 0x00) return false

                // SOCKS5 CONNECT request to target
                out.writeSocks5ConnectIPv4(targetHost, targetPort)

                // Expect: version(1) reply(1) rsv(1) atyp(1) + bind addr + bind port
                // Minimum response for IPv4: 4 + 4 + 2 = 10 bytes
                val response = inp.readExactly(4) ?: return false
                val replyCode = response[1].toInt() and 0xFF

                // replyCode 0x00 = succeeded
                replyCode == 0x00
            } catch (error: SocketTimeoutException) {
                rethrowIfCancellation(error, executionContext)
                false
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                false
            } finally {
                registration.dispose()
            }
        }
    }

    private fun OutputStream.writeSocks5Greeting() {
        write(byteArrayOf(0x05, 0x01, 0x00))
        flush()
    }

    private fun OutputStream.writeSocks5ConnectIPv4(host: String, port: Int) {
        val ipParts = host.split('.')
        val request = byteArrayOf(
            0x05,                                     // version
            0x01,                                     // CMD: CONNECT
            0x00,                                     // reserved
            0x01,                                     // ATYP: IPv4
            ipParts[0].toInt().toByte(),
            ipParts[1].toInt().toByte(),
            ipParts[2].toInt().toByte(),
            ipParts[3].toInt().toByte(),
            (port shr 8).toByte(),                    // port high byte
            (port and 0xFF).toByte(),                 // port low byte
        )
        write(request)
        flush()
    }

    private fun InputStream.readExactly(byteCount: Int): ByteArray? {
        val buffer = ByteArray(byteCount)
        var offset = 0
        while (offset < byteCount) {
            val read = read(buffer, offset, byteCount - offset)
            if (read <= 0) return null
            offset += read
        }
        return buffer
    }
}
