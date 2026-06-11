package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.registerSocket
import com.notcvnt.rknhardering.rethrowIfCancellation
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

object ProxyProber {

    internal enum class PortProbeResult {
        CLOSED,
        UNKNOWN_TCP_SERVICE,
        SOCKS5_NO_AUTH,
        SOCKS5_AUTH_REQUIRED,
        HTTP_CONNECT_PROXY,
        HTTP_CONNECT_AUTH_REQUIRED,
    }

    data class ProbeResult(
        val type: ProxyType,
        val authRequired: Boolean,
    )

    // RFC 1929 weak-credential dictionary used against loopback-only SOCKS5
    // proxies. Offensive technique; gated by an opt-in setting and never run
    // against non-loopback hosts.
    val WEAK_CREDENTIALS: List<Pair<String, String>> = listOf(
        "" to "", "admin" to "admin", "user" to "password", "proxy" to "proxy",
        "1" to "1", "test" to "test", "socks" to "socks",
    )

    fun probeSocks5Auth(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        username: String,
        password: String,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): Boolean {
        return Socket().use { socket ->
            val registration = executionContext.cancellationSignal.registerSocket(socket)
            try {
                executionContext.throwIfCancelled()
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
                socket.soTimeout = readTimeoutMs
                socket.tcpNoDelay = true
                val out = socket.getOutputStream()
                val input = socket.getInputStream()
                // Greeting: VER=5, NMETHODS=1, METHOD=0x02 (username/password)
                out.write(byteArrayOf(0x05, 0x01, 0x02)); out.flush()
                val methodResp = input.readExactly(2) ?: return false
                if ((methodResp[0].toInt() and 0xFF) != 0x05) return false
                if ((methodResp[1].toInt() and 0xFF) != 0x02) return false
                val u = username.encodeToByteArray()
                val p = password.encodeToByteArray()
                val authReq = ByteArray(3 + u.size + p.size)
                authReq[0] = 0x01
                authReq[1] = u.size.toByte()
                u.copyInto(authReq, 2)
                authReq[2 + u.size] = p.size.toByte()
                p.copyInto(authReq, 3 + u.size)
                out.write(authReq); out.flush()
                val authResp = input.readExactly(2) ?: return false
                (authResp[1].toInt() and 0xFF) == 0x00
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                false
            } finally {
                registration.dispose()
            }
        }
    }

    fun probeUdpAssociate(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): Boolean {
        return Socket().use { socket ->
            val registration = executionContext.cancellationSignal.registerSocket(socket)
            try {
                executionContext.throwIfCancelled()
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
                socket.soTimeout = readTimeoutMs
                socket.tcpNoDelay = true
                val out = socket.getOutputStream()
                val input = socket.getInputStream()
                // Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth)
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
                val methodResp = input.readExactly(2) ?: return false
                if ((methodResp[0].toInt() and 0xFF) != 0x05) return false
                if ((methodResp[1].toInt() and 0xFF) != 0x00) return false
                // UDP ASSOCIATE request: VER=5, CMD=3, RSV=0, ATYP=1 (ipv4), 0.0.0.0:0
                out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                val reply = input.readExactly(2) ?: return false
                (reply[0].toInt() and 0xFF) == 0x05 && (reply[1].toInt() and 0xFF) == 0x00
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                false
            } finally {
                registration.dispose()
            }
        }
    }

    fun probeProxyType(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): ProbeResult? {
        return when (probePort(host, port, connectTimeoutMs, readTimeoutMs, executionContext)) {
            PortProbeResult.SOCKS5_NO_AUTH -> ProbeResult(ProxyType.SOCKS5, authRequired = false)
            PortProbeResult.SOCKS5_AUTH_REQUIRED -> ProbeResult(ProxyType.SOCKS5, authRequired = true)
            PortProbeResult.HTTP_CONNECT_PROXY -> ProbeResult(ProxyType.HTTP, authRequired = false)
            PortProbeResult.HTTP_CONNECT_AUTH_REQUIRED -> ProbeResult(ProxyType.HTTP, authRequired = true)
            PortProbeResult.CLOSED,
            PortProbeResult.UNKNOWN_TCP_SERVICE,
            -> null
        }
    }

    @Deprecated("Use probeProxyType", ReplaceWith("probeProxyType(host, port, connectTimeoutMs, readTimeoutMs, executionContext)?.type"))
    fun probeNoAuthProxyType(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): ProxyType? = probeProxyType(host, port, connectTimeoutMs, readTimeoutMs, executionContext)?.type

    internal fun probePort(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): PortProbeResult {
        val socksResult = probeSocks5NoAuth(host, port, connectTimeoutMs, readTimeoutMs, executionContext)
        return when (socksResult) {
            PortProbeResult.SOCKS5_NO_AUTH,
            PortProbeResult.SOCKS5_AUTH_REQUIRED,
            PortProbeResult.CLOSED,
            -> socksResult
            PortProbeResult.UNKNOWN_TCP_SERVICE -> probeHttpConnect(host, port, connectTimeoutMs, readTimeoutMs, executionContext)
            PortProbeResult.HTTP_CONNECT_PROXY,
            PortProbeResult.HTTP_CONNECT_AUTH_REQUIRED,
            -> socksResult
        }
    }

    private fun probeSocks5NoAuth(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext,
    ): PortProbeResult {
        return Socket().use { socket ->
            val registration = executionContext.cancellationSignal.registerSocket(socket)
            try {
                executionContext.throwIfCancelled()
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                return PortProbeResult.CLOSED
            } finally {
                if (!socket.isConnected) {
                    registration.dispose()
                }
            }

            socket.soTimeout = readTimeoutMs
            socket.tcpNoDelay = true

            try {
                socket.getOutputStream().writeSocks5NoAuthGreeting()
                val response = socket.getInputStream().readExactly(2)
                    ?: return PortProbeResult.UNKNOWN_TCP_SERVICE
                val version = response[0].toInt() and 0xFF
                val method = response[1].toInt() and 0xFF
                when {
                    version == 0x05 && method == 0x00 -> PortProbeResult.SOCKS5_NO_AUTH
                    // 0xFF = no acceptable methods, 0x02 = username/password — both are valid SOCKS5 responses
                    version == 0x05 -> PortProbeResult.SOCKS5_AUTH_REQUIRED
                    else -> PortProbeResult.UNKNOWN_TCP_SERVICE
                }
            } catch (error: SocketTimeoutException) {
                rethrowIfCancellation(error, executionContext)
                PortProbeResult.UNKNOWN_TCP_SERVICE
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                PortProbeResult.UNKNOWN_TCP_SERVICE
            } finally {
                registration.dispose()
            }
        }
    }

    private fun probeHttpConnect(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext,
    ): PortProbeResult {
        return Socket().use { socket ->
            val registration = executionContext.cancellationSignal.registerSocket(socket)
            try {
                executionContext.throwIfCancelled()
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                return PortProbeResult.CLOSED
            } finally {
                if (!socket.isConnected) {
                    registration.dispose()
                }
            }

            socket.soTimeout = readTimeoutMs
            socket.tcpNoDelay = true

            try {
                socket.getOutputStream().writeHttpConnectProbe()
                val response = socket.getInputStream().readAsciiPrefix()
                    ?: return PortProbeResult.UNKNOWN_TCP_SERVICE
                val code = Regex("^HTTP/1\\.[01]\\s+(\\d{3})").find(response)
                    ?.groupValues
                    ?.getOrNull(1)
                    ?.toIntOrNull()
                    ?: return PortProbeResult.UNKNOWN_TCP_SERVICE

                when (code) {
                    200 -> PortProbeResult.HTTP_CONNECT_PROXY
                    // 407 = Proxy Authentication Required — unambiguous HTTP proxy signal
                    407 -> PortProbeResult.HTTP_CONNECT_AUTH_REQUIRED
                    else -> PortProbeResult.UNKNOWN_TCP_SERVICE
                }
            } catch (error: SocketTimeoutException) {
                rethrowIfCancellation(error, executionContext)
                PortProbeResult.UNKNOWN_TCP_SERVICE
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                PortProbeResult.UNKNOWN_TCP_SERVICE
            } finally {
                registration.dispose()
            }
        }
    }

    private fun OutputStream.writeSocks5NoAuthGreeting() {
        write(byteArrayOf(0x05, 0x01, 0x00))
        flush()
    }

    private fun OutputStream.writeHttpConnectProbe() {
        write(
            (
                "CONNECT ifconfig.me:443 HTTP/1.1\r\n" +
                    "Host: ifconfig.me:443\r\n" +
                    "User-Agent: ProxyBypass/1.0\r\n" +
                    "Proxy-Connection: keep-alive\r\n" +
                    "\r\n"
                ).encodeToByteArray(),
        )
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

    private fun InputStream.readAsciiPrefix(limit: Int = 256): String? {
        val buffer = ByteArray(limit)
        val read = read(buffer)
        if (read <= 0) return null
        return buffer.decodeToString(0, read)
    }
}
