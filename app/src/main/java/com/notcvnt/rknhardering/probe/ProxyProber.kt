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
        HTTP_CONNECT_PROXY,
    }

    fun probeNoAuthProxyType(
        host: String,
        port: Int,
        connectTimeoutMs: Int,
        readTimeoutMs: Int,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): ProxyType? {
        return when (probePort(host, port, connectTimeoutMs, readTimeoutMs, executionContext)) {
            PortProbeResult.SOCKS5_NO_AUTH -> ProxyType.SOCKS5
            PortProbeResult.HTTP_CONNECT_PROXY -> ProxyType.HTTP
            PortProbeResult.CLOSED,
            PortProbeResult.UNKNOWN_TCP_SERVICE,
            -> null
        }
    }

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
            PortProbeResult.CLOSED,
            -> socksResult
            PortProbeResult.UNKNOWN_TCP_SERVICE -> probeHttpConnect(host, port, connectTimeoutMs, readTimeoutMs, executionContext)
            PortProbeResult.HTTP_CONNECT_PROXY -> PortProbeResult.HTTP_CONNECT_PROXY
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
                if (version == 0x05 && method == 0x00) {
                    PortProbeResult.SOCKS5_NO_AUTH
                } else {
                    PortProbeResult.UNKNOWN_TCP_SERVICE
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

                if (code == 200) {
                    PortProbeResult.HTTP_CONNECT_PROXY
                } else {
                    PortProbeResult.UNKNOWN_TCP_SERVICE
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
