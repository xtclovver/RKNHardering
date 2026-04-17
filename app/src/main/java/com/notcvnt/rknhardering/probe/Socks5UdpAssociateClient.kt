package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.registerDatagramSocket
import com.notcvnt.rknhardering.registerSocket
import com.notcvnt.rknhardering.rethrowIfCancellation
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

object Socks5UdpAssociateClient {

    data class UdpDatagram(
        val sourceHost: String,
        val sourcePort: Int,
        val payload: ByteArray,
    )

    open class Socks5UdpAssociateException(message: String) : IOException(message)

    class AuthenticationRequiredException : Socks5UdpAssociateException(
        "SOCKS5 proxy requires authentication; only NO_AUTH is supported",
    )

    class UnsupportedAuthMethodException(method: Int) : Socks5UdpAssociateException(
        "SOCKS5 proxy did not accept NO_AUTH (method=0x${method.toString(16).padStart(2, '0')})",
    )

    class UdpAssociateRejectedException(val replyCode: Int) : Socks5UdpAssociateException(
        "SOCKS5 UDP ASSOCIATE rejected with code 0x${replyCode.toString(16).padStart(2, '0')}",
    )

    class MalformedSocksResponseException(message: String) : Socks5UdpAssociateException(message)

    data class SessionInfo(
        val relayHost: String,
        val relayPort: Int,
    )

    class Session internal constructor(
        private val controlSocket: Socket?,
        private val udpSocket: DatagramSocket,
        private val controlRegistration: ScanCancellationSignal.Registration,
        private val udpRegistration: ScanCancellationSignal.Registration,
        val relayHost: String,
        val relayPort: Int,
    ) : AutoCloseable {

        val info: SessionInfo = SessionInfo(relayHost = relayHost, relayPort = relayPort)

        fun exchange(
            targetHost: String,
            targetPort: Int,
            payload: ByteArray,
            executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
        ): UdpDatagram {
            try {
                executionContext.throwIfCancelled()
                val request = buildUdpPacket(targetHost = targetHost, targetPort = targetPort, payload = payload)
                val packet = DatagramPacket(
                    request,
                    request.size,
                    InetAddress.getByName(relayHost),
                    relayPort,
                )
                udpSocket.send(packet)

                val responseBuffer = ByteArray(65_535)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                udpSocket.receive(responsePacket)
                val response = responsePacket.data.copyOf(responsePacket.length)
                return parseUdpPacket(response)
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                throw error
            }
        }

        override fun close() {
            udpRegistration.dispose()
            controlRegistration.dispose()
            runCatching { udpSocket.close() }
            runCatching { controlSocket?.close() }
        }
    }

    fun openRelay(
        relayHost: String,
        relayPort: Int,
        readTimeoutMs: Int = 3_000,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): Session {
        val udpSocket = DatagramSocket()
        val udpRegistration = executionContext.cancellationSignal.registerDatagramSocket(udpSocket)
        try {
            udpSocket.soTimeout = readTimeoutMs
            return Session(
                controlSocket = null,
                udpSocket = udpSocket,
                controlRegistration = ScanCancellationSignal.Registration.NO_OP,
                udpRegistration = udpRegistration,
                relayHost = relayHost,
                relayPort = relayPort,
            )
        } catch (error: Exception) {
            udpRegistration.dispose()
            runCatching { udpSocket.close() }
            rethrowIfCancellation(error, executionContext)
            throw error
        }
    }

    fun open(
        proxyHost: String,
        proxyPort: Int,
        connectTimeoutMs: Int = 3_000,
        readTimeoutMs: Int = 3_000,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): Session {
        val controlSocket = Socket()
        val udpSocket = DatagramSocket()
        val controlRegistration = executionContext.cancellationSignal.registerSocket(controlSocket)
        val udpRegistration = executionContext.cancellationSignal.registerDatagramSocket(udpSocket)

        try {
            executionContext.throwIfCancelled()
            controlSocket.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeoutMs)
            controlSocket.soTimeout = readTimeoutMs
            controlSocket.tcpNoDelay = true
            udpSocket.soTimeout = readTimeoutMs

            val input = controlSocket.getInputStream()
            val output = controlSocket.getOutputStream()

            output.writeSocks5NoAuthGreeting()
            val greeting = input.readExactly(2)
                ?: throw MalformedSocksResponseException("SOCKS5 greeting response is incomplete")
            if (greeting[0].toInt() and 0xFF != 0x05) {
                throw MalformedSocksResponseException("Unexpected SOCKS5 greeting version")
            }

            when (val method = greeting[1].toInt() and 0xFF) {
                0x00 -> Unit
                0x02 -> throw AuthenticationRequiredException()
                else -> throw UnsupportedAuthMethodException(method)
            }

            output.writeUdpAssociateRequest(clientPort = udpSocket.localPort)
            val associateResponse = readSocks5Reply(input)
            if (associateResponse.replyCode != 0x00) {
                throw UdpAssociateRejectedException(associateResponse.replyCode)
            }

            val relayHost = associateResponse.boundHost.takeUnless(::isUnspecifiedHost) ?: proxyHost
            return Session(
                controlSocket = controlSocket,
                udpSocket = udpSocket,
                controlRegistration = controlRegistration,
                udpRegistration = udpRegistration,
                relayHost = relayHost,
                relayPort = associateResponse.boundPort,
            )
        } catch (error: SocketTimeoutException) {
            controlRegistration.dispose()
            udpRegistration.dispose()
            runCatching { udpSocket.close() }
            runCatching { controlSocket.close() }
            rethrowIfCancellation(error, executionContext)
            throw IOException("Timed out during SOCKS5 UDP ASSOCIATE", error)
        } catch (error: Exception) {
            controlRegistration.dispose()
            udpRegistration.dispose()
            runCatching { udpSocket.close() }
            runCatching { controlSocket.close() }
            rethrowIfCancellation(error, executionContext)
            throw error
        }
    }

    private data class SocksReply(
        val replyCode: Int,
        val boundHost: String,
        val boundPort: Int,
    )

    private fun OutputStream.writeSocks5NoAuthGreeting() {
        write(byteArrayOf(0x05, 0x01, 0x00))
        flush()
    }

    private fun OutputStream.writeUdpAssociateRequest(clientPort: Int) {
        val request = byteArrayOf(
            0x05,
            0x03,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            ((clientPort ushr 8) and 0xFF).toByte(),
            (clientPort and 0xFF).toByte(),
        )
        write(request)
        flush()
    }

    private fun readSocks5Reply(input: InputStream): SocksReply {
        val header = input.readExactly(4)
            ?: throw MalformedSocksResponseException("SOCKS5 reply header is incomplete")
        if (header[0].toInt() and 0xFF != 0x05) {
            throw MalformedSocksResponseException("Unexpected SOCKS5 reply version")
        }

        val replyCode = header[1].toInt() and 0xFF
        val atyp = header[3].toInt() and 0xFF
        val boundHost = readHost(input, atyp)
        val portBytes = input.readExactly(2)
            ?: throw MalformedSocksResponseException("SOCKS5 reply port is incomplete")
        val boundPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

        return SocksReply(replyCode = replyCode, boundHost = boundHost, boundPort = boundPort)
    }

    private fun buildUdpPacket(
        targetHost: String,
        targetPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val addressBytes = encodeAddress(targetHost)
        val packet = ByteArray(3 + 1 + addressBytes.value.size + 2 + payload.size)
        packet[0] = 0x00
        packet[1] = 0x00
        packet[2] = 0x00
        packet[3] = addressBytes.type.toByte()
        addressBytes.value.copyInto(packet, destinationOffset = 4)
        val portOffset = 4 + addressBytes.value.size
        packet[portOffset] = ((targetPort ushr 8) and 0xFF).toByte()
        packet[portOffset + 1] = (targetPort and 0xFF).toByte()
        payload.copyInto(packet, destinationOffset = portOffset + 2)
        return packet
    }

    private fun parseUdpPacket(packet: ByteArray): UdpDatagram {
        if (packet.size < 10) {
            throw MalformedSocksResponseException("SOCKS5 UDP packet is too short")
        }
        if (packet[2].toInt() and 0xFF != 0x00) {
            throw MalformedSocksResponseException("Fragmented SOCKS5 UDP packets are not supported")
        }

        val address = decodeAddress(packet, offset = 3)
        val portOffset = address.nextOffset
        if (portOffset + 2 > packet.size) {
            throw MalformedSocksResponseException("SOCKS5 UDP packet port is incomplete")
        }
        val sourcePort = ((packet[portOffset].toInt() and 0xFF) shl 8) or
            (packet[portOffset + 1].toInt() and 0xFF)
        val payload = packet.copyOfRange(portOffset + 2, packet.size)
        return UdpDatagram(
            sourceHost = address.host,
            sourcePort = sourcePort,
            payload = payload,
        )
    }

    private data class EncodedAddress(
        val type: Int,
        val value: ByteArray,
    )

    private data class DecodedAddress(
        val host: String,
        val nextOffset: Int,
    )

    private fun encodeAddress(host: String): EncodedAddress {
        parseLiteralAddress(host)?.let { address ->
            return when (address) {
                is Inet4Address -> EncodedAddress(type = 0x01, value = address.address)
                is Inet6Address -> EncodedAddress(type = 0x04, value = address.address)
                else -> throw MalformedSocksResponseException("Unsupported literal IP family")
            }
        }

        val domainBytes = host.encodeToByteArray()
        require(domainBytes.size <= 255) { "SOCKS5 domain name is too long" }
        return EncodedAddress(
            type = 0x03,
            value = byteArrayOf(domainBytes.size.toByte()) + domainBytes,
        )
    }

    private fun decodeAddress(data: ByteArray, offset: Int): DecodedAddress {
        if (offset >= data.size) {
            throw MalformedSocksResponseException("SOCKS5 address type is missing")
        }

        return when (val atyp = data[offset].toInt() and 0xFF) {
            0x01 -> {
                if (offset + 1 + 4 > data.size) {
                    throw MalformedSocksResponseException("SOCKS5 IPv4 address is incomplete")
                }
                val address = data.copyOfRange(offset + 1, offset + 5)
                DecodedAddress(
                    host = InetAddress.getByAddress(address).hostAddress ?: throw MalformedSocksResponseException("IPv4 host is unavailable"),
                    nextOffset = offset + 5,
                )
            }
            0x03 -> {
                if (offset + 2 > data.size) {
                    throw MalformedSocksResponseException("SOCKS5 domain length is missing")
                }
                val length = data[offset + 1].toInt() and 0xFF
                val endOffset = offset + 2 + length
                if (endOffset > data.size) {
                    throw MalformedSocksResponseException("SOCKS5 domain address is incomplete")
                }
                DecodedAddress(
                    host = data.decodeToString(offset + 2, endOffset),
                    nextOffset = endOffset,
                )
            }
            0x04 -> {
                if (offset + 1 + 16 > data.size) {
                    throw MalformedSocksResponseException("SOCKS5 IPv6 address is incomplete")
                }
                val address = data.copyOfRange(offset + 1, offset + 17)
                DecodedAddress(
                    host = InetAddress.getByAddress(address).hostAddress ?: throw MalformedSocksResponseException("IPv6 host is unavailable"),
                    nextOffset = offset + 17,
                )
            }
            else -> throw MalformedSocksResponseException(
                "Unsupported SOCKS5 address type 0x${atyp.toString(16).padStart(2, '0')}",
            )
        }
    }

    private fun readHost(input: InputStream, atyp: Int): String {
        return when (atyp) {
            0x01 -> {
                val address = input.readExactly(4)
                    ?: throw MalformedSocksResponseException("SOCKS5 IPv4 address is incomplete")
                InetAddress.getByAddress(address).hostAddress
                    ?: throw MalformedSocksResponseException("SOCKS5 IPv4 host is unavailable")
            }
            0x03 -> {
                val length = input.read()
                if (length < 0) {
                    throw MalformedSocksResponseException("SOCKS5 domain length is missing")
                }
                val address = input.readExactly(length)
                    ?: throw MalformedSocksResponseException("SOCKS5 domain address is incomplete")
                address.decodeToString()
            }
            0x04 -> {
                val address = input.readExactly(16)
                    ?: throw MalformedSocksResponseException("SOCKS5 IPv6 address is incomplete")
                InetAddress.getByAddress(address).hostAddress
                    ?: throw MalformedSocksResponseException("SOCKS5 IPv6 host is unavailable")
            }
            else -> throw MalformedSocksResponseException(
                "Unsupported SOCKS5 address type 0x${atyp.toString(16).padStart(2, '0')}",
            )
        }
    }

    private fun parseLiteralAddress(host: String): InetAddress? {
        return when {
            isIpv4Literal(host) -> InetAddress.getByName(host)
            ':' in host -> InetAddress.getByName(host.removePrefix("[").removeSuffix("]"))
            else -> null
        }
    }

    private fun isIpv4Literal(host: String): Boolean {
        val segments = host.split('.')
        if (segments.size != 4) return false
        return segments.all { segment ->
            segment.isNotEmpty() &&
                segment.all { it.isDigit() } &&
                segment.toIntOrNull() in 0..255
        }
    }

    private fun isUnspecifiedHost(host: String): Boolean {
        return host == "0.0.0.0" || host == "::" || host == "0:0:0:0:0:0:0:0"
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
