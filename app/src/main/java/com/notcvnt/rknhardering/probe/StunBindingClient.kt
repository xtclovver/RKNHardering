package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import com.notcvnt.rknhardering.network.ResolverSocketBinder
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.random.Random

object StunBindingClient {

    data class BindingResult(
        val resolvedIps: List<String>,
        val remoteIp: String,
        val remotePort: Int,
        val mappedIp: String,
        val mappedPort: Int,
    )

    private const val MAGIC_COOKIE = 0x2112A442
    private const val BINDING_REQUEST = 0x0001
    private const val BINDING_SUCCESS_RESPONSE = 0x0101
    private const val ATTR_MAPPED_ADDRESS = 0x0001
    private const val ATTR_XOR_MAPPED_ADDRESS = 0x0020

    fun probe(
        host: String,
        port: Int,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        binding: ResolverBinding? = null,
        timeoutMs: Int = 3_000,
    ): Result<BindingResult> {
        return runCatching {
            val resolvedAddresses = ResolverNetworkStack.lookup(host, resolverConfig, binding)
                .distinctBy { it.hostAddress }
            if (resolvedAddresses.isEmpty()) {
                throw IOException("No addresses resolved for $host")
            }

            var lastError: Exception? = null
            for (address in resolvedAddresses) {
                try {
                    return@runCatching sendBindingRequest(
                        host = host,
                        port = port,
                        address = address,
                        resolvedAddresses = resolvedAddresses,
                        binding = binding,
                        timeoutMs = timeoutMs,
                    )
                } catch (error: Exception) {
                    lastError = error
                }
            }
            throw lastError ?: IOException("No STUN response from $host:$port")
        }
    }

    private fun sendBindingRequest(
        host: String,
        port: Int,
        address: InetAddress,
        resolvedAddresses: List<InetAddress>,
        binding: ResolverBinding?,
        timeoutMs: Int,
    ): BindingResult {
        val transactionId = Random.nextBytes(12)
        val request = buildBindingRequest(transactionId)

        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            ResolverSocketBinder.bind(socket, binding)
            val packet = DatagramPacket(request, request.size, address, port)
            socket.send(packet)

            val responseBuffer = ByteArray(1500)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)

            val response = responsePacket.data.copyOf(responsePacket.length)
            val mappedAddress = parseMappedAddress(response, transactionId)
                ?: throw IOException("STUN response did not include a mapped address")

            return BindingResult(
                resolvedIps = resolvedAddresses.mapNotNull { it.hostAddress }.distinct(),
                remoteIp = responsePacket.address.hostAddress ?: host,
                remotePort = responsePacket.port,
                mappedIp = mappedAddress.address.hostAddress ?: throw IOException("Mapped IP is unavailable"),
                mappedPort = mappedAddress.port,
            )
        }
    }

    private fun buildBindingRequest(transactionId: ByteArray): ByteArray {
        val request = ByteArray(20)
        writeUnsignedShort(request, 0, BINDING_REQUEST)
        writeUnsignedShort(request, 2, 0)
        writeInt(request, 4, MAGIC_COOKIE)
        transactionId.copyInto(request, destinationOffset = 8)
        return request
    }

    private fun parseMappedAddress(
        response: ByteArray,
        expectedTransactionId: ByteArray,
    ): java.net.InetSocketAddress? {
        if (response.size < 20) throw IOException("STUN response is too short")

        val messageType = readUnsignedShort(response, 0)
        if (messageType != BINDING_SUCCESS_RESPONSE) {
            throw IOException("Unexpected STUN response type: 0x${messageType.toString(16)}")
        }

        val messageLength = readUnsignedShort(response, 2)
        if (messageLength + 20 > response.size) {
            throw IOException("Malformed STUN response length")
        }

        val cookie = readInt(response, 4)
        if (cookie != MAGIC_COOKIE) {
            throw IOException("Unexpected STUN magic cookie")
        }

        val transactionId = response.copyOfRange(8, 20)
        if (!transactionId.contentEquals(expectedTransactionId)) {
            throw IOException("STUN transaction id mismatch")
        }

        var offset = 20
        val limit = 20 + messageLength
        while (offset + 4 <= limit) {
            val attributeType = readUnsignedShort(response, offset)
            val attributeLength = readUnsignedShort(response, offset + 2)
            val valueOffset = offset + 4
            val paddedLength = ((attributeLength + 3) / 4) * 4
            if (valueOffset + attributeLength > response.size) {
                throw IOException("Malformed STUN attribute")
            }

            when (attributeType) {
                ATTR_XOR_MAPPED_ADDRESS -> {
                    parseAddressAttribute(
                        response = response,
                        valueOffset = valueOffset,
                        attributeLength = attributeLength,
                        xor = true,
                        transactionId = expectedTransactionId,
                    )?.let { return it }
                }
                ATTR_MAPPED_ADDRESS -> {
                    parseAddressAttribute(
                        response = response,
                        valueOffset = valueOffset,
                        attributeLength = attributeLength,
                        xor = false,
                        transactionId = expectedTransactionId,
                    )?.let { return it }
                }
            }

            offset = valueOffset + paddedLength
        }
        return null
    }

    private fun parseAddressAttribute(
        response: ByteArray,
        valueOffset: Int,
        attributeLength: Int,
        xor: Boolean,
        transactionId: ByteArray,
    ): java.net.InetSocketAddress? {
        if (attributeLength < 8) return null
        val family = response[valueOffset + 1].toInt() and 0xFF
        val encodedPort = readUnsignedShort(response, valueOffset + 2)
        val port = if (xor) encodedPort xor (MAGIC_COOKIE ushr 16) else encodedPort

        return when (family) {
            0x01 -> {
                val rawAddress = response.copyOfRange(valueOffset + 4, valueOffset + 8)
                val decoded = if (xor) {
                    rawAddress.mapIndexed { index, byte ->
                        (byte.toInt() xor magicCookieBytes()[index].toInt()).toByte()
                    }.toByteArray()
                } else {
                    rawAddress
                }
                java.net.InetSocketAddress(InetAddress.getByAddress(decoded), port)
            }
            0x02 -> {
                if (attributeLength < 20) return null
                val rawAddress = response.copyOfRange(valueOffset + 4, valueOffset + 20)
                val mask = magicCookieBytes() + transactionId
                val decoded = rawAddress.mapIndexed { index, byte ->
                    (byte.toInt() xor mask[index].toInt()).toByte()
                }.toByteArray()
                java.net.InetSocketAddress(InetAddress.getByAddress(decoded), port)
            }
            else -> null
        }
    }

    private fun magicCookieBytes(): ByteArray = byteArrayOf(
        ((MAGIC_COOKIE ushr 24) and 0xFF).toByte(),
        ((MAGIC_COOKIE ushr 16) and 0xFF).toByte(),
        ((MAGIC_COOKIE ushr 8) and 0xFF).toByte(),
        (MAGIC_COOKIE and 0xFF).toByte(),
    )

    private fun writeUnsignedShort(target: ByteArray, offset: Int, value: Int) {
        target[offset] = ((value ushr 8) and 0xFF).toByte()
        target[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeInt(target: ByteArray, offset: Int, value: Int) {
        target[offset] = ((value ushr 24) and 0xFF).toByte()
        target[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        target[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        target[offset + 3] = (value and 0xFF).toByte()
    }

    private fun readUnsignedShort(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    private fun readInt(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
            ((data[offset + 1].toInt() and 0xFF) shl 16) or
            ((data[offset + 2].toInt() and 0xFF) shl 8) or
            (data[offset + 3].toInt() and 0xFF)
    }
}
