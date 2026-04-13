package com.notcvnt.rknhardering.network

import android.net.Network
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.dnsoverhttps.DnsOverHttps
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Dns
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Proxy
import java.net.Socket
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import kotlin.random.Random

data class ResolverHttpResponse(
    val code: Int,
    val body: String,
)

object ResolverNetworkStack {
    private val lock = Any()
    @Volatile
    internal var dnsFactoryOverride: ((DnsResolverConfig, ResolverBinding?) -> Dns)? = null
    @Volatile
    private var cachedConfig: DnsResolverConfig? = null
    @Volatile
    private var cachedDns: Dns? = null
    @Volatile
    private var cachedClient: OkHttpClient? = null

    fun lookup(
        hostname: String,
        config: DnsResolverConfig,
        binding: ResolverBinding? = null,
    ): List<InetAddress> {
        return dns(config, binding).lookup(hostname)
    }

    internal fun resetForTests() {
        synchronized(lock) {
            cachedConfig = null
            cachedDns = null
            cachedClient = null
        }
        ResolverSocketBinder.resetForTests()
    }

    fun execute(
        url: String,
        method: String,
        headers: Map<String, String> = emptyMap(),
        body: String? = null,
        bodyContentType: String? = null,
        timeoutMs: Int,
        config: DnsResolverConfig,
        proxy: Proxy? = null,
        binding: ResolverBinding? = null,
    ): ResolverHttpResponse {
        val requestBuilder = Request.Builder().url(url)
        headers.forEach { (name, value) -> requestBuilder.header(name, value) }
        val requestBody = body?.toRequestBody(bodyContentType?.toMediaTypeOrNull())
        when (method.uppercase()) {
            "GET" -> requestBuilder.get()
            "POST" -> requestBuilder.post(requestBody ?: ByteArray(0).toRequestBody(bodyContentType?.toMediaTypeOrNull()))
            else -> requestBuilder.method(method.uppercase(), requestBody)
        }
        val client = baseClient(config, binding)
            .newBuilder()
            .connectTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .callTimeout((timeoutMs * 2L).coerceAtLeast(timeoutMs.toLong()), TimeUnit.MILLISECONDS)
            .apply {
                if (proxy != null) {
                    proxy(proxy)
                }
            }
            .build()
        client.newCall(requestBuilder.build()).execute().use { response ->
            return ResolverHttpResponse(
                code = response.code,
                body = response.body?.string().orEmpty(),
            )
        }
    }

    private fun baseClient(
        config: DnsResolverConfig,
        binding: ResolverBinding? = null,
    ): OkHttpClient {
        val normalized = config.sanitized()
        if (binding != null) {
            return buildClient(
                config = normalized,
                dns = createDns(normalized, binding),
                binding = binding,
            )
        }
        val cached = cachedConfig
        if (cached == normalized) {
            return cachedClient ?: buildClient(normalized)
        }
        synchronized(lock) {
            val lockedConfig = cachedConfig
            if (lockedConfig == normalized) {
                return cachedClient ?: buildClient(normalized)
            }
            val dns = createDns(normalized)
            val client = buildClient(normalized, dns)
            cachedConfig = normalized
            cachedDns = dns
            cachedClient = client
            return client
        }
    }

    private fun dns(config: DnsResolverConfig, binding: ResolverBinding? = null): Dns {
        val normalized = config.sanitized()
        if (binding != null) {
            return createDns(normalized, binding)
        }
        val cached = cachedConfig
        if (cached == normalized) {
            return cachedDns ?: createDns(normalized)
        }
        return synchronized(lock) {
            if (cachedConfig == normalized) {
                cachedDns ?: createDns(normalized)
            } else {
                val dns = createDns(normalized)
                val client = buildClient(normalized, dns)
                cachedConfig = normalized
                cachedDns = dns
                cachedClient = client
                dns
            }
        }
    }

    internal fun buildClient(
        config: DnsResolverConfig,
        dns: Dns = createDns(config),
        binding: ResolverBinding? = null,
    ): OkHttpClient {
        return OkHttpClient.Builder()
            .dns(dns)
            .followRedirects(true)
            .followSslRedirects(true)
            .apply {
                when (binding) {
                    is ResolverBinding.AndroidNetworkBinding -> socketFactory(binding.network.socketFactory)
                    is ResolverBinding.OsDeviceBinding -> socketFactory(BindToDeviceSocketFactory(binding.interfaceName))
                    null -> Unit
                }
            }
            .build()
    }

    internal fun createDns(config: DnsResolverConfig, binding: ResolverBinding? = null): Dns {
        dnsFactoryOverride?.let { return it(config, binding) }
        if (binding is ResolverBinding.OsDeviceBinding && binding.dnsMode == ResolverBinding.DnsMode.SYSTEM) {
            return Dns.SYSTEM
        }
        return when (config.mode) {
            DnsResolverMode.SYSTEM -> fallbackDns(binding)
            DnsResolverMode.DIRECT -> {
                val servers = config.effectiveDirectServers()
                if (servers.isEmpty()) {
                    fallbackDns(binding)
                } else {
                    DirectDns(servers, binding = binding)
                }
            }
            DnsResolverMode.DOH -> {
                val dohUrl = config.effectiveDohUrl() ?: return fallbackDns(binding)
                val bootstrapHosts = config.effectiveDohBootstrapHosts()
                    .mapNotNull { literalToInetAddress(it) }
                val bootstrapClient = OkHttpClient.Builder()
                    .apply {
                        when (binding) {
                            is ResolverBinding.AndroidNetworkBinding -> {
                                socketFactory(binding.network.socketFactory)
                                dns(NetworkDns(binding.network))
                            }
                            is ResolverBinding.OsDeviceBinding -> {
                                socketFactory(BindToDeviceSocketFactory(binding.interfaceName))
                                dns(Dns.SYSTEM)
                            }
                            null -> Unit
                        }
                    }
                    .build()
                val builder = DnsOverHttps.Builder()
                    .client(bootstrapClient)
                    .url(dohUrl.toHttpUrl())
                if (bootstrapHosts.isNotEmpty()) {
                    builder.bootstrapDnsHosts(bootstrapHosts)
                }
                builder.build()
            }
        }
    }

    private fun literalToInetAddress(value: String): InetAddress? {
        if (!DnsResolverConfig.isValidIpLiteral(value)) return null
        return runCatching { InetAddress.getByName(value.trim()) }.getOrNull()
    }

    private fun fallbackDns(binding: ResolverBinding?): Dns {
        return when (binding) {
            is ResolverBinding.AndroidNetworkBinding -> NetworkDns(binding.network)
            else -> Dns.SYSTEM
        }
    }
}

/**
 * SocketFactory that applies SO_BINDTODEVICE to each unconnected socket before OkHttp connects it.
 * Only the no-arg createSocket() matters for OkHttp. The other overloads connect immediately and
 * are present only to satisfy the abstract contract.
 */
internal class BindToDeviceSocketFactory(
    private val interfaceName: String,
) : SocketFactory() {
    override fun createSocket(): Socket = Socket().also {
        ResolverSocketBinder.bind(it, ResolverBinding.OsDeviceBinding(interfaceName))
    }
    override fun createSocket(host: String, port: Int): Socket = Socket(host, port)
    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        Socket(host, port, localHost, localPort)
    override fun createSocket(host: InetAddress, port: Int): Socket = Socket(host, port)
    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        Socket(address, port, localAddress, localPort)
}

private class NetworkDns(
    private val network: Network,
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (DnsResolverConfig.isValidIpLiteral(hostname)) {
            return listOf(InetAddress.getByName(hostname))
        }
        return network.getAllByName(hostname)
            ?.toList()
            ?.distinctBy { it.hostAddress }
            ?.takeIf { it.isNotEmpty() }
            ?: throw UnknownHostException("Failed to resolve $hostname on bound network")
    }
}

internal class DirectDns(
    servers: List<String>,
    private val port: Int = 53,
    private val timeoutMs: Int = 3_000,
    private val binding: ResolverBinding? = null,
) : Dns {
    private val serverAddresses = servers.mapNotNull { value ->
        runCatching { InetAddress.getByName(value.trim()) }.getOrNull()
    }

    override fun lookup(hostname: String): List<InetAddress> {
        if (serverAddresses.isEmpty()) return Dns.SYSTEM.lookup(hostname)
        if (DnsResolverConfig.isValidIpLiteral(hostname)) {
            return listOf(InetAddress.getByName(hostname))
        }

        val resolved = LinkedHashMap<String, InetAddress>()
        var lastFailure: Exception? = null

        for (type in listOf(1, 28)) {
            var typeResolved = false
            for (server in serverAddresses) {
                try {
                    val addresses = query(server, hostname, type)
                    if (addresses.isNotEmpty()) {
                        addresses.forEach { address ->
                            resolved[address.hostAddress ?: return@forEach] = address
                        }
                        typeResolved = true
                        break
                    }
                } catch (error: Exception) {
                    lastFailure = error
                }
            }
            if (!typeResolved && type == 1 && resolved.isEmpty() && lastFailure is UnknownHostException) {
                throw lastFailure as UnknownHostException
            }
        }

        if (resolved.isNotEmpty()) return resolved.values.toList()
        throw UnknownHostException(lastFailure?.message ?: "Failed to resolve $hostname")
    }

    private fun query(server: InetAddress, hostname: String, type: Int): List<InetAddress> {
        val requestId = Random.nextInt(0, 0xFFFF)
        val payload = buildQuery(hostname, type, requestId)
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            ResolverSocketBinder.bind(socket, binding)
            socket.send(DatagramPacket(payload, payload.size, server, port))

            val responseBuffer = ByteArray(1500)
            val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(responsePacket)
            return parseResponse(
                hostname = hostname,
                type = type,
                expectedId = requestId,
                data = responsePacket.data.copyOf(responsePacket.length),
            )
        }
    }

    private fun buildQuery(hostname: String, type: Int, requestId: Int): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeShort(requestId)
            stream.writeShort(0x0100)
            stream.writeShort(1)
            stream.writeShort(0)
            stream.writeShort(0)
            stream.writeShort(0)
            hostname.trimEnd('.').split('.').forEach { label ->
                val bytes = label.toByteArray(Charsets.UTF_8)
                stream.writeByte(bytes.size)
                stream.write(bytes)
            }
            stream.writeByte(0)
            stream.writeShort(type)
            stream.writeShort(1)
        }
        return output.toByteArray()
    }

    private fun parseResponse(
        hostname: String,
        type: Int,
        expectedId: Int,
        data: ByteArray,
    ): List<InetAddress> {
        if (data.size < 12) throw IOException("DNS response too short")
        val responseId = readUnsignedShort(data, 0)
        if (responseId != expectedId) throw IOException("Unexpected DNS response id")

        val flags = readUnsignedShort(data, 2)
        val rcode = flags and 0x000F
        if (rcode == 3) throw UnknownHostException(hostname)
        if (rcode != 0) throw IOException("DNS server error $rcode")

        val questionCount = readUnsignedShort(data, 4)
        val answerCount = readUnsignedShort(data, 6)

        var offset = 12
        repeat(questionCount) {
            offset = skipName(data, offset)
            offset += 4
            if (offset > data.size) throw IOException("Malformed DNS question")
        }

        val addresses = mutableListOf<InetAddress>()
        repeat(answerCount) {
            offset = skipName(data, offset)
            if (offset + 10 > data.size) throw IOException("Malformed DNS answer")
            val answerType = readUnsignedShort(data, offset)
            val answerClass = readUnsignedShort(data, offset + 2)
            val rdLength = readUnsignedShort(data, offset + 8)
            offset += 10
            if (offset + rdLength > data.size) throw IOException("Malformed DNS payload")

            val record = when {
                answerClass == 1 && answerType == 1 && rdLength == 4 -> InetAddress.getByAddress(data.copyOfRange(offset, offset + rdLength))
                answerClass == 1 && answerType == 28 && rdLength == 16 -> InetAddress.getByAddress(data.copyOfRange(offset, offset + rdLength))
                else -> null
            }
            if (record != null && matchesRequestedType(record, type)) {
                addresses += record
            }
            offset += rdLength
        }
        return addresses.distinctBy { it.hostAddress }
    }

    private fun matchesRequestedType(address: InetAddress, type: Int): Boolean {
        return when (type) {
            1 -> address is Inet4Address
            28 -> address is Inet6Address
            else -> false
        }
    }

    private fun skipName(data: ByteArray, startOffset: Int): Int {
        var offset = startOffset
        while (offset < data.size) {
            val length = data[offset].toInt() and 0xFF
            if (length == 0) return offset + 1
            if ((length and 0xC0) == 0xC0) {
                if (offset + 1 >= data.size) throw IOException("Malformed compression pointer")
                return offset + 2
            }
            offset += 1 + length
        }
        throw IOException("Malformed DNS name")
    }

    private fun readUnsignedShort(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }
}
