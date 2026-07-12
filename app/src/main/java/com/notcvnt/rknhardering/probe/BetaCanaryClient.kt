package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.Network
import android.os.Build
import com.notcvnt.rknhardering.AppUiSettings
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.SettingsPrefs
import com.notcvnt.rknhardering.registerDatagramSocket
import com.notcvnt.rknhardering.registerSocket
import com.notcvnt.rknhardering.rethrowIfCancellation
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

internal object BetaCanaryClient {
    private const val MAX_RESPONSE_BYTES = 32 * 1024
    private const val TOKEN_BYTES = 16
    private const val DNS_TYPE_TXT = 16
    private const val DNS_CLASS_IN = 1
    private val secureRandom = SecureRandom()

    fun run(
        context: Context,
        endpointConfig: BetaCanaryEndpointConfig?,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
        network: Network? = null,
        networkRequestsEnabled: Boolean = AppUiSettings.prefs(context)
            .getBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true),
    ): BetaCanaryRunResult {
        if (endpointConfig == null) {
            return BetaCanaryRunResult(BETA_CANARY_SCHEMA_VERSION, BetaCanaryStatus.UNAVAILABLE, reason = "ENDPOINT_CONFIG_ABSENT")
        }
        if (!networkRequestsEnabled) {
            return BetaCanaryRunResult(BETA_CANARY_SCHEMA_VERSION, BetaCanaryStatus.DISABLED, reason = "NETWORK_REQUESTS_DISABLED")
        }
        val config = endpointConfig.validated().getOrElse {
            return BetaCanaryRunResult(BETA_CANARY_SCHEMA_VERSION, BetaCanaryStatus.FAILED, reason = "ENDPOINT_CONFIG_INVALID")
        }
        executionContext.throwIfCancelled()
        val token = newRunToken()
        val observations = buildList {
            config.targets().forEach { (family, address) ->
                add(capture(BetaCanaryTransport.HTTP, family, executionContext) {
                    httpProbe(address, config.httpPort, family, token, config, tls = false, executionContext, network)
                })
                config.httpsPort?.let { httpsPort ->
                    add(capture(BetaCanaryTransport.HTTPS, family, executionContext) {
                        httpProbe(address, httpsPort, family, token, config, tls = true, executionContext, network)
                    })
                }
                add(capture(BetaCanaryTransport.TCP, family, executionContext) {
                    tcpProbe(address, config.tcpPort, family, token, config.timeoutMs, executionContext, network)
                })
                add(capture(BetaCanaryTransport.UDP, family, executionContext) {
                    udpProbe(address, config.udpPort, family, token, config.timeoutMs, executionContext, network)
                })
                add(capture(BetaCanaryTransport.DNS, family, executionContext) {
                    dnsProbe(address, config.dnsPort, config.dnsZone, family, token, config.timeoutMs, executionContext, network)
                })
                add(
                    BetaCanaryObservation(
                        transport = BetaCanaryTransport.QUIC,
                        family = family,
                        status = BetaCanaryStatus.UNSUPPORTED,
                        failureKind = "QUIC_REQUIRES_ABSENT_CRONET_OR_QUIC_DEPENDENCY",
                    ),
                )
            }
        }
        executionContext.throwIfCancelled()
        return BetaCanaryRunResult(
            schemaVersion = BETA_CANARY_SCHEMA_VERSION,
            status = if (observations.any { it.status == BetaCanaryStatus.AVAILABLE }) {
                BetaCanaryStatus.AVAILABLE
            } else {
                BetaCanaryStatus.FAILED
            },
            runTokenHash = privacyHash(token, token),
            boundNetworkHandle = network?.networkHandle,
            observations = observations,
        )
    }

    private inline fun capture(
        transport: BetaCanaryTransport,
        family: BetaCanaryAddressFamily,
        executionContext: ScanExecutionContext,
        block: () -> BetaCanaryObservation,
    ): BetaCanaryObservation = try {
        block()
    } catch (error: Exception) {
        rethrowIfCancellation(error, executionContext)
        BetaCanaryObservation(
            transport = transport,
            family = family,
            status = BetaCanaryStatus.FAILED,
            failureKind = when {
                error.hasCause<TlsSpkiPinMismatchException>() -> "SPKI_PIN_MISMATCH"
                error is SocketTimeoutException -> "TIMEOUT"
                error is SecurityException -> "PERMISSION_DENIED"
                else -> error.javaClass.simpleName.take(80)
            },
        )
    }

    private fun httpProbe(
        address: InetAddress,
        port: Int,
        family: BetaCanaryAddressFamily,
        token: String,
        config: BetaCanaryEndpointConfig,
        tls: Boolean,
        executionContext: ScanExecutionContext,
        network: Network?,
    ): BetaCanaryObservation {
        val rawSocket = connectedSocket(address, port, config.timeoutMs, executionContext, network)
        val lifetimeRegistration = executionContext.cancellationSignal.registerSocket(rawSocket)
        try {
            val socket: Socket
            var tlsFacts: TlsFacts? = null
            if (tls) {
                val serverName = requireNotNull(config.tlsServerName)
                val sslSocket = createTlsSocket(rawSocket, serverName, port, config.tlsSpkiSha256)
                sslSocket.soTimeout = config.timeoutMs
                sslSocket.startHandshake()
                val peer = sslSocket.session.peerCertificates.firstOrNull() as? X509Certificate
                    ?: throw IOException("TLS peer certificate unavailable")
                val actualPin = spkiPin(peer)
                config.tlsSpkiSha256?.let { expected ->
                    if (!MessageDigest.isEqual(normalizePin(expected).toByteArray(), actualPin.toByteArray())) {
                        throw TlsSpkiPinMismatchException()
                    }
                }
                tlsFacts = TlsFacts(
                    version = sslSocket.session.protocol,
                    cipher = sslSocket.session.cipherSuite,
                    alpn = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) sslSocket.applicationProtocol else null,
                    spki = actualPin,
                    chain = sslSocket.session.peerCertificates.filterIsInstance<X509Certificate>().map { certificate ->
                        Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.encoded))
                    },
                )
                socket = sslSocket
            } else {
                socket = rawSocket
            }
            socket.use {
                val host = config.tlsServerName ?: address.hostAddress.orEmpty()
                val path = "/v1/observe?schema=$BETA_CANARY_SCHEMA_VERSION&token=$token&family=${family.wireValue}"
                val request = "GET $path HTTP/1.1\r\nHost: $host\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
                socket.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
                socket.getOutputStream().flush()
                val rawResponse = readBounded(socket, MAX_RESPONSE_BYTES)
                val headerEnd = rawResponse.indexOf("\r\n\r\n")
                if (headerEnd < 0) throw IOException("Malformed HTTP response")
                val statusLine = rawResponse.substringBefore("\r\n")
                if (!statusLine.contains(" 200 ")) throw IOException("Canary HTTP status is not 200")
                val response = parseObservation(JSONObject(rawResponse.substring(headerEnd + 4)), token, family, if (tls) "https" else "http")
                return response.copy(
                    transport = if (tls) BetaCanaryTransport.HTTPS else BetaCanaryTransport.HTTP,
                    tlsVersion = tlsFacts?.version,
                    tlsCipher = tlsFacts?.cipher,
                    tlsAlpn = tlsFacts?.alpn,
                    certificateSpkiSha256 = tlsFacts?.spki,
                    certificateChainSha256 = tlsFacts?.chain.orEmpty(),
                    httpVersion = statusLine.substringBefore(' '),
                    clientLocalAddressHash = socket.localAddress?.hostAddress?.let { privacyHash(token, it) },
                )
            }
        } finally {
            lifetimeRegistration.dispose()
            runCatching { rawSocket.close() }
        }
    }

    private fun tcpProbe(
        address: InetAddress,
        port: Int,
        family: BetaCanaryAddressFamily,
        token: String,
        timeoutMs: Int,
        executionContext: ScanExecutionContext,
        network: Network?,
    ): BetaCanaryObservation {
        connectedSocket(address, port, timeoutMs, executionContext, network).use { socket ->
            val registration = executionContext.cancellationSignal.registerSocket(socket)
            try {
                val request = JSONObject()
                    .put("schema", BETA_CANARY_SCHEMA_VERSION)
                    .put("token", token)
                    .put("family", family.wireValue)
                    .toString() + "\n"
                socket.getOutputStream().write(request.toByteArray(Charsets.UTF_8))
                socket.getOutputStream().flush()
                val response = readLineBounded(socket, MAX_RESPONSE_BYTES)
                return parseObservation(JSONObject(response), token, family, "tcp").copy(
                    transport = BetaCanaryTransport.TCP,
                    clientLocalAddressHash = socket.localAddress?.hostAddress?.let { privacyHash(token, it) },
                )
            } finally {
                registration.dispose()
            }
        }
    }

    private fun udpProbe(
        address: InetAddress,
        port: Int,
        family: BetaCanaryAddressFamily,
        token: String,
        timeoutMs: Int,
        executionContext: ScanExecutionContext,
        network: Network?,
    ): BetaCanaryObservation {
        DatagramSocket(null).use { socket ->
            socket.reuseAddress = false
            network?.bindSocket(socket)
            socket.bind(InetSocketAddress(if (family == BetaCanaryAddressFamily.IPV4) "0.0.0.0" else "::", 0))
            socket.connect(address, port)
            socket.soTimeout = timeoutMs
            val registration = executionContext.cancellationSignal.registerDatagramSocket(socket)
            try {
                executionContext.throwIfCancelled()
                val request = JSONObject()
                    .put("schema", BETA_CANARY_SCHEMA_VERSION)
                    .put("token", token)
                    .put("family", family.wireValue)
                    .toString()
                    .toByteArray(Charsets.UTF_8)
                socket.send(DatagramPacket(request, request.size))
                val buffer = ByteArray(8192)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                executionContext.throwIfCancelled()
                return parseObservation(
                    JSONObject(String(response.data, response.offset, response.length, Charsets.UTF_8)),
                    token,
                    family,
                    "udp",
                ).copy(
                    transport = BetaCanaryTransport.UDP,
                    clientLocalAddressHash = socket.localAddress?.hostAddress?.let { privacyHash(token, it) },
                )
            } finally {
                registration.dispose()
            }
        }
    }

    private fun dnsProbe(
        address: InetAddress,
        port: Int,
        zone: String,
        family: BetaCanaryAddressFamily,
        token: String,
        timeoutMs: Int,
        executionContext: ScanExecutionContext,
        network: Network?,
    ): BetaCanaryObservation {
        val nonce = newRunToken().take(12)
        val qname = "$nonce.$token.$zone"
        val queryId = secureRandom.nextInt(0x10000)
        val query = buildDnsTxtQuery(queryId, qname)
        DatagramSocket(null).use { socket ->
            network?.bindSocket(socket)
            socket.bind(InetSocketAddress(if (family == BetaCanaryAddressFamily.IPV4) "0.0.0.0" else "::", 0))
            socket.connect(address, port)
            socket.soTimeout = timeoutMs
            val registration = executionContext.cancellationSignal.registerDatagramSocket(socket)
            try {
                socket.send(DatagramPacket(query, query.size))
                val buffer = ByteArray(4096)
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                executionContext.throwIfCancelled()
                val fields = parseDnsTxtResponse(packet.data.copyOfRange(packet.offset, packet.offset + packet.length), queryId)
                if (fields["v"] != BETA_CANARY_SCHEMA_VERSION.toString() || fields["t"] != token) {
                    throw IOException("DNS canary schema/token mismatch")
                }
                val observed = fields["src"] ?: throw IOException("DNS canary source missing")
                if (fields["fam"] != family.wireValue) throw IOException("DNS canary family mismatch")
                return BetaCanaryObservation(
                    transport = BetaCanaryTransport.DNS,
                    family = family,
                    status = BetaCanaryStatus.AVAILABLE,
                    observedAddressHash = privacyHash(token, observed),
                    clientLocalAddressHash = socket.localAddress?.hostAddress?.let { privacyHash(token, it) },
                    serverInstance = fields["srv"]?.take(80),
                    serverTimestampSeconds = fields["ts"]?.toLongOrNull(),
                )
            } finally {
                registration.dispose()
            }
        }
    }

    private fun connectedSocket(
        address: InetAddress,
        port: Int,
        timeoutMs: Int,
        executionContext: ScanExecutionContext,
        network: Network?,
    ): Socket {
        val socket = Socket()
        val registration = executionContext.cancellationSignal.registerSocket(socket)
        try {
            executionContext.throwIfCancelled()
            network?.bindSocket(socket)
            socket.connect(InetSocketAddress(address, port), timeoutMs)
            socket.soTimeout = timeoutMs
            return socket
        } catch (error: Exception) {
            socket.close()
            rethrowIfCancellation(error, executionContext)
            throw error
        } finally {
            registration.dispose()
        }
    }

    private fun parseObservation(
        json: JSONObject,
        token: String,
        family: BetaCanaryAddressFamily,
        expectedProtocol: String,
    ): BetaCanaryObservation {
        if (json.optInt("schema", -1) != BETA_CANARY_SCHEMA_VERSION) throw IOException("Canary schema mismatch")
        if (json.optString("token") != token) throw IOException("Canary token mismatch")
        if (json.optString("family") != family.wireValue) throw IOException("Canary family mismatch")
        if (json.optString("protocol") != expectedProtocol) throw IOException("Canary protocol mismatch")
        val observedAddress = json.optString("observed_address").takeIf { it.isNotBlank() }
            ?: throw IOException("Canary observed address missing")
        return BetaCanaryObservation(
            transport = BetaCanaryTransport.TCP,
            family = family,
            status = BetaCanaryStatus.AVAILABLE,
            observedAddressHash = privacyHash(token, observedAddress),
            localDestinationHash = json.optString("local_destination").takeIf { it.isNotBlank() }?.let { privacyHash(token, it) },
            ingressInterfaceIndex = json.optInt("ingress_ifindex", -1).takeIf { it >= 0 },
            serverInstance = json.optString("server_instance").takeIf { it.isNotBlank() }?.take(80),
            serverTimestampSeconds = json.optLong("timestamp", -1L).takeIf { it >= 0 },
            httpVersion = json.optString("http_version").takeIf { it.isNotBlank() }?.take(32),
            serverFingerprintHash = json.optJSONObject("fingerprint")?.toString()?.let { privacyHash(token, it) },
        )
    }

    private fun createTlsSocket(rawSocket: Socket, serverName: String, port: Int, pin: String?): SSLSocket {
        val factory = if (pin == null) {
            SSLSocketFactory.getDefault() as SSLSocketFactory
        } else {
            pinnedSocketFactory(normalizePin(pin))
        }
        val socket = factory.createSocket(rawSocket, serverName, port, true) as SSLSocket
        val parameters = socket.sslParameters
        parameters.endpointIdentificationAlgorithm = "HTTPS"
        parameters.serverNames = listOf(SNIHostName(serverName))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) parameters.applicationProtocols = arrayOf("http/1.1")
        socket.sslParameters = parameters
        return socket
    }

    private fun pinnedSocketFactory(expectedPin: String): SSLSocketFactory {
        val trustManager = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                val leaf = chain?.firstOrNull() ?: throw java.security.cert.CertificateException("Empty server chain")
                val actual = spkiPin(leaf)
                if (!MessageDigest.isEqual(expectedPin.toByteArray(), actual.toByteArray())) {
                    throw TlsSpkiPinMismatchException()
                }
            }
        }
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), secureRandom)
        }.socketFactory
    }

    private fun spkiPin(certificate: X509Certificate): String =
        "sha256/" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded))

    private fun normalizePin(pin: String): String {
        val normalized = pin.trim()
        require(normalized.startsWith("sha256/") && normalized.length > 10) { "Invalid SPKI pin" }
        Base64.getDecoder().decode(normalized.removePrefix("sha256/"))
        return normalized
    }

    private inline fun <reified T : Throwable> Throwable.hasCause(): Boolean {
        var current: Throwable? = this
        while (current != null) {
            if (current is T) return true
            current = current.cause
        }
        return false
    }

    private class TlsSpkiPinMismatchException : java.security.cert.CertificateException("SPKI pin mismatch")

    private fun buildDnsTxtQuery(id: Int, qname: String): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { data ->
            data.writeShort(id)
            data.writeShort(0x0100)
            data.writeShort(1)
            data.writeShort(0)
            data.writeShort(0)
            data.writeShort(0)
            qname.split('.').forEach { label ->
                val bytes = label.toByteArray(Charsets.US_ASCII)
                require(bytes.size in 1..63) { "Invalid DNS label" }
                data.writeByte(bytes.size)
                data.write(bytes)
            }
            data.writeByte(0)
            data.writeShort(DNS_TYPE_TXT)
            data.writeShort(DNS_CLASS_IN)
        }
        return output.toByteArray()
    }

    private fun parseDnsTxtResponse(data: ByteArray, expectedId: Int): Map<String, String> {
        if (data.size < 12 || unsignedShort(data, 0) != expectedId) throw IOException("Malformed DNS response")
        val flags = unsignedShort(data, 2)
        if ((flags and 0x8000) == 0 || (flags and 0x000F) != 0) throw IOException("DNS canary returned an error")
        val questions = unsignedShort(data, 4)
        val answers = unsignedShort(data, 6)
        var offset = 12
        repeat(questions) {
            offset = skipDnsName(data, offset)
            if (offset + 4 > data.size) throw IOException("Malformed DNS question")
            offset += 4
        }
        repeat(answers) {
            offset = skipDnsName(data, offset)
            if (offset + 10 > data.size) throw IOException("Malformed DNS answer")
            val type = unsignedShort(data, offset)
            val recordClass = unsignedShort(data, offset + 2)
            val length = unsignedShort(data, offset + 8)
            offset += 10
            if (offset + length > data.size) throw IOException("Malformed DNS rdata")
            if (type == DNS_TYPE_TXT && recordClass == DNS_CLASS_IN && length > 0) {
                val textLength = data[offset].toInt() and 0xFF
                if (textLength + 1 > length) throw IOException("Malformed DNS TXT")
                val text = String(data, offset + 1, textLength, Charsets.UTF_8)
                return text.split(';').mapNotNull { part ->
                    val separator = part.indexOf('=')
                    if (separator <= 0) null else part.substring(0, separator) to part.substring(separator + 1)
                }.toMap()
            }
            offset += length
        }
        throw IOException("DNS TXT answer missing")
    }

    private fun skipDnsName(data: ByteArray, start: Int): Int {
        var offset = start
        while (offset < data.size) {
            val length = data[offset].toInt() and 0xFF
            if (length == 0) return offset + 1
            if ((length and 0xC0) == 0xC0) {
                if (offset + 1 >= data.size) throw IOException("Malformed DNS compression")
                return offset + 2
            }
            if (length > 63 || offset + 1 + length > data.size) throw IOException("Malformed DNS name")
            offset += 1 + length
        }
        throw IOException("Malformed DNS name")
    }

    private fun unsignedShort(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun readLineBounded(socket: Socket, limit: Int): String {
        val output = ByteArrayOutputStream()
        while (output.size() < limit) {
            val next = socket.getInputStream().read()
            if (next < 0 || next == '\n'.code) return output.toString(Charsets.UTF_8.name())
            output.write(next)
        }
        throw IOException("Canary response exceeds limit")
    }

    private fun readBounded(socket: Socket, limit: Int): String {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (output.size() < limit) {
            val read = socket.getInputStream().read(buffer, 0, minOf(buffer.size, limit - output.size()))
            if (read < 0) return output.toString(Charsets.UTF_8.name())
            output.write(buffer, 0, read)
        }
        throw IOException("Canary response exceeds limit")
    }

    internal fun newRunToken(): String = ByteArray(TOKEN_BYTES).also(secureRandom::nextBytes).joinToString("") { "%02x".format(it) }

    internal fun privacyHash(token: String, value: String): String = MessageDigest.getInstance("SHA-256")
        .digest("$token\u0000$value".toByteArray(Charsets.UTF_8))
        .take(12)
        .joinToString("") { "%02x".format(it) }

    private data class TlsFacts(
        val version: String,
        val cipher: String,
        val alpn: String?,
        val spki: String,
        val chain: List<String>,
    )
}
