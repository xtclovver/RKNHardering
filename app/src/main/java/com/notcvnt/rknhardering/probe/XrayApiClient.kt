package com.notcvnt.rknhardering.probe

import android.util.Base64
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.rethrowIfCancellation
import com.xray.app.proxyman.command.HandlerServiceGrpc
import com.xray.app.proxyman.command.ListOutboundsRequest
import com.xray.app.proxyman.SenderConfig as ProxymanSenderConfig
import com.xray.common.net.IPOrDomain
import com.xray.proxy.vless.Account as VlessAccount
import com.xray.proxy.vless.outbound.Config as VlessOutboundConfig
import com.xray.transport.internet.reality.Config as RealityConfig
import io.grpc.okhttp.OkHttpChannelBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.util.concurrent.TimeUnit

class XrayApiClient(
    private val host: String = "127.0.0.1",
) {
    suspend fun listOutbounds(
        port: Int,
        deadlineMs: Long = 600,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): Result<XrayApiScanResult> = withContext(Dispatchers.IO) {
        val channel = OkHttpChannelBuilder.forAddress(host, port)
            .usePlaintext()
            .build()
        val registration = executionContext.cancellationSignal.register {
            channel.shutdownNow()
        }

        try {
            executionContext.throwIfCancelled()
            val stub = HandlerServiceGrpc.newBlockingStub(channel)
                .withDeadlineAfter(deadlineMs, TimeUnit.MILLISECONDS)

            val response = stub.listOutbounds(ListOutboundsRequest.getDefaultInstance())
            val outbounds = response.outboundsList
                .filterNot { outbound ->
                    outbound.proxySettings.type == "xray.proxy.freedom.Config" ||
                        outbound.proxySettings.type == "xray.proxy.blackhole.Config"
                }
                .map { outbound ->
                    val tag = outbound.tag.takeIf { it.isNotBlank() } ?: "(untagged)"
                    val senderType = outbound.senderSettings.type.takeIf { it.isNotBlank() }
                    val proxyType = outbound.proxySettings.type.takeIf { it.isNotBlank() }

                    val senderParsed = parseSenderSettings(outbound.senderSettings.type, outbound.senderSettings.value)
                    val vlessParsed = parseVlessProxySettings(outbound.proxySettings.type, outbound.proxySettings.value)

                    XrayOutboundSummary(
                        tag = tag,
                        protocolName = senderParsed.protocolName,
                        address = vlessParsed.address,
                        port = vlessParsed.port,
                        uuid = vlessParsed.uuid,
                        sni = senderParsed.sni,
                        publicKey = senderParsed.publicKey,
                        senderSettingsType = senderType,
                        proxySettingsType = proxyType,
                    )
                }

            Result.success(
                XrayApiScanResult(
                    endpoint = XrayApiEndpoint(host = host, port = port),
                    outbounds = outbounds,
                ),
            )
        } catch (e: Exception) {
            rethrowIfCancellation(e, executionContext)
            Result.failure(e)
        } finally {
            registration.dispose()
            channel.shutdownNow()
            channel.awaitTermination(100, TimeUnit.MILLISECONDS)
        }
    }

    private data class SenderParsed(
        val protocolName: String?,
        val sni: String?,
        val publicKey: String?,
    )

    private data class VlessParsed(
        val address: String?,
        val port: Int?,
        val uuid: String?,
    )

    private fun parseSenderSettings(type: String, value: com.google.protobuf.ByteString): SenderParsed {
        if (type != "xray.app.proxyman.SenderConfig") {
            return SenderParsed(protocolName = null, sni = null, publicKey = null)
        }

        return try {
            val sender = ProxymanSenderConfig.parseFrom(value)
            val stream = sender.streamSettings
            val protocolName = stream.protocolName.takeIf { it.isNotBlank() }

            var sni: String? = null
            var publicKey: String? = null
            for (security in stream.securitySettingsList) {
                if (security.type != "xray.transport.internet.reality.Config") continue
                val reality = RealityConfig.parseFrom(security.value)
                if (sni == null) sni = reality.serverName.takeIf { it.isNotBlank() }
                if (publicKey == null && reality.publicKey.size() > 0) {
                    publicKey = Base64.encodeToString(reality.publicKey.toByteArray(), Base64.NO_WRAP)
                }
            }

            SenderParsed(protocolName = protocolName, sni = sni, publicKey = publicKey)
        } catch (_: Exception) {
            SenderParsed(protocolName = null, sni = null, publicKey = null)
        }
    }

    private fun parseVlessProxySettings(type: String, value: com.google.protobuf.ByteString): VlessParsed {
        if (type != "xray.proxy.vless.outbound.Config") {
            return VlessParsed(address = null, port = null, uuid = null)
        }

        return try {
            val config = VlessOutboundConfig.parseFrom(value)
            val vnext = config.vnext
            val address = ipOrDomainToString(vnext.address)
            val port = vnext.port
            val user = vnext.user

            var uuid: String? = null
            val account = user.account
            if (account.type == "xray.proxy.vless.Account") {
                uuid = VlessAccount.parseFrom(account.value).id.takeIf { it.isNotBlank() }
            }

            VlessParsed(address = address, port = port, uuid = uuid)
        } catch (_: Exception) {
            VlessParsed(address = null, port = null, uuid = null)
        }
    }

    private fun ipOrDomainToString(value: IPOrDomain): String? {
        return when (value.addressCase) {
            IPOrDomain.AddressCase.DOMAIN -> value.domain.takeIf { it.isNotBlank() }
            IPOrDomain.AddressCase.IP -> try {
                InetAddress.getByAddress(value.ip.toByteArray()).hostAddress
            } catch (_: Exception) {
                null
            }
            else -> null
        }
    }
}
