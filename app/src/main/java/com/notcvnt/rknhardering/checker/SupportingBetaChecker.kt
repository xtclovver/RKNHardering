package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import java.io.File
import java.net.Proxy
import java.net.ProxySelector
import java.net.URI

internal object SupportingBetaChecker {
    internal data class InterfaceTrafficSample(
        val interfaceName: String?,
        val rxBytes: Long?,
        val txBytes: Long?,
    )
    private val CONTROL_URIS = listOf(
        URI.create("https://api4.ipify.org/"),
        URI.create("https://api6.ipify.org/"),
        URI.create("https://ifconfig.me/ip"),
    )
    private val SAFE_INTERFACE_NAME = Regex("[A-Za-z0-9_.:-]{1,64}")
    private val TUNNEL_MARKERS = setOf("tun", "wireguard", "xfrm", "vti", "ovpn", "tuntap")

    fun check(
        context: Context,
        proxySelectorEnabled: Boolean,
        interfaceDriverEnabled: Boolean,
        epochId: String,
        observedAtElapsedMs: Long,
    ): List<BetaObservation> = buildList {
        if (proxySelectorEnabled) {
            add(proxySelectorObservation(context, epochId, observedAtElapsedMs))
        }
        if (interfaceDriverEnabled) {
            add(interfaceDriverObservation(context, epochId, observedAtElapsedMs))
        }
    }

    internal fun proxySelectorObservation(
        context: Context,
        epochId: String,
        at: Long,
        selector: ProxySelector? = ProxySelector.getDefault(),
    ): BetaObservation {
        if (selector == null) return observation(
            checkId = "beta.proxy_selector",
            source = EvidenceSource.BETA_PROXY_SELECTOR,
            group = "android_proxy",
            domain = DetectionDomain.VPN_OR_PROXY,
            availability = ProbeAvailability.UNAVAILABLE,
            polarity = ObservationPolarity.INCONCLUSIVE,
            confidence = EvidenceConfidence.LOW,
            summary = context.getString(R.string.beta_proxy_selector_unavailable),
            epochId = epochId,
            at = at,
        )
        val selections = runCatching {
            CONTROL_URIS.flatMap { uri -> selector.select(uri).orEmpty() }
        }.getOrElse { error ->
            return observation(
                checkId = "beta.proxy_selector",
                source = EvidenceSource.BETA_PROXY_SELECTOR,
                group = "android_proxy",
                domain = DetectionDomain.VPN_OR_PROXY,
                availability = if (error is SecurityException) {
                    ProbeAvailability.PERMISSION_DENIED
                } else {
                    ProbeAvailability.ERROR
                },
                polarity = ObservationPolarity.INCONCLUSIVE,
                confidence = EvidenceConfidence.LOW,
                summary = context.getString(R.string.beta_proxy_selector_unavailable),
                epochId = epochId,
                at = at,
            )
        }
        val proxyTypes = selections.asSequence()
            .filter { it.type() != Proxy.Type.DIRECT }
            .map { it.type().name }
            .toSortedSet()
        return observation(
            checkId = "beta.proxy_selector",
            source = EvidenceSource.BETA_PROXY_SELECTOR,
            group = "android_proxy",
            domain = DetectionDomain.VPN_OR_PROXY,
            availability = ProbeAvailability.AVAILABLE,
            polarity = if (proxyTypes.isEmpty()) {
                ObservationPolarity.AUTHORITATIVE_NEGATIVE
            } else {
                ObservationPolarity.POSITIVE
            },
            confidence = if (proxyTypes.isEmpty()) EvidenceConfidence.LOW else EvidenceConfidence.MEDIUM,
            summary = if (proxyTypes.isEmpty()) {
                context.getString(R.string.beta_proxy_selector_direct)
            } else {
                context.getString(R.string.beta_proxy_selector_configured, proxyTypes.joinToString(", "))
            },
            epochId = epochId,
            at = at,
            suppressions = if (proxyTypes.isEmpty()) emptyList() else {
                listOf(BetaSuppressionRuleId.UNSCOPED_GLOBAL_STATE)
            },
        )
    }

    internal fun interfaceDriverObservation(
        context: Context,
        epochId: String,
        at: Long,
        sysfsReader: (String) -> String? = ::readSmallText,
    ): BetaObservation {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = connectivity?.activeNetwork
        val interfaceName = network?.let(connectivity::getLinkProperties)?.interfaceName
        if (interfaceName == null || !SAFE_INTERFACE_NAME.matches(interfaceName)) {
            return interfaceObservation(
                context,
                ProbeAvailability.UNAVAILABLE,
                ObservationPolarity.INCONCLUSIVE,
                EvidenceConfidence.LOW,
                null,
                epochId,
                at,
            )
        }
        val base = "/sys/class/net/$interfaceName"
        val values = listOf("uevent", "tun_flags", "iflink", "addr_assign_type", "operstate")
            .mapNotNull { name -> sysfsReader("$base/$name") }
        return evaluateInterfaceDriver(context, interfaceName, values, epochId, at)
    }

    fun sampleInterfaceTraffic(context: Context): InterfaceTrafficSample {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val interfaceName = connectivity?.activeNetwork
            ?.let(connectivity::getLinkProperties)
            ?.interfaceName
            ?.takeIf(SAFE_INTERFACE_NAME::matches)
        if (interfaceName == null) return InterfaceTrafficSample(null, null, null)
        val base = "/sys/class/net/$interfaceName/statistics"
        return InterfaceTrafficSample(
            interfaceName,
            readSmallText("$base/rx_bytes")?.trim()?.toLongOrNull(),
            readSmallText("$base/tx_bytes")?.trim()?.toLongOrNull(),
        )
    }

    fun interfaceTrafficObservation(
        context: Context,
        before: InterfaceTrafficSample,
        after: InterfaceTrafficSample,
        canaryTransferred: Boolean,
        epochId: String,
        at: Long,
    ): BetaObservation {
        val complete = before.interfaceName != null && before.interfaceName == after.interfaceName &&
            before.rxBytes != null && before.txBytes != null && after.rxBytes != null && after.txBytes != null
        val increased = complete && canaryTransferred &&
            (after.rxBytes!! > before.rxBytes!! || after.txBytes!! > before.txBytes!!)
        return observation(
            checkId = "beta.interface_traffic",
            source = EvidenceSource.BETA_INTERFACE_TRAFFIC,
            group = "active_egress",
            domain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
            availability = if (complete) ProbeAvailability.AVAILABLE else ProbeAvailability.UNAVAILABLE,
            polarity = if (increased) ObservationPolarity.POSITIVE else ObservationPolarity.INCONCLUSIVE,
            confidence = if (increased) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
            summary = context.getString(
                if (increased) R.string.beta_interface_traffic_correlated else R.string.beta_interface_traffic_unavailable,
            ),
            epochId = epochId,
            at = at,
            suppressions = if (increased) listOf(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS) else emptyList(),
        )
    }

    internal fun evaluateInterfaceDriver(
        context: Context,
        interfaceName: String,
        values: List<String>,
        epochId: String,
        at: Long,
    ): BetaObservation {
        if (values.isEmpty()) {
            return interfaceObservation(
                context,
                ProbeAvailability.UNAVAILABLE,
                ObservationPolarity.INCONCLUSIVE,
                EvidenceConfidence.LOW,
                interfaceName,
                epochId,
                at,
            )
        }
        val normalized = values.joinToString("\n").lowercase()
        val tunnelKind = TUNNEL_MARKERS.firstOrNull { marker -> normalized.contains(marker) }
        return interfaceObservation(
            context,
            ProbeAvailability.AVAILABLE,
            if (tunnelKind == null) ObservationPolarity.INCONCLUSIVE else ObservationPolarity.POSITIVE,
            if (tunnelKind == null) EvidenceConfidence.LOW else EvidenceConfidence.MEDIUM,
            interfaceName,
            epochId,
            at,
            tunnelKind,
            suppressions = if (tunnelKind == null) emptyList() else {
                listOf(BetaSuppressionRuleId.NO_CAUSAL_COUNTER_DELTA)
            },
        )
    }

    private fun interfaceObservation(
        context: Context,
        availability: ProbeAvailability,
        polarity: ObservationPolarity,
        confidence: EvidenceConfidence,
        interfaceName: String?,
        epochId: String,
        at: Long,
        tunnelKind: String? = null,
        suppressions: List<BetaSuppressionRuleId> = emptyList(),
    ) = observation(
        checkId = "beta.interface_driver",
        source = EvidenceSource.BETA_LINK_DRIVER,
        group = "kernel_link",
        domain = DetectionDomain.VPN_OR_PROXY,
        availability = availability,
        polarity = polarity,
        confidence = confidence,
        summary = when {
            tunnelKind != null -> context.getString(R.string.beta_interface_driver_tunnel, tunnelKind)
            interfaceName != null -> context.getString(R.string.beta_interface_driver_checked)
            else -> context.getString(R.string.beta_interface_driver_unavailable)
        },
        epochId = epochId,
        at = at,
        suppressions = suppressions,
    )

    private fun observation(
        checkId: String,
        source: EvidenceSource,
        group: String,
        domain: DetectionDomain,
        availability: ProbeAvailability,
        polarity: ObservationPolarity,
        confidence: EvidenceConfidence,
        summary: String,
        epochId: String,
        at: Long,
        suppressions: List<BetaSuppressionRuleId> = emptyList(),
    ) = BetaObservation(
        checkId = checkId,
        source = source,
        availability = availability,
        polarity = polarity,
        authority = ObservationAuthority.PUBLIC_ANDROID_API,
        confidence = confidence,
        independenceGroup = group,
        detectionDomain = domain,
        facts = mapOf("summary" to summary),
        suppressions = suppressions,
        observedAtElapsedMs = at,
        networkEpochId = epochId,
    )

    private fun readSmallText(path: String): String? = runCatching {
        File(path).inputStream().bufferedReader().use { reader ->
            buildString {
                val buffer = CharArray(1024)
                while (length < 4096) {
                    val count = reader.read(buffer, 0, minOf(buffer.size, 4096 - length))
                    if (count <= 0) break
                    append(buffer, 0, count)
                }
            }
        }
    }.getOrNull()
}
