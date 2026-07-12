package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.ParcelFileDescriptor
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.registerDatagramSocket
import java.net.DatagramSocket
import java.net.InetAddress

internal data class ParsedBetaProbeRow(
    val checkId: String,
    val availability: ProbeAvailability,
    val fields: Map<String, String>,
)

internal object BetaProbeRowParser {
    private const val PREFIX = "beta_v1"
    private const val MAX_ROWS = 32
    private const val MAX_TOTAL_CHARS = 16_384
    private const val MAX_FIELDS = 64

    fun parse(rows: Array<String>, expectedCheckId: String): ParsedBetaProbeRow {
        if (rows.isEmpty()) return unavailable(expectedCheckId)
        if (rows.size > MAX_ROWS || rows.sumOf(String::length) > MAX_TOTAL_CHARS) {
            return ParsedBetaProbeRow(expectedCheckId, ProbeAvailability.TRUNCATED, emptyMap())
        }
        val matching = rows.firstOrNull { row -> row.contains("check=$expectedCheckId") }
            ?: return ParsedBetaProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
        val parts = matching.split('|')
        if (parts.firstOrNull() != PREFIX || parts.size > MAX_FIELDS + 1) {
            return ParsedBetaProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
        }
        val fields = linkedMapOf<String, String>()
        for (part in parts.drop(1)) {
            val separator = part.indexOf('=')
            if (separator <= 0 || separator == part.lastIndex) {
                return ParsedBetaProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
            }
            val key = part.substring(0, separator)
            if (fields.put(key, part.substring(separator + 1)) != null) {
                return ParsedBetaProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
            }
        }
        if (fields["check"] != expectedCheckId) {
            return ParsedBetaProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
        }
        val availability = when (fields["status"]) {
            "available" -> ProbeAvailability.AVAILABLE
            "permission_denied" -> ProbeAvailability.PERMISSION_DENIED
            "unsupported" -> ProbeAvailability.UNSUPPORTED
            "unavailable" -> ProbeAvailability.UNAVAILABLE
            "truncated" -> ProbeAvailability.TRUNCATED
            "malformed_response" -> ProbeAvailability.MALFORMED_RESPONSE
            "race" -> ProbeAvailability.RACE
            "skipped" -> ProbeAvailability.SKIPPED
            "error" -> ProbeAvailability.ERROR
            else -> ProbeAvailability.MALFORMED_RESPONSE
        }
        return ParsedBetaProbeRow(expectedCheckId, availability, fields)
    }

    private fun unavailable(checkId: String) =
        ParsedBetaProbeRow(checkId, ProbeAvailability.UNAVAILABLE, emptyMap())
}

internal object AdvancedNetlinkProbe {
    fun check(
        context: Context,
        aggressive: Boolean,
        epochId: String,
        observedAtElapsedMs: Long,
        executionContext: ScanExecutionContext,
    ): List<BetaObservation> {
        NativeSignsBridge.initIfNeeded()
        if (!NativeSignsBridge.isLibraryLoaded()) return unavailable(epochId, observedAtElapsedMs)
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = connectivity?.activeNetwork ?: return unsupported(epochId, observedAtElapsedMs)
        val target = connectivity.getLinkProperties(network)?.dnsServers?.firstOrNull()
            ?: return unsupported(epochId, observedAtElapsedMs)
        executionContext.throwIfCancelled()

        val socket = DatagramSocket()
        val registration = executionContext.cancellationSignal.registerDatagramSocket(socket)
        return try {
            network.bindSocket(socket)
            socket.connect(target, 53)
            val parcelDescriptor = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                ParcelFileDescriptor.fromDatagramSocket(socket).dup()
            } else {
                ParcelFileDescriptor.fromDatagramSocket(socket)
            }
            parcelDescriptor.use { descriptor ->
                executionContext.throwIfCancelled()
                val socketRow = compareSocketViews(BetaProbeRowParser.parse(
                    NativeSignsBridge.betaSocketIdentity(descriptor.fd),
                    "socket_identity",
                ), socket)
                executionContext.throwIfCancelled()
                val diagRow = BetaProbeRowParser.parse(
                    NativeSignsBridge.betaInetDiagByCookie(descriptor.fd, executionContext.cancellationSignal),
                    "inet_diag_cookie",
                )
                executionContext.throwIfCancelled()
                val netdRow = BetaProbeRowParser.parse(
                    NativeSignsBridge.betaNetdIdentity(descriptor.fd),
                    "netd_netid",
                )
                executionContext.throwIfCancelled()
                val routingRows = NativeSignsBridge.betaRoutingSnapshot(
                    descriptor.fd,
                    android.os.Process.myUid(),
                    executionContext.cancellationSignal,
                )
                executionContext.throwIfCancelled()
                val routeRow = BetaProbeRowParser.parse(routingRows, "route_lookup")
                val rulesRow = BetaProbeRowParser.parse(routingRows, "policy_rules")
                val addressRow = BetaProbeRowParser.parse(routingRows, "rtnl_address")
                val base = listOf(
                    socketObservation(socketRow, epochId, observedAtElapsedMs),
                    diagObservation(diagRow, epochId, observedAtElapsedMs),
                    netdObservation(netdRow, epochId, observedAtElapsedMs),
                    routeObservation(routeRow, epochId, observedAtElapsedMs),
                    rulesObservation(rulesRow, epochId, observedAtElapsedMs),
                    addressObservation(addressRow, epochId, observedAtElapsedMs),
                )
                if (!aggressive) return@use base
                executionContext.throwIfCancelled()
                val unixRow = BetaProbeRowParser.parse(
                    NativeSignsBridge.betaUnixDiagProbe(executionContext.cancellationSignal),
                    "unix_diag",
                )
                val originalRow = BetaProbeRowParser.parse(
                    NativeSignsBridge.betaOriginalDestinationProbe(descriptor.fd),
                    "original_destination",
                )
                val pktInfoRow = BetaProbeRowParser.parse(
                    NativeSignsBridge.betaPktInfoProbe(descriptor.fd),
                    "pktinfo",
                )
                val extendedRouteRow = BetaProbeRowParser.parse(
                    NativeSignsBridge.betaExtendedRouteProbe(
                        descriptor.fd,
                        android.os.Process.myUid(),
                        executionContext.cancellationSignal,
                    ),
                    "extended_rtnetlink",
                )
                val transitionRow = BetaProbeRowParser.parse(
                    NativeSignsBridge.betaTransitionMonitor(250, executionContext.cancellationSignal),
                    "netlink_transitions",
                )
                base + listOf(
                    unixDiagObservation(unixRow, epochId, observedAtElapsedMs),
                    originalDestinationObservation(originalRow, epochId, observedAtElapsedMs),
                    pktInfoObservation(pktInfoRow, epochId, observedAtElapsedMs),
                    extendedRouteObservation(extendedRouteRow, epochId, observedAtElapsedMs),
                    transitionObservation(transitionRow, epochId, observedAtElapsedMs),
                )
            }
        } catch (error: Throwable) {
            executionContext.throwIfCancelled(error)
            unavailable(epochId, observedAtElapsedMs)
        } finally {
            registration.dispose()
            socket.close()
        }
    }

    internal fun socketObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row = row,
        source = EvidenceSource.BETA_SOCKET_MARK,
        group = "kernel_socket",
        summary = "Socket identity collected",
        positive = row.fields["critical_mismatch"] == "true",
        authoritativeNegative = row.fields["identity_complete"] == "true" &&
            row.fields["critical_mismatch"] == "false" &&
            row.fields.keys.any { it in setOf("cookie", "mark", "netns_cookie", "bound_ifindex") },
        epochId = epochId,
        at = at,
    )

    internal fun compareSocketViews(
        row: ParsedBetaProbeRow,
        socket: DatagramSocket,
    ): ParsedBetaProbeRow {
        if (row.availability != ProbeAvailability.AVAILABLE) return row
        val nativeLocal = row.fields["local_address"]?.substringBefore('%')
        val nativeRemote = row.fields["remote_address"]?.substringBefore('%')
        val nativeLocalPort = row.fields["local_port"]?.toIntOrNull()
        val nativeRemotePort = row.fields["remote_port"]?.toIntOrNull()
        if (nativeLocal == null || nativeRemote == null || nativeLocalPort == null || nativeRemotePort == null) {
            return row
        }
        val normalizedNativeLocal = normalizeAddress(nativeLocal) ?: return row
        val normalizedNativeRemote = normalizeAddress(nativeRemote) ?: return row
        val normalizedJavaLocal = normalizeAddress(socket.localAddress.hostAddress) ?: return row
        val normalizedJavaRemote = normalizeAddress(socket.inetAddress.hostAddress) ?: return row
        val mismatch = normalizedNativeLocal != normalizedJavaLocal ||
            normalizedNativeRemote != normalizedJavaRemote ||
            nativeLocalPort != socket.localPort ||
            nativeRemotePort != socket.port
        return row.copy(fields = row.fields + ("critical_mismatch" to mismatch.toString()))
    }

    internal fun normalizeAddress(value: String?): List<Int>? = runCatching {
        val bytes = InetAddress.getByName(value?.substringBefore('%') ?: return null).address
        val normalized = if (bytes.size == 16 &&
            bytes.take(10).all { it == 0.toByte() } &&
            bytes[10] == 0xff.toByte() && bytes[11] == 0xff.toByte()
        ) {
            bytes.copyOfRange(12, 16)
        } else {
            bytes
        }
        normalized.map { it.toInt() and 0xff }
    }.getOrNull()

    internal fun diagObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row = row,
        source = EvidenceSource.BETA_SOCKET_DIAG,
        group = "socket_diag",
        summary = if (row.fields["matched"] == "true") "Exact socket cookie confirmed" else "Exact socket query completed",
        positive = row.fields["critical_mismatch"] == "true",
        authoritativeNegative = row.fields["matched"] == "true" && row.fields["cookie_match"] == "true",
        epochId = epochId,
        at = at,
    )

    internal fun netdObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row = row,
        source = EvidenceSource.BETA_NETD_NETID,
        group = "netd",
        summary = "netd network identity collected",
        positive = row.fields["path_mismatch_confirmed"] == "true",
        authoritativeNegative = row.fields.containsKey("socket_netid") && row.fields.containsKey("process_netid"),
        epochId = epochId,
        at = at,
    )

    internal fun routeObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row = row,
        source = EvidenceSource.BETA_ROUTE_LOOKUP,
        group = "kernel_route",
        summary = "Destination route collected",
        positive = row.fields["path_mismatch_confirmed"] == "true",
        authoritativeNegative = row.fields.containsKey("table") && row.fields.containsKey("oif"),
        epochId = epochId,
        at = at,
    )

    internal fun rulesObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row = row,
        source = EvidenceSource.BETA_POLICY_RULE,
        group = "kernel_route",
        summary = "Current UID policy rules collected",
        positive = row.fields["alternate_path_selected"] == "true",
        authoritativeNegative = row.fields.containsKey("matching_uid_rules"),
        epochId = epochId,
        at = at,
    )

    internal fun addressObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row = row,
        source = EvidenceSource.BETA_RTNL_ADDRESS,
        group = "kernel_link",
        summary = "Route interface addresses collected",
        positive = row.fields["framework_hidden_route_address"] == "true",
        authoritativeNegative = row.fields.containsKey("address_count"),
        epochId = epochId,
        at = at,
    )

    internal fun unixDiagObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row, EvidenceSource.BETA_UNIX_DIAG, "local_control_plane", DetectionDomain.VPN_OR_PROXY,
        "Matched local control sockets inspected", positive = false,
        authoritativeNegative = row.fields.containsKey("matched"), epochId = epochId, at = at,
    )

    internal fun originalDestinationObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row, EvidenceSource.BETA_BPF_NETFILTER, "packet_policy", DetectionDomain.NETWORK_PATH_DIVERGENCE,
        "Original destination compared with socket peer",
        positive = row.fields["matches_peer"] == "false" && row.fields["original_loopback"] == "true",
        authoritativeNegative = row.fields["matches_peer"] == "true", epochId = epochId, at = at,
        suppressions = if (row.fields["matches_peer"] == "false") {
            listOf(BetaSuppressionRuleId.NO_CAUSAL_COUNTER_DELTA)
        } else emptyList(),
    )

    internal fun pktInfoObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row, EvidenceSource.BETA_PKTINFO, "kernel_socket", DetectionDomain.NETWORK_PATH_DIVERGENCE,
        "Packet-info capability checked", positive = false,
        authoritativeNegative = row.fields["ancillary_observed"] == "true", epochId = epochId, at = at,
    )

    internal fun extendedRouteObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row, EvidenceSource.BETA_NETD_NETID, "kernel_routing", DetectionDomain.NETWORK_PATH_DIVERGENCE,
        "Selected route extended attributes collected", positive = false,
        authoritativeNegative = row.fields.containsKey("table") && row.fields.containsKey("oif"), epochId = epochId, at = at,
    )

    internal fun transitionObservation(row: ParsedBetaProbeRow, epochId: String, at: Long) = observation(
        row, EvidenceSource.BETA_NETWORK_TRANSITION, "network_timeline", DetectionDomain.NETWORK_PATH_DIVERGENCE,
        "Kernel network transitions monitored", positive = false,
        authoritativeNegative = row.fields.containsKey("joined_groups"), epochId = epochId, at = at,
    )

    private fun observation(
        row: ParsedBetaProbeRow,
        source: EvidenceSource,
        group: String,
        domain: DetectionDomain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
        summary: String,
        positive: Boolean,
        authoritativeNegative: Boolean,
        epochId: String,
        at: Long,
        suppressions: List<BetaSuppressionRuleId> = emptyList(),
    ) = BetaObservation(
        checkId = "beta.${row.checkId}",
        source = source,
        availability = row.availability,
        polarity = when {
            row.availability != ProbeAvailability.AVAILABLE -> ObservationPolarity.INCONCLUSIVE
            positive -> ObservationPolarity.POSITIVE
            authoritativeNegative -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
            else -> ObservationPolarity.INCONCLUSIVE
        },
        authority = ObservationAuthority.KERNEL_QUERY,
        confidence = if (positive) EvidenceConfidence.HIGH else EvidenceConfidence.LOW,
        independenceGroup = group,
        detectionDomain = domain,
        facts = mapOf("summary" to summary),
        suppressions = suppressions,
        observedAtElapsedMs = at,
        networkEpochId = epochId,
    )

    private fun unavailable(epochId: String, at: Long) = placeholder(ProbeAvailability.UNAVAILABLE, epochId, at)
    private fun unsupported(epochId: String, at: Long) = placeholder(ProbeAvailability.UNSUPPORTED, epochId, at)

    private fun placeholder(availability: ProbeAvailability, epochId: String, at: Long) = listOf(
        socketObservation(ParsedBetaProbeRow("socket_identity", availability, emptyMap()), epochId, at),
        diagObservation(ParsedBetaProbeRow("inet_diag_cookie", availability, emptyMap()), epochId, at),
        netdObservation(ParsedBetaProbeRow("netd_netid", availability, emptyMap()), epochId, at),
        routeObservation(ParsedBetaProbeRow("route_lookup", availability, emptyMap()), epochId, at),
        rulesObservation(ParsedBetaProbeRow("policy_rules", availability, emptyMap()), epochId, at),
        addressObservation(ParsedBetaProbeRow("rtnl_address", availability, emptyMap()), epochId, at),
    )
}
