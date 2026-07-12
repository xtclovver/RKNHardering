package com.notcvnt.rknhardering.probe.privileged

import android.os.Process
import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.BetaProbeRowParser
import com.notcvnt.rknhardering.probe.NativeSignsBridge

internal const val PRIVILEGED_PROBE_PROTOCOL_VERSION = 2
internal const val PRIVILEGED_NONCE_SIZE = 32
internal const val PRIVILEGED_MAX_ROWS = 8
internal const val PRIVILEGED_MAX_ROW_CHARS = 2_048

internal interface PrivilegedProbeEngine {
    fun wireGuard(cancellationSignal: ScanCancellationSignal): Array<String>
    fun ovpn(cancellationSignal: ScanCancellationSignal): Array<String>
    fun xfrm(imsContext: Boolean, cancellationSignal: ScanCancellationSignal): Array<String>
    fun bpfNetfilter(cancellationSignal: ScanCancellationSignal): Array<String>
}

internal object NativePrivilegedProbeEngine : PrivilegedProbeEngine {
    override fun wireGuard(cancellationSignal: ScanCancellationSignal): Array<String> = nativeRows("wireguard_genl") {
        NativeSignsBridge.betaWireGuardProbe(cancellationSignal)
    }

    override fun ovpn(cancellationSignal: ScanCancellationSignal): Array<String> = nativeRows("ovpn_genl") {
        NativeSignsBridge.betaOvpnProbe(cancellationSignal)
    }

    override fun xfrm(imsContext: Boolean, cancellationSignal: ScanCancellationSignal): Array<String> = nativeRows("xfrm") {
        NativeSignsBridge.betaXfrmProbe(imsContext, cancellationSignal)
    }

    override fun bpfNetfilter(cancellationSignal: ScanCancellationSignal): Array<String> {
        NativeSignsBridge.initIfNeeded()
        if (!NativeSignsBridge.isLibraryLoaded()) {
            return arrayOf(
                unavailable("cgroup_bpf"),
                unavailable("bpf_netd"),
                unavailable("netfilter_path"),
            )
        }
        return PrivilegedProbeRows.sanitize(
            NativeSignsBridge.betaBpfNetfilterProbe(aggressive = true, cancellationSignal),
            listOf("cgroup_bpf", "bpf_netd", "netfilter_path"),
        )
    }

    private inline fun nativeRows(checkId: String, block: () -> Array<String>): Array<String> {
        NativeSignsBridge.initIfNeeded()
        if (!NativeSignsBridge.isLibraryLoaded()) return arrayOf(unavailable(checkId))
        return PrivilegedProbeRows.sanitize(block(), listOf(checkId))
    }

    private fun unavailable(checkId: String) = "beta_v1|check=$checkId|status=unavailable"
}

internal object PrivilegedProbeRows {
    private val allowedFields = mapOf(
        "wireguard_genl" to setOf(
            "devices", "peers", "peers_with_handshake_or_counters", "rx_bytes", "tx_bytes",
            "interface_indexes",
        ),
        "ovpn_genl" to setOf("family", "interfaces", "peers", "rx_bytes", "tx_bytes", "interface_indexes"),
        "xfrm" to setOf(
            "states", "tunnel_states", "states_with_traffic", "nat_t_states", "classification",
        ),
        "cgroup_bpf" to setOf("attach_types", "programs"),
        "bpf_netd" to setOf("opened", "denied", "missing"),
        "netfilter_path" to setOf("table_messages", "scope"),
    )

    fun sanitize(rows: Array<String>, expectedCheckIds: List<String>): Array<String> =
        expectedCheckIds.take(PRIVILEGED_MAX_ROWS).map { checkId ->
            val parsed = BetaProbeRowParser.parse(rows, checkId)
            buildString {
                append("beta_v1|check=").append(checkId)
                append("|status=").append(parsed.availability.toWireStatus())
                if (parsed.availability == ProbeAvailability.AVAILABLE) {
                    allowedFields[checkId].orEmpty().sorted().forEach { key ->
                        parsed.fields[key]
                            ?.takeIf(::safeValue)
                            ?.let { append('|').append(key).append('=').append(it) }
                    }
                }
            }.take(PRIVILEGED_MAX_ROW_CHARS)
        }.toTypedArray()

    fun validate(rows: Array<String>, expectedCheckIds: Set<String>): Boolean {
        if (rows.isEmpty() || rows.size > PRIVILEGED_MAX_ROWS) return false
        if (rows.any { it.length > PRIVILEGED_MAX_ROW_CHARS }) return false
        val parsedIds = rows.mapNotNull { row ->
            row.split('|').firstOrNull { it.startsWith("check=") }?.removePrefix("check=")
        }
        return parsedIds.size == rows.size && parsedIds.toSet() == expectedCheckIds &&
            parsedIds.size == parsedIds.toSet().size && rows.all { row ->
                val checkId = row.split('|').first { it.startsWith("check=") }.removePrefix("check=")
                BetaProbeRowParser.parse(arrayOf(row), checkId).availability != ProbeAvailability.MALFORMED_RESPONSE
            }
    }

    private fun safeValue(value: String): Boolean = value.isNotEmpty() && value.length <= 96 &&
        value.all { it.isLetterOrDigit() || it in setOf('_', '-', '.', ',') }

    private fun ProbeAvailability.toWireStatus(): String = when (this) {
        ProbeAvailability.AVAILABLE -> "available"
        ProbeAvailability.PERMISSION_DENIED -> "permission_denied"
        ProbeAvailability.UNSUPPORTED -> "unsupported"
        ProbeAvailability.UNAVAILABLE -> "unavailable"
        ProbeAvailability.TRUNCATED -> "truncated"
        ProbeAvailability.MALFORMED_RESPONSE -> "malformed_response"
        ProbeAvailability.RACE -> "race"
        ProbeAvailability.SKIPPED -> "skipped"
        ProbeAvailability.ERROR -> "error"
    }
}

internal fun currentPrivilegedProviderUid(): Int = Process.myUid()
