package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.NetworkCapabilities
import android.os.Process
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ExecutionContextFacts
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.ConnectivityBinderProbe
import com.notcvnt.rknhardering.probe.ConnectivityBinderSnapshot
import com.notcvnt.rknhardering.probe.HiddenCallResult
import com.notcvnt.rknhardering.probe.LegacyVpnFacts
import com.notcvnt.rknhardering.probe.VpnConfigFacts
import com.notcvnt.rknhardering.probe.VpnManagerBinderProbe
import com.notcvnt.rknhardering.probe.VpnManagerBinderSnapshot

internal object HiddenAndroidBetaChecker {
    private const val LEGACY_VPN_STATE_CONNECTED = 3

    fun check(
        context: Context,
        executionFacts: ExecutionContextFacts?,
        epochId: String,
        observedAtElapsedMs: Long,
    ): List<BetaObservation> {
        val userId = Process.myUid() / 100_000
        return listOf(
            vpnObservation(context, VpnManagerBinderProbe.inspect(userId), epochId, observedAtElapsedMs),
            connectivityObservation(
                context,
                ConnectivityBinderProbe.effectiveNetworkForUid(context),
                epochId,
                observedAtElapsedMs,
            ),
            foregroundObservation(context, executionFacts, epochId, observedAtElapsedMs),
        )
    }

    fun checkVpnOnly(context: Context, epochId: String, at: Long): BetaObservation {
        val userId = Process.myUid() / 100_000
        return vpnObservation(context, VpnManagerBinderProbe.inspect(userId), epochId, at)
    }

    internal fun vpnObservation(
        context: Context,
        result: HiddenCallResult<VpnManagerBinderSnapshot>,
        epochId: String,
        at: Long,
    ): BetaObservation {
        val snapshot = (result as? HiddenCallResult.Success)?.value
        val config = (snapshot?.config as? HiddenCallResult.Success<VpnConfigFacts>)?.value
        val legacy = (snapshot?.legacyInfo as? HiddenCallResult.Success<LegacyVpnFacts>)?.value
        val activeConfig = config?.present == true && !config.interfaceName.isNullOrBlank()
        val activeLegacy = legacy?.present == true && legacy.state == LEGACY_VPN_STATE_CONNECTED
        val available = snapshot != null && (config != null || legacy != null)
        val clean = config?.present == false && legacy?.present == false
        return observation(
            checkId = "beta.vpn_binder",
            source = EvidenceSource.BETA_VPN_BINDER,
            group = "android_vpn_service",
            domain = DetectionDomain.VPN_OR_PROXY,
            availability = if (available) ProbeAvailability.AVAILABLE else result.toAvailability(snapshot?.config, snapshot?.legacyInfo),
            polarity = when {
                activeConfig || activeLegacy -> ObservationPolarity.POSITIVE
                clean -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
                else -> ObservationPolarity.INCONCLUSIVE
            },
            confidence = if (activeConfig || activeLegacy) EvidenceConfidence.HIGH else EvidenceConfidence.LOW,
            summary = when {
                activeConfig || activeLegacy -> context.getString(R.string.beta_vpn_binder_active)
                clean -> context.getString(R.string.beta_vpn_binder_clean)
                else -> context.getString(R.string.beta_vpn_binder_unavailable)
            },
            epochId = epochId,
            at = at,
        )
    }

    internal fun connectivityObservation(
        context: Context,
        result: HiddenCallResult<ConnectivityBinderSnapshot>,
        epochId: String,
        at: Long,
        vpnTransportOverride: Boolean? = null,
    ): BetaObservation {
        val snapshot = (result as? HiddenCallResult.Success)?.value
        val vpn = vpnTransportOverride
            ?: (snapshot?.capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        val divergent = snapshot?.differsFromPublicActiveNetwork == true
        val comparable = snapshot != null &&
            (snapshot.effectiveNetworkHandle != null || snapshot.publicActiveNetworkHandle != null)
        return observation(
            checkId = "beta.connectivity_binder",
            source = EvidenceSource.BETA_CONNECTIVITY_BINDER,
            group = "android_connectivity",
            domain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
            availability = if (snapshot != null) ProbeAvailability.AVAILABLE else result.toAvailability(),
            polarity = when {
                divergent && vpn -> ObservationPolarity.POSITIVE
                comparable && !divergent -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
                else -> ObservationPolarity.INCONCLUSIVE
            },
            confidence = if (divergent && vpn) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
            summary = when {
                divergent && vpn -> context.getString(R.string.beta_connectivity_binder_divergent)
                comparable && !divergent -> context.getString(R.string.beta_connectivity_binder_consistent)
                else -> context.getString(R.string.beta_connectivity_binder_unavailable)
            },
            epochId = epochId,
            at = at,
            suppressions = if (divergent && vpn) {
                listOf(BetaSuppressionRuleId.NO_CAUSAL_COUNTER_DELTA)
            } else emptyList(),
        )
    }

    internal fun foregroundObservation(
        context: Context,
        facts: ExecutionContextFacts?,
        epochId: String,
        at: Long,
    ): BetaObservation {
        val current = facts?.uidDerivedUserId
        val foreground = facts?.foregroundUserId
        val comparable = current != null && foreground != null
        val mismatch = comparable && current != foreground
        return observation(
            checkId = "beta.foreground_user",
            source = EvidenceSource.BETA_USER_PROFILE,
            group = "android_user_manager",
            domain = DetectionDomain.ISOLATED_PROFILE,
            availability = if (comparable) ProbeAvailability.AVAILABLE else ProbeAvailability.UNAVAILABLE,
            polarity = when {
                mismatch -> ObservationPolarity.POSITIVE
                comparable -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
                else -> ObservationPolarity.INCONCLUSIVE
            },
            confidence = if (mismatch) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
            summary = if (mismatch) {
                context.getString(R.string.beta_foreground_user_mismatch)
            } else {
                context.getString(R.string.beta_foreground_user_checked)
            },
            epochId = epochId,
            at = at,
        )
    }

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
        authority = ObservationAuthority.BINDER_SERVICE,
        confidence = confidence,
        independenceGroup = group,
        detectionDomain = domain,
        facts = mapOf("summary" to summary),
        suppressions = suppressions,
        observedAtElapsedMs = at,
        networkEpochId = epochId,
    )

    private fun HiddenCallResult<*>.toAvailability(vararg nested: HiddenCallResult<*>?): ProbeAvailability {
        val outcomes = listOf(this) + nested.filterNotNull()
        return when {
            outcomes.any { it is HiddenCallResult.PermissionDenied } -> ProbeAvailability.PERMISSION_DENIED
            outcomes.any { it is HiddenCallResult.Failure } -> ProbeAvailability.ERROR
            outcomes.any { it is HiddenCallResult.Unsupported } -> ProbeAvailability.UNSUPPORTED
            outcomes.any { it is HiddenCallResult.Skipped } -> ProbeAvailability.SKIPPED
            else -> ProbeAvailability.UNAVAILABLE
        }
    }
}
