package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.model.NetworkEpoch
import com.notcvnt.rknhardering.probe.BetaCanaryAddressFamily
import com.notcvnt.rknhardering.probe.BetaCanaryClient
import com.notcvnt.rknhardering.probe.BetaCanaryConfigProvider
import com.notcvnt.rknhardering.probe.BetaCanaryObservation
import com.notcvnt.rknhardering.probe.BetaCanaryRunResult
import com.notcvnt.rknhardering.probe.BetaCanaryStatus
import com.notcvnt.rknhardering.probe.BetaCanaryTransport

internal object BetaCanaryChecker {
    internal data class Evaluation(
        val result: BetaCanaryRunResult,
        val observations: List<BetaObservation>,
    )

    fun check(
        context: Context,
        epoch: NetworkEpoch,
        observedAtElapsedMs: Long,
        executionContext: ScanExecutionContext,
        networkRequestsEnabled: Boolean,
    ): Evaluation {
        val result = BetaCanaryClient.run(
            context,
            BetaCanaryConfigProvider.configuredEndpoint(),
            executionContext,
            networkRequestsEnabled = networkRequestsEnabled,
        )
        return Evaluation(result, observations(context, result, epoch, observedAtElapsedMs))
    }

    internal fun observations(
        context: Context,
        result: BetaCanaryRunResult,
        epoch: NetworkEpoch,
        at: Long,
    ): List<BetaObservation> = listOf(
        dnsObservation(context, result, epoch, at),
        transportObservation(context, result, epoch, at),
        tlsObservation(context, result, epoch, at),
        serverObservation(context, result, epoch.id, at),
    )

    private fun dnsObservation(context: Context, result: BetaCanaryRunResult, epoch: NetworkEpoch, at: Long): BetaObservation {
        val available = result.observations.filter { it.status == BetaCanaryStatus.AVAILABLE }
        val divergent = BetaCanaryAddressFamily.entries.any { family ->
            val dns = available.firstOrNull { it.family == family && it.transport == BetaCanaryTransport.DNS }
            val http = available.firstOrNull { it.family == family && it.transport == BetaCanaryTransport.HTTP }
            dns?.observedAddressHash != null && http?.observedAddressHash != null &&
                dns.observedAddressHash != http.observedAddressHash
        }
        val comparable = BetaCanaryAddressFamily.entries.any { family ->
            available.any { it.family == family && it.transport == BetaCanaryTransport.DNS } &&
                available.any { it.family == family && it.transport == BetaCanaryTransport.HTTP }
        }
        return observation(
            "beta.dns_netid", EvidenceSource.BETA_DNS_NETID, "dns_path",
            DetectionDomain.NETWORK_PATH_DIVERGENCE, result.toAvailability(),
            divergent, comparable && !divergent, if (divergent) EvidenceConfidence.HIGH else EvidenceConfidence.LOW,
            context.getString(if (divergent) R.string.beta_canary_dns_divergent else R.string.beta_canary_dns_checked), epoch.id, at,
            suppressions = if (divergent) epoch.canarySuppressions() else emptyList(),
        )
    }

    private fun transportObservation(context: Context, result: BetaCanaryRunResult, epoch: NetworkEpoch, at: Long): BetaObservation {
        val available = result.observations.filter {
            it.status == BetaCanaryStatus.AVAILABLE &&
                it.transport in setOf(BetaCanaryTransport.HTTP, BetaCanaryTransport.TCP, BetaCanaryTransport.UDP)
        }
        val divergent = available.groupBy { it.family }.values.any { family ->
            family.mapNotNull(BetaCanaryObservation::observedAddressHash).distinct().size > 1
        }
        val comparable = available.groupBy { it.family }.values.any { it.size >= 2 }
        return observation(
            "beta.transport_matrix", EvidenceSource.BETA_TRANSPORT_MATRIX, "active_egress",
            DetectionDomain.NETWORK_PATH_DIVERGENCE, result.toAvailability(), divergent, comparable && !divergent,
            if (divergent) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
            context.getString(if (divergent) R.string.beta_canary_transport_divergent else R.string.beta_canary_transport_checked), epoch.id, at,
            suppressions = if (divergent) epoch.canarySuppressions() else emptyList(),
        )
    }

    private fun tlsObservation(context: Context, result: BetaCanaryRunResult, epoch: NetworkEpoch, at: Long): BetaObservation {
        val tls = result.observations.filter { it.transport == BetaCanaryTransport.HTTPS }
        val pinMismatch = tls.any { it.failureKind == "SPKI_PIN_MISMATCH" }
        val available = tls.any { it.status == BetaCanaryStatus.AVAILABLE }
        return observation(
            "beta.tls_interception", EvidenceSource.BETA_TLS_INTERCEPTION, "tls_path",
            DetectionDomain.VPN_OR_PROXY,
            if (tls.isEmpty()) ProbeAvailability.UNSUPPORTED else if (pinMismatch) ProbeAvailability.AVAILABLE else result.toAvailability(),
            pinMismatch, available && !pinMismatch,
            if (pinMismatch) EvidenceConfidence.HIGH else EvidenceConfidence.LOW,
            context.getString(if (pinMismatch) R.string.beta_canary_tls_mismatch else R.string.beta_canary_tls_checked), epoch.id, at,
            suppressions = if (pinMismatch) buildList {
                add(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS)
                if (epoch.captivePortal == true) add(BetaSuppressionRuleId.CAPTIVE_PORTAL_ACTIVE)
                if (epoch.httpProxy != null) add(BetaSuppressionRuleId.ENTERPRISE_PROXY_CONTEXT)
                if (epoch.validated == false) add(BetaSuppressionRuleId.NETWORK_NOT_VALIDATED)
            } else emptyList(),
        )
    }

    private fun serverObservation(context: Context, result: BetaCanaryRunResult, epochId: String, at: Long): BetaObservation {
        val available = result.observations.any {
            it.status == BetaCanaryStatus.AVAILABLE && it.serverFingerprintHash != null
        }
        return observation(
            "beta.server_fingerprint", EvidenceSource.BETA_SERVER_FINGERPRINT, "server_observation",
            DetectionDomain.SYSTEM_NETWORK_CONTEXT, result.toAvailability(), positive = false,
            clean = available, confidence = EvidenceConfidence.LOW,
            context.getString(R.string.beta_canary_server_checked), epochId, at,
        )
    }

    private fun observation(
        checkId: String,
        source: EvidenceSource,
        group: String,
        domain: DetectionDomain,
        availability: ProbeAvailability,
        positive: Boolean,
        clean: Boolean,
        confidence: EvidenceConfidence,
        summary: String,
        epochId: String,
        at: Long,
        suppressions: List<BetaSuppressionRuleId> = emptyList(),
    ) = BetaObservation(
        checkId = checkId,
        source = source,
        availability = availability,
        polarity = when {
            availability != ProbeAvailability.AVAILABLE -> ObservationPolarity.INCONCLUSIVE
            positive -> ObservationPolarity.POSITIVE
            clean -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
            else -> ObservationPolarity.INCONCLUSIVE
        },
        authority = ObservationAuthority.ACTIVE_CANARY,
        confidence = confidence,
        independenceGroup = group,
        detectionDomain = domain,
        facts = mapOf("summary" to summary),
        suppressions = suppressions,
        observedAtElapsedMs = at,
        networkEpochId = epochId,
    )

    private fun BetaCanaryRunResult.toAvailability(): ProbeAvailability = when (status) {
        BetaCanaryStatus.AVAILABLE -> ProbeAvailability.AVAILABLE
        BetaCanaryStatus.UNAVAILABLE -> ProbeAvailability.UNAVAILABLE
        BetaCanaryStatus.DISABLED -> ProbeAvailability.SKIPPED
        BetaCanaryStatus.UNSUPPORTED -> ProbeAvailability.UNSUPPORTED
        BetaCanaryStatus.FAILED -> ProbeAvailability.ERROR
    }

    private fun NetworkEpoch.canarySuppressions(): List<BetaSuppressionRuleId> = buildList {
        add(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS)
        if (validated == false) add(BetaSuppressionRuleId.NETWORK_NOT_VALIDATED)
        if (captivePortal == true) add(BetaSuppressionRuleId.CAPTIVE_PORTAL_ACTIVE)
        if (privateDnsActive == true) add(BetaSuppressionRuleId.PRIVATE_DNS_EXPECTED)
        if (nat64Prefix != null) add(BetaSuppressionRuleId.NAT64_OR_CLAT_CONTEXT)
    }
}
