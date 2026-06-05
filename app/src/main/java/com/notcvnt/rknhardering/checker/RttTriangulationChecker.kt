package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.customcheck.RttTriangulationConfig
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.GeoIpFacts
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import com.notcvnt.rknhardering.probe.SystemPingProber
import com.notcvnt.rknhardering.util.HomeCountryResolver
import java.io.IOException
import java.net.Inet4Address
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

internal object RttTriangulationChecker {

    private const val PING_COUNT = 4
    private const val THRESHOLD_HOME_MS = 80.0
    private const val JITTER_LIMIT_MS = 60.0
    private const val MIN_REACHABLE_TARGETS_PER_GROUP = 2
    private const val CATEGORY_NAME = "RTT triangulation"

    private val RU_TARGETS = listOf(
        "yandex.ru",
        "mail.ru",
        "vk.com",
        "sberbank.ru",
        "gosuslugi.ru",
    )

    private val FOREIGN_TARGETS = listOf(
        "facebook.com",
        "github.com",
        "twitter.com",
        "reddit.com",
        "instagram.com",
    )

    internal enum class TargetGroup { RU, FOREIGN }

    internal data class TargetSpec(val host: String, val group: TargetGroup)

    internal data class TargetOutcome(
        val spec: TargetSpec,
        val ip: String,
        val medianRtt: Double?,
        val jitter: Double?,
        val sent: Int,
        val received: Int,
    )

    internal data class Dependencies(
        val resolveIpv4: (String, DnsResolverConfig) -> String = { host, resolverConfig ->
            val addresses = ResolverNetworkStack.lookup(
                hostname = host,
                config = resolverConfig,
                cancellationSignal = ScanExecutionContext.currentOrDefault().cancellationSignal,
            )
            val ipv4 = addresses.firstOrNull { it is Inet4Address }
                ?: throw IOException("No IPv4 address resolved for $host")
            ipv4.hostAddress ?: throw IOException("Resolved IPv4 address is empty for $host")
        },
        val ping: suspend (String, Int, Int) -> SystemPingProber.PingResult = { address, count, replyTimeoutSeconds ->
            SystemPingProber.probe(address = address, count = count, replyTimeoutSeconds = replyTimeoutSeconds)
        },
    )

    @Volatile
    internal var dependenciesOverride: Dependencies? = null

    suspend fun check(
        context: Context,
        resolverConfig: DnsResolverConfig,
        geoFacts: GeoIpFacts?,
        config: RttTriangulationConfig = RttTriangulationConfig(enabled = false),
    ): CategoryResult = withContext(Dispatchers.IO) {
        if (!config.enabled) {
            return@withContext CategoryResult(
                name = CATEGORY_NAME,
                detected = false,
                findings = emptyList(),
            )
        }

        val resolved = HomeCountryResolver.resolve(context, geoFacts)

        if (resolved.country == null) {
            return@withContext CategoryResult(
                name = CATEGORY_NAME,
                detected = false,
                needsReview = true,
                findings = listOf(
                    Finding(
                        description = context.getString(R.string.checker_rtt_summary_inconclusive),
                        needsReview = true,
                        source = EvidenceSource.RTT_TRIANGULATION,
                        confidence = EvidenceConfidence.LOW,
                    ),
                ),
            )
        }

        if (resolved.country != "RU") {
            return@withContext CategoryResult(
                name = CATEGORY_NAME,
                detected = false,
                needsReview = true,
                findings = listOf(
                    Finding(
                        description = context.getString(R.string.checker_rtt_summary_unsupported_country),
                        needsReview = true,
                        source = EvidenceSource.RTT_TRIANGULATION,
                        confidence = EvidenceConfidence.LOW,
                    ),
                ),
            )
        }

        val deps = dependenciesOverride ?: Dependencies()
        val pingCount = if (config.pingCount > 0) config.pingCount else PING_COUNT
        val replyTimeoutSeconds = maxOf(1, config.timeoutMs / 1_000)

        val builtinRu = if (config.builtinTargetsEnabled) RU_TARGETS.map { TargetSpec(it, TargetGroup.RU) } else emptyList()
        val builtinForeign = if (config.builtinTargetsEnabled) FOREIGN_TARGETS.map { TargetSpec(it, TargetGroup.FOREIGN) } else emptyList()
        val customSpecs = config.customTargets
            .filter { it.host.isNotBlank() }
            .map { target ->
                val group = if (target.expectedLocation.equals("RU", ignoreCase = true)) TargetGroup.RU else TargetGroup.FOREIGN
                TargetSpec(target.host, group)
            }
        val allSpecs = builtinRu + builtinForeign + customSpecs

        val outcomes: List<TargetOutcome> = coroutineScope {
            allSpecs.map { spec ->
                async {
                    val (ip, pingResult) = try {
                        val address = deps.resolveIpv4(spec.host, resolverConfig)
                        val result = deps.ping(address, pingCount, replyTimeoutSeconds)
                        address to result
                    } catch (_: Throwable) {
                        return@async TargetOutcome(
                            spec = spec,
                            ip = "unresolved",
                            medianRtt = null,
                            jitter = null,
                            sent = 0,
                            received = 0,
                        )
                    }
                    val medianRtt = if (pingResult.received > 0) pingResult.avgRttMs else null
                    val jitter = if (pingResult.received >= 2 &&
                        pingResult.maxRttMs != null &&
                        pingResult.minRttMs != null
                    ) {
                        pingResult.maxRttMs - pingResult.minRttMs
                    } else {
                        null
                    }
                    TargetOutcome(
                        spec = spec,
                        ip = ip,
                        medianRtt = medianRtt,
                        jitter = jitter,
                        sent = pingResult.sent,
                        received = pingResult.received,
                    )
                }
            }.awaitAll()
        }

        val ruOutcomes = outcomes.filter { it.spec.group == TargetGroup.RU }
        val foreignOutcomes = outcomes.filter { it.spec.group == TargetGroup.FOREIGN }

        val homeMedian = median(ruOutcomes.mapNotNull { it.medianRtt })
        val foreignMedian = median(foreignOutcomes.mapNotNull { it.medianRtt })
        val homeReachableCount = ruOutcomes.count { it.medianRtt != null }
        val foreignReachableCount = foreignOutcomes.count { it.medianRtt != null }
        val insufficientSamples = homeReachableCount < MIN_REACHABLE_TARGETS_PER_GROUP ||
            foreignReachableCount < MIN_REACHABLE_TARGETS_PER_GROUP

        val allReachable = outcomes.filter { it.medianRtt != null }
        val highJitterCount = allReachable.count { it.jitter != null && it.jitter > JITTER_LIMIT_MS }
        val highJitterMajority = allReachable.isNotEmpty() &&
            highJitterCount.toDouble() / allReachable.size > 0.5

        val (detected, baseConfidence, needsReview, descriptionKey, isError) = when {
            insufficientSamples -> RttDecision(
                detected = false,
                confidence = EvidenceConfidence.LOW,
                needsReview = true,
                descriptionKey = R.string.checker_rtt_summary_unavailable,
                isError = true,
            )
            homeMedian != null &&
                homeMedian > THRESHOLD_HOME_MS &&
                foreignMedian != null &&
                homeMedian > foreignMedian -> RttDecision(
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                needsReview = true,
                descriptionKey = R.string.checker_rtt_summary_detected,
                isError = false,
            )
            homeMedian != null &&
                homeMedian > THRESHOLD_HOME_MS &&
                foreignMedian != null &&
                homeMedian <= foreignMedian -> RttDecision(
                detected = false,
                confidence = EvidenceConfidence.LOW,
                needsReview = true,
                descriptionKey = R.string.checker_rtt_summary_needs_review,
                isError = false,
            )
            else -> RttDecision(
                detected = false,
                confidence = EvidenceConfidence.MEDIUM,
                needsReview = false,
                descriptionKey = R.string.checker_rtt_summary_clean,
                isError = false,
            )
        }

        val finalConfidence = if (highJitterMajority) downgrade(baseConfidence) else baseConfidence

        val mainFinding = Finding(
            description = context.getString(descriptionKey),
            detected = detected,
            needsReview = needsReview,
            isError = isError,
            source = EvidenceSource.RTT_TRIANGULATION,
            confidence = finalConfidence,
        )

        val homeLabel = context.getString(R.string.checker_rtt_target_home)
        val foreignLabel = context.getString(R.string.checker_rtt_target_foreign)
        val unavailable = context.getString(R.string.checker_rtt_value_unavailable)

        val mediansFinding = Finding(
            description = context.getString(
                R.string.checker_rtt_finding_medians,
                homeMedian?.let { String.format(Locale.US, "%.0f", it) } ?: unavailable,
                foreignMedian?.let { String.format(Locale.US, "%.0f", it) } ?: unavailable,
                THRESHOLD_HOME_MS,
            ),
            isInformational = true,
        )

        val perTargetFindings = outcomes.map { outcome ->
            val groupLabel = when (outcome.spec.group) {
                TargetGroup.RU -> homeLabel
                TargetGroup.FOREIGN -> foreignLabel
            }
            val description = if (outcome.medianRtt != null) {
                context.getString(
                    R.string.checker_rtt_finding_target,
                    groupLabel,
                    outcome.spec.host,
                    outcome.ip,
                    outcome.received,
                    outcome.sent,
                    outcome.medianRtt,
                    outcome.jitter ?: 0.0,
                )
            } else {
                context.getString(
                    R.string.checker_rtt_finding_target_unreachable,
                    groupLabel,
                    outcome.spec.host,
                    outcome.ip,
                )
            }
            Finding(description = description, isInformational = true)
        }

        val noteFindings = mutableListOf<Finding>()
        if (detected) {
            noteFindings += Finding(
                description = context.getString(R.string.checker_rtt_finding_threshold_note),
                isInformational = true,
            )
        }
        if (highJitterMajority) {
            noteFindings += Finding(
                description = context.getString(R.string.checker_rtt_finding_jitter_note),
                isInformational = true,
            )
        }

        val allFindings = listOf(mainFinding, mediansFinding) + noteFindings + perTargetFindings

        val evidence = outcomes.map { outcome ->
            val groupLabel = when (outcome.spec.group) {
                TargetGroup.RU -> context.getString(R.string.checker_rtt_target_home)
                TargetGroup.FOREIGN -> context.getString(R.string.checker_rtt_target_foreign)
            }
            val description = if (outcome.medianRtt != null) {
                context.getString(
                    R.string.checker_rtt_evidence_template,
                    "[$groupLabel] ${outcome.spec.host}",
                    outcome.medianRtt,
                    outcome.jitter ?: 0.0,
                )
            } else {
                context.getString(
                    R.string.checker_rtt_evidence_unreachable,
                    "[$groupLabel] ${outcome.spec.host}",
                )
            }
            val evidenceDetected = detected &&
                outcome.spec.group == TargetGroup.RU &&
                outcome.medianRtt != null &&
                outcome.medianRtt > THRESHOLD_HOME_MS
            EvidenceItem(
                source = EvidenceSource.RTT_TRIANGULATION,
                detected = evidenceDetected,
                confidence = EvidenceConfidence.MEDIUM,
                description = description,
            )
        }

        CategoryResult(
            name = CATEGORY_NAME,
            detected = detected,
            needsReview = needsReview,
            findings = allFindings,
            evidence = evidence,
        )
    }

    private fun median(values: List<Double>): Double? {
        if (values.isEmpty()) return null
        val sorted = values.sorted()
        val mid = sorted.size / 2
        return if (sorted.size % 2 == 0) (sorted[mid - 1] + sorted[mid]) / 2.0 else sorted[mid]
    }

    private fun downgrade(confidence: EvidenceConfidence): EvidenceConfidence = when (confidence) {
        EvidenceConfidence.HIGH -> EvidenceConfidence.MEDIUM
        EvidenceConfidence.MEDIUM -> EvidenceConfidence.LOW
        EvidenceConfidence.LOW -> EvidenceConfidence.LOW
    }

    private data class RttDecision(
        val detected: Boolean,
        val confidence: EvidenceConfidence,
        val needsReview: Boolean,
        val descriptionKey: Int,
        val isError: Boolean,
    )
}
