package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.customcheck.IcmpSpoofingConfig
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import com.notcvnt.rknhardering.probe.SystemPingProber
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.util.Locale
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object IcmpSpoofingChecker {
    private const val RTT_THRESHOLD_MS = 10.0

    internal data class Target(
        val host: String,
        val role: Role,
    )

    internal enum class Role {
        BLOCKED,
        CONTROL,
    }

    internal data class TargetOutcome(
        val target: Target,
        val address: String,
        val ping: SystemPingProber.PingResult,
    )

    internal data class Dependencies(
        val resolveIpv4: (String, DnsResolverConfig) -> String = { host, resolverConfig ->
            val addresses = ResolverNetworkStack.lookup(
                hostname = host,
                config = resolverConfig,
                cancellationSignal = ScanExecutionContext.currentOrDefault().cancellationSignal,
            )
            val ipv4 = addresses.filterIsInstance<Inet4Address>().firstOrNull(::isUsablePublicIpv4)
                ?: throw IOException("No usable public IPv4 address resolved for $host")
            ipv4.hostAddress ?: throw IOException("Resolved IPv4 address is empty for $host")
        },
        val ping: suspend (String, Int, Int) -> SystemPingProber.PingResult = { address, count, timeoutSeconds ->
            SystemPingProber.probe(address = address, count = count, replyTimeoutSeconds = timeoutSeconds)
        },
    )

    @Volatile
    internal var dependenciesOverride: Dependencies? = null

    private val defaultTargets = listOf(
        Target(host = "instagram.com", role = Role.BLOCKED),
        Target(host = "google.com", role = Role.CONTROL),
    )

    suspend fun check(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        config: IcmpSpoofingConfig = IcmpSpoofingConfig(enabled = true),
    ): CategoryResult = withContext(Dispatchers.IO) {
        val dependencies = dependenciesOverride ?: Dependencies()
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val effectiveTargets = buildList {
            if (config.builtinTargetsEnabled) addAll(defaultTargets)
            config.customTargets
                .filter { it.host.isNotBlank() }
                .forEach { ct ->
                    add(Target(host = ct.host.trim(), role = if (ct.isControl) Role.CONTROL else Role.BLOCKED))
                }
        }
        if (effectiveTargets.none { it.role == Role.BLOCKED } || effectiveTargets.none { it.role == Role.CONTROL }) {
            // No usable target pair (need at least one blocked + one control) — return inconclusive.
            return@withContext unsupportedResult(context, IOException("No usable ICMP target pair configured"))
        }

        val pingCount = config.pingCount.coerceAtLeast(1)
        val timeoutSeconds = (config.timeoutMs / 1000).coerceAtLeast(1)

        val outcomes = try {
            coroutineScope {
                effectiveTargets.map { target ->
                    async {
                        val address = dependencies.resolveIpv4(target.host, resolverConfig)
                        val parsedAddress = if (DnsResolverConfig.isValidIpLiteral(address)) {
                            runCatching { InetAddress.getByName(address) }.getOrNull() as? Inet4Address
                        } else {
                            null
                        }
                        if (parsedAddress == null || !isUsablePublicIpv4(parsedAddress)) {
                            throw IOException("No usable public IPv4 address resolved for ${target.host}")
                        }
                        val pingResult = dependencies.ping(address, pingCount, timeoutSeconds)
                        TargetOutcome(target = target, address = address, ping = pingResult)
                    }
                }.awaitAll()
            }
        } catch (error: Throwable) {
            return@withContext unsupportedResult(context, error)
        }

        val blockedOutcome = outcomes.first { it.target.role == Role.BLOCKED }
        val controlOutcome = outcomes.first { it.target.role == Role.CONTROL }

        val blockedUnexpectedReply = blockedOutcome.ping.hasReplies
        val controlRttTooLow =
            controlOutcome.ping.hasReplies &&
                (
                    (controlOutcome.ping.minRttMs != null && controlOutcome.ping.minRttMs < RTT_THRESHOLD_MS) ||
                        (controlOutcome.ping.avgRttMs != null && controlOutcome.ping.avgRttMs < RTT_THRESHOLD_MS)
                    )
        val controlNoReply = !controlOutcome.ping.hasReplies

        when {
            controlNoReply -> {
                findings += Finding(
                    description = context.getString(
                        R.string.checker_icmp_summary_inconclusive,
                        controlOutcome.target.host,
                    ),
                    isInformational = true,
                )
                findings += Finding(
                    description = "ICMP control target ${controlOutcome.target.host} did not reply",
                    isError = true,
                    source = EvidenceSource.ICMP_SPOOFING,
                )
            }
            blockedUnexpectedReply && controlRttTooLow -> {
                findings += Finding(
                    description = context.getString(
                        R.string.checker_icmp_summary_both_suspicious,
                        blockedOutcome.target.host,
                        controlOutcome.target.host,
                        formatRtt(controlOutcome.ping.minRttMs),
                        formatRtt(controlOutcome.ping.avgRttMs),
                    ),
                    needsReview = true,
                    source = EvidenceSource.ICMP_SPOOFING,
                    confidence = EvidenceConfidence.MEDIUM,
                )
                evidence += suspiciousEvidence(
                    context.getString(
                        R.string.checker_icmp_evidence_both,
                        blockedOutcome.target.host,
                        controlOutcome.target.host,
                    ),
                )
            }
            blockedUnexpectedReply -> {
                findings += Finding(
                    description = context.getString(
                        R.string.checker_icmp_summary_blocked_replied,
                        blockedOutcome.target.host,
                    ),
                    needsReview = true,
                    source = EvidenceSource.ICMP_SPOOFING,
                    confidence = EvidenceConfidence.MEDIUM,
                )
                evidence += suspiciousEvidence(
                    context.getString(
                        R.string.checker_icmp_evidence_blocked_replied,
                        blockedOutcome.target.host,
                    ),
                )
            }
            controlRttTooLow -> {
                findings += Finding(
                    description = context.getString(
                        R.string.checker_icmp_summary_control_too_fast,
                        controlOutcome.target.host,
                        formatRtt(controlOutcome.ping.minRttMs),
                        formatRtt(controlOutcome.ping.avgRttMs),
                    ),
                    needsReview = true,
                    source = EvidenceSource.ICMP_SPOOFING,
                    confidence = EvidenceConfidence.MEDIUM,
                )
                evidence += suspiciousEvidence(
                    context.getString(
                        R.string.checker_icmp_evidence_control_too_fast,
                        controlOutcome.target.host,
                    ),
                )
            }
            else -> {
                findings += Finding(
                    description = context.getString(
                        R.string.checker_icmp_summary_clean,
                        blockedOutcome.target.host,
                        controlOutcome.target.host,
                        formatRtt(controlOutcome.ping.avgRttMs),
                    ),
                    isInformational = true,
                )
            }
        }

        findings += outcomes.map { outcome ->
            Finding(
                description = when (outcome.target.role) {
                    Role.BLOCKED -> context.getString(
                        R.string.checker_icmp_target_blocked,
                        outcome.target.host,
                        outcome.address,
                        outcome.ping.received,
                        outcome.ping.sent,
                    )
                    Role.CONTROL -> context.getString(
                        R.string.checker_icmp_target_control,
                        outcome.target.host,
                        outcome.address,
                        outcome.ping.received,
                        outcome.ping.sent,
                        formatRtt(outcome.ping.minRttMs),
                        formatRtt(outcome.ping.avgRttMs),
                        formatRtt(outcome.ping.maxRttMs),
                    )
                },
                isInformational = true,
            )
        }

        CategoryResult(
            name = context.getString(R.string.main_card_icmp_spoofing),
            detected = false,
            findings = findings,
            needsReview = findings.any { it.needsReview },
            evidence = evidence,
        )
    }

    private fun unsupportedResult(context: Context, error: Throwable): CategoryResult {
        return CategoryResult(
            name = context.getString(R.string.main_card_icmp_spoofing),
            detected = false,
            findings = listOf(
                Finding(
                    description = context.getString(R.string.checker_icmp_summary_unavailable),
                    isInformational = true,
                ),
                Finding(
                    description = error.message ?: error::class.java.simpleName,
                    isError = true,
                    source = EvidenceSource.ICMP_SPOOFING,
                ),
            ),
        )
    }

    private fun suspiciousEvidence(description: String): EvidenceItem {
        return EvidenceItem(
            source = EvidenceSource.ICMP_SPOOFING,
            detected = true,
            confidence = EvidenceConfidence.MEDIUM,
            description = description,
        )
    }

    private fun formatRtt(value: Double?): String {
        return value?.let { String.format(Locale.US, "%.1f ms", it) } ?: "n/a"
    }

    internal fun isUsablePublicIpv4(address: Inet4Address): Boolean {
        if (
            address.isAnyLocalAddress ||
            address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isMulticastAddress
        ) {
            return false
        }

        val bytes = address.address.map { it.toInt() and 0xff }
        val first = bytes[0]
        val second = bytes[1]
        val third = bytes[2]
        return when {
            first == 0 -> false
            first == 100 && second in 64..127 -> false
            first == 192 && second == 0 && (third == 0 || third == 2) -> false
            first == 198 && second in 18..19 -> false
            first == 198 && second == 51 && third == 100 -> false
            first == 203 && second == 0 && third == 113 -> false
            first >= 240 -> false
            else -> true
        }
    }
}
