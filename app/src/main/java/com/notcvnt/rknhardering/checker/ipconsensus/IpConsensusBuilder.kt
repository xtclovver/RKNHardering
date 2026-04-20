package com.notcvnt.rknhardering.checker.ipconsensus

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.IpFamily
import com.notcvnt.rknhardering.model.ObservedIp
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.model.UnparsedIp
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber

object IpConsensusBuilder {

    private data class Candidate(
        val raw: String,
        val channel: Channel,
        val source: String,
        val targetGroup: TargetGroup?,
        val countryCode: String?,
        val asn: String?,
    )

    suspend fun build(
        geoIp: CategoryResult,
        ipComparison: IpComparisonResult,
        cdnPulling: CdnPullingResult,
        tunProbe: UnderlyingNetworkProber.ProbeResult?,
        bypass: BypassResult,
        callTransportLeaks: List<CallTransportLeakResult> = emptyList(),
        asnResolver: AsnResolver,
    ): IpConsensusResult {
        val candidates = collectCandidates(
            geoIp = geoIp,
            ipComparison = ipComparison,
            cdn = cdnPulling,
            probe = tunProbe,
            bypass = bypass,
            callTransportLeaks = callTransportLeaks,
        )

        val unparsed = mutableListOf<UnparsedIp>()
        val parsed = mutableListOf<ParsedCandidate>()
        for (candidate in candidates) {
            val normalized = IpNormalization.parse(candidate.raw)
            if (normalized == null) {
                unparsed += UnparsedIp(raw = candidate.raw, source = candidate.source)
                continue
            }
            parsed += ParsedCandidate(
                value = normalized.value,
                family = normalized.family,
                channel = candidate.channel,
                source = candidate.source,
                targetGroup = candidate.targetGroup,
                countryCode = candidate.countryCode,
                asn = candidate.asn,
            )
        }

        val ipsNeedingResolve = parsed
            .filter { it.countryCode == null || it.asn == null }
            .map { it.value }
            .toSet()
        val asnInfo = asnResolver.resolveAll(ipsNeedingResolve)

        val merged = mergeByChannelAndValue(parsed, asnInfo)
        val channelIps = merged.groupBy({ it.channel }, { it.value })
            .mapValues { (_, ips) -> ips.toSet() }

        val channelConflict = Channel.values().filter { channel ->
            val ipsV4 = merged.filter { it.channel == channel && it.family == IpFamily.V4 }.map { it.value }.toSet()
            val ipsV6 = merged.filter { it.channel == channel && it.family == IpFamily.V6 }.map { it.value }.toSet()
            ipsV4.size >= 2 || ipsV6.size >= 2
        }.toSet()

        val allFamilies = merged.map { it.family }.toSet()
        val dualStackObserved = IpFamily.V4 in allFamilies && IpFamily.V6 in allFamilies

        val crossChannelMismatch = computeCrossChannelMismatch(merged)
        val foreignIps = merged
            .filter { it.countryCode != null && it.countryCode != "RU" }
            .map { it.value }
            .toSet()
        val geoCountryMismatch = merged
            .mapNotNull { it.countryCode }
            .toSet()
            .size >= 2
        val sameAsnAcrossChannels = computeSameAsnAcrossChannels(merged)
        val warpLikeIndicator = computeWarpLike(merged)

        val probeTargetDivergence = ipsDifferAcrossTargets(
            merged, Channel.VPN,
        )
        val probeTargetDirectDivergence = ipsDifferAcrossTargets(
            merged, Channel.DIRECT,
        )

        val needsReview = unparsed.isNotEmpty()

        return IpConsensusResult(
            observedIps = merged.map {
                ObservedIp(
                    value = it.value,
                    family = it.family,
                    channel = it.channel,
                    sources = it.sources,
                    countryCode = it.countryCode,
                    asn = it.asn,
                    targetGroup = it.targetGroup,
                )
            },
            unparsedIps = unparsed,
            channelIps = channelIps,
            channelConflict = channelConflict,
            crossChannelMismatch = crossChannelMismatch,
            dualStackObserved = dualStackObserved,
            foreignIps = foreignIps,
            geoCountryMismatch = geoCountryMismatch,
            sameAsnAcrossChannels = sameAsnAcrossChannels,
            warpLikeIndicator = warpLikeIndicator,
            probeTargetDivergence = probeTargetDivergence,
            probeTargetDirectDivergence = probeTargetDirectDivergence,
            needsReview = needsReview,
        )
    }

    private fun collectCandidates(
        geoIp: CategoryResult,
        ipComparison: IpComparisonResult,
        cdn: CdnPullingResult,
        probe: UnderlyingNetworkProber.ProbeResult?,
        bypass: BypassResult,
        callTransportLeaks: List<CallTransportLeakResult>,
    ): List<Candidate> {
        val out = mutableListOf<Candidate>()

        geoIp.geoFacts?.ip?.let {
            out += Candidate(
                raw = it,
                channel = Channel.DIRECT,
                source = "geoip",
                targetGroup = null,
                countryCode = geoIp.geoFacts?.countryCode,
                asn = geoIp.geoFacts?.asn,
            )
        }

        for (response in ipComparison.ruGroup.responses) {
            val ip = response.ip ?: continue
            out += Candidate(
                raw = ip,
                channel = Channel.DIRECT,
                source = "ipcomp:ru:${response.label}",
                targetGroup = null,
                countryCode = null,
                asn = null,
            )
        }
        for (response in ipComparison.nonRuGroup.responses) {
            val ip = response.ip ?: continue
            out += Candidate(
                raw = ip,
                channel = Channel.DIRECT,
                source = "ipcomp:non-ru:${response.label}",
                targetGroup = null,
                countryCode = null,
                asn = null,
            )
        }

        for (response in cdn.responses) {
            val ip = response.ip ?: response.ipv4 ?: continue
            out += Candidate(
                raw = ip,
                channel = Channel.CDN,
                source = "cdn:${response.targetLabel}",
                targetGroup = null,
                countryCode = null,
                asn = null,
            )
        }

        probe?.ruTarget?.directIp?.let {
            out += Candidate(it, Channel.DIRECT, "underlying-prober.ru.direct", TargetGroup.RU, null, null)
        }
        probe?.ruTarget?.vpnIp?.let {
            out += Candidate(it, Channel.VPN, "underlying-prober.ru.vpn", TargetGroup.RU, null, null)
        }
        probe?.nonRuTarget?.directIp?.let {
            out += Candidate(it, Channel.DIRECT, "underlying-prober.non-ru.direct", TargetGroup.NON_RU, null, null)
        }
        probe?.nonRuTarget?.vpnIp?.let {
            out += Candidate(it, Channel.VPN, "underlying-prober.non-ru.vpn", TargetGroup.NON_RU, null, null)
        }

        bypass.directIp?.let { out += Candidate(it, Channel.DIRECT, "bypass.direct", null, null, null) }
        bypass.underlyingIp?.let { out += Candidate(it, Channel.DIRECT, "bypass.underlying", null, null, null) }
        bypass.vpnNetworkIp?.let { out += Candidate(it, Channel.VPN, "bypass.vpn", null, null, null) }
        bypass.proxyIp?.let { out += Candidate(it, Channel.PROXY, "bypass.proxy", null, null, null) }
        callTransportLeaks.forEach { leak ->
            val mappedIp = leak.mappedIp ?: return@forEach
            val channel = when (leak.networkPath) {
                CallTransportNetworkPath.ACTIVE,
                CallTransportNetworkPath.UNDERLYING -> Channel.DIRECT
                CallTransportNetworkPath.LOCAL_PROXY -> Channel.PROXY
            }
            val source = buildString {
                append("call-transport:")
                append(leak.networkPath.name.lowercase())
                append(':')
                append(leak.probeKind.name.lowercase())
                leak.targetHost?.let {
                    append(':')
                    append(it)
                }
                leak.targetPort?.let {
                    append(':')
                    append(it)
                }
            }
            out += Candidate(
                raw = mappedIp,
                channel = channel,
                source = source,
                targetGroup = null,
                countryCode = null,
                asn = null,
            )
        }

        return out
    }

    private data class ParsedCandidate(
        val value: String,
        val family: IpFamily,
        val channel: Channel,
        val source: String,
        val targetGroup: TargetGroup?,
        val countryCode: String?,
        val asn: String?,
    )

    private data class MergedIp(
        val value: String,
        val family: IpFamily,
        val channel: Channel,
        val sources: Set<String>,
        val countryCode: String?,
        val asn: String?,
        val targetGroup: TargetGroup?,
    )

    private fun mergeByChannelAndValue(
        candidates: List<ParsedCandidate>,
        asnInfo: Map<String, com.notcvnt.rknhardering.model.AsnInfo?>,
    ): List<MergedIp> {
        return candidates.groupBy { it.value to it.channel }.map { (key, group) ->
            val (value, channel) = key
            val resolved = asnInfo[value]
            val countryCode = group.firstNotNullOfOrNull { it.countryCode } ?: resolved?.countryCode
            val asn = group.firstNotNullOfOrNull { it.asn } ?: resolved?.asn
            MergedIp(
                value = value,
                family = group.first().family,
                channel = channel,
                sources = group.map { it.source }.toSet(),
                countryCode = countryCode,
                asn = asn,
                targetGroup = group.mapNotNull { it.targetGroup }.firstOrNull(),
            )
        }
    }

    private fun computeCrossChannelMismatch(merged: List<MergedIp>): Boolean {
        val channels = merged.map { it.channel }.toSet()
        if (channels.size < 2) return false
        for (family in IpFamily.values()) {
            val byChannel = channels.associateWith { ch ->
                merged.filter { it.channel == ch && it.family == family }.map { it.value }.toSet()
            }
            val nonEmpty = byChannel.filterValues { it.isNotEmpty() }
            if (nonEmpty.size < 2) continue
            val pairs = nonEmpty.entries.toList()
            for (i in pairs.indices) {
                for (j in i + 1 until pairs.size) {
                    if (pairs[i].value.intersect(pairs[j].value).isEmpty()) return true
                }
            }
        }
        return false
    }

    private fun computeSameAsnAcrossChannels(merged: List<MergedIp>): Boolean {
        val byAsn = merged.filter { it.asn != null }.groupBy { it.asn!! }
        return byAsn.any { (_, list) -> list.map { it.channel }.toSet().size >= 2 }
    }

    private fun computeWarpLike(merged: List<MergedIp>): Boolean {
        val proxyIps = merged.filter { it.channel == Channel.PROXY }.map { it.value }.toSet()
        if (proxyIps.isEmpty()) return false
        val otherIps = merged.filter { it.channel != Channel.PROXY }.map { it.value }.toSet()
        return (proxyIps - otherIps).isNotEmpty()
    }

    private fun ipsDifferAcrossTargets(merged: List<MergedIp>, channel: Channel): Boolean {
        val ru = merged.filter { it.channel == channel && it.targetGroup == TargetGroup.RU }
        val nonRu = merged.filter { it.channel == channel && it.targetGroup == TargetGroup.NON_RU }
        for (family in IpFamily.values()) {
            val ruValues = ru.filter { it.family == family }.map { it.value }.toSet()
            val nonRuValues = nonRu.filter { it.family == family }.map { it.value }.toSet()
            if (ruValues.isNotEmpty() && nonRuValues.isNotEmpty() && ruValues.intersect(nonRuValues).isEmpty()) {
                return true
            }
        }
        return false
    }
}
