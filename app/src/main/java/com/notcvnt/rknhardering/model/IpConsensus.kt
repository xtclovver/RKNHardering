package com.notcvnt.rknhardering.model

enum class Channel { DIRECT, VPN, PROXY, CDN }

enum class TargetGroup { RU, NON_RU }

enum class IpFamily { V4, V6 }

data class AsnInfo(
    val asn: String?,
    val countryCode: String?,
)

data class ObservedIp(
    val value: String,
    val family: IpFamily,
    val channel: Channel,
    val sources: Set<String>,
    val countryCode: String? = null,
    val asn: String? = null,
    val targetGroup: TargetGroup? = null,
)

data class UnparsedIp(
    val raw: String,
    val source: String,
)

data class IpConsensusResult(
    val observedIps: List<ObservedIp> = emptyList(),
    val unparsedIps: List<UnparsedIp> = emptyList(),
    val channelIps: Map<Channel, Set<String>> = emptyMap(),
    val channelConflict: Set<Channel> = emptySet(),
    val crossChannelMismatch: Boolean = false,
    val dualStackObserved: Boolean = false,
    val foreignIps: Set<String> = emptySet(),
    val geoCountryMismatch: Boolean = false,
    val sameAsnAcrossChannels: Boolean = false,
    val warpLikeIndicator: Boolean = false,
    val probeTargetDivergence: Boolean = false,
    val probeTargetDirectDivergence: Boolean = false,
    val needsReview: Boolean = false,
) {
    companion object {
        fun empty(needsReview: Boolean = false): IpConsensusResult =
            IpConsensusResult(needsReview = needsReview)
    }
}
