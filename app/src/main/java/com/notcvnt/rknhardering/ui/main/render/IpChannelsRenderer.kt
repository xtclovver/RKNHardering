package com.notcvnt.rknhardering.ui.main.render

import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.StatusSemantic
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.IpFamily
import com.notcvnt.rknhardering.model.ObservedIp
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.util.maskInfoValue

/**
 * Renders the IP-channels (consensus) card: per-channel observed IP rows and
 * the aggregated warning flags. Moved verbatim from MainActivity. Note that
 * render() currently has no production caller, matching the pre-extraction
 * state of displayIpChannels; createIpChannelRow stays reachable through the
 * MainActivity reflection delegator.
 */
internal class IpChannelsRenderer(
    env: MainRenderEnvironment,
) : SectionRenderer(env) {

    fun render(
        consensus: IpConsensusResult,
        card: MaterialCardView,
        container: LinearLayout,
        privacyMode: Boolean,
    ) {
        if (consensus.observedIps.isEmpty()) {
            card.visibility = View.GONE
            return
        }
        card.visibility = View.VISIBLE
        container.removeAllViews()

        consensus.observedIps.forEach { ip ->
            container.addView(createIpChannelRow(ip, privacyMode))
        }

        val hasWarning = consensus.crossChannelMismatch || consensus.warpLikeIndicator ||
                consensus.geoCountryMismatch || consensus.probeTargetDivergence ||
                consensus.probeTargetDirectDivergence || consensus.channelConflict.isNotEmpty() ||
                consensus.needsReview

        if (hasWarning) {
            val flagsContainer = LinearLayout(themedContext()).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = 8.dp }
            }

            val warningColor = statusColor(StatusSemantic.DETECTED)
            val warningBackground = TextView(themedContext()).apply {
                text = buildIpConsensusWarningText(consensus)
                textSize = 12f
                setTextColor(warningColor)
                setPadding(8.dp, 8.dp, 8.dp, 8.dp)
            }

            flagsContainer.addView(warningBackground)
            container.addView(flagsContainer)
        }
    }

    fun createIpChannelRow(ip: ObservedIp, privacyMode: Boolean): View {
        val row = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val channelChip = TextView(themedContext()).apply {
            text = ipChannelLabel(ip.channel)
            textSize = 11f
            setTextColor(onSurfaceColor())
            typeface = Typeface.DEFAULT_BOLD
            val padding = 6.dp
            setPadding(padding, padding / 2, padding, padding / 2)
            setBackgroundColor(MaterialColors.getColor(themedContext(), com.google.android.material.R.attr.colorSurfaceVariant, 0))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                .apply { marginEnd = 8.dp }
        }

        val targetChip = if (ip.targetGroup != null) {
            TextView(themedContext()).apply {
                text = ipTargetGroupLabel(ip.targetGroup)
                textSize = 11f
                setTextColor(onSurfaceColor())
                typeface = Typeface.DEFAULT_BOLD
                val padding = 6.dp
                setPadding(padding, padding / 2, padding, padding / 2)
                setBackgroundColor(statusContainerColor(StatusSemantic.REVIEW))
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                    .apply { marginEnd = 8.dp }
            }
        } else null

        val infoText = buildString {
            val maskedIp = maskInfoValue(ip.value, privacyMode)
            append(maskedIp)
            if (ip.countryCode != null) append(" (${ip.countryCode})")
            if (ip.asn != null) append(" ${ip.asn}")
            append(" • ${ipFamilyLabel(ip.family)}")
        }

        val infoView = TextView(themedContext()).apply {
            text = infoText
            textSize = 13f
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = View.TEXT_ALIGNMENT_VIEW_START
        }

        row.addView(channelChip)
        if (targetChip != null) row.addView(targetChip)
        row.addView(infoView)

        return row
    }

    private fun buildIpConsensusWarningText(consensus: IpConsensusResult): String {
        val warnings = buildList {
            if (consensus.crossChannelMismatch) add(getString(R.string.ip_channels_flag_cross_channel_mismatch))
            if (consensus.warpLikeIndicator) add(getString(R.string.ip_channels_flag_warp_like_behavior))
            if (consensus.geoCountryMismatch) add(getString(R.string.ip_channels_flag_geo_country_mismatch))
            if (consensus.probeTargetDivergence) add(getString(R.string.ip_channels_flag_probe_target_divergence))
            if (consensus.probeTargetDirectDivergence) {
                add(getString(R.string.ip_channels_flag_probe_target_direct_divergence))
            }
            if (consensus.channelConflict.isNotEmpty()) {
                val channels = consensus.channelConflict
                    .sortedBy { it.ordinal }
                    .joinToString(", ") { ipChannelLabel(it) }
                add(getString(R.string.ip_channels_flag_channel_conflict, channels))
            }
            if (consensus.needsReview) add(getString(R.string.ip_channels_flag_needs_review))
        }
        return warnings.joinToString(separator = "\n") { "⚠ $it" }
    }

    private fun ipChannelLabel(channel: Channel): String = when (channel) {
        Channel.DIRECT -> getString(R.string.ip_channels_channel_direct)
        Channel.VPN -> getString(R.string.ip_channels_channel_vpn)
        Channel.PROXY -> getString(R.string.ip_channels_channel_proxy)
        Channel.CDN -> getString(R.string.ip_channels_channel_cdn)
    }

    private fun ipTargetGroupLabel(targetGroup: TargetGroup): String = when (targetGroup) {
        TargetGroup.RU -> getString(R.string.ip_channels_target_ru)
        TargetGroup.NON_RU -> getString(R.string.ip_channels_target_non_ru)
    }

    private fun ipFamilyLabel(family: IpFamily): String = when (family) {
        IpFamily.V4 -> getString(R.string.main_card_call_transport_stun_ipv4)
        IpFamily.V6 -> getString(R.string.main_card_call_transport_stun_ipv6)
    }
}
