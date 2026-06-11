package com.notcvnt.rknhardering.ui.main.render

import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.StatusSemantic
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.StunProbeGroupResult
import com.notcvnt.rknhardering.model.StunScope
import com.notcvnt.rknhardering.util.formatCallTransportReason
import com.notcvnt.rknhardering.util.maskIp

/**
 * Renders the call-transport card: STUN probe groups and per-service leak
 * rows. Moved verbatim from MainActivity.
 */
internal class CallTransportRenderer(
    env: MainRenderEnvironment,
    private val findingViews: FindingViewFactory,
) : SectionRenderer(env) {

    fun render(
        leaks: List<CallTransportLeakResult>,
        stunGroups: List<StunProbeGroupResult>,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        summary: TextView,
        stunGroupsContainer: LinearLayout,
        findingsContainer: LinearLayout,
        privacyMode: Boolean,
    ) {
        val hasContent = leaks.isNotEmpty() || stunGroups.any { it.results.isNotEmpty() }
        if (!hasContent) {
            card.visibility = View.GONE
            return
        }
        card.visibility = View.VISIBLE

        val hasNeedsReview = leaks.any { it.status == CallTransportStatus.NEEDS_REVIEW }
        val hasError = leaks.any { it.status == CallTransportStatus.ERROR }
        bindCardStatus(
            detected = false,
            needsReview = hasNeedsReview,
            icon = icon,
            status = status,
            hasError = hasError,
        )

        val respondedCount = stunGroups.sumOf { it.respondedCount }
        val totalCount = stunGroups.sumOf { it.totalCount }
        if (totalCount > 0) {
            summary.text = getString(
                R.string.main_card_call_transport_stun_responded,
                respondedCount,
                totalCount,
            )
            summary.visibility = View.VISIBLE
        } else {
            summary.visibility = View.GONE
        }

        stunGroupsContainer.removeAllViews()
        if (stunGroups.isNotEmpty()) {
            stunGroupsContainer.visibility = View.VISIBLE
            for (group in stunGroups) {
                stunGroupsContainer.addView(createStunGroupView(group, privacyMode))
            }
        } else {
            stunGroupsContainer.visibility = View.GONE
        }

        findingsContainer.removeAllViews()
        if (leaks.isNotEmpty()) {
            findingsContainer.visibility = View.VISIBLE
            for (leak in leaks) {
                findingsContainer.addView(createCallTransportLeakView(leak, privacyMode))
            }
        } else {
            findingsContainer.visibility = View.GONE
        }
    }

    private fun createStunGroupView(group: StunProbeGroupResult, privacyMode: Boolean): View {
        val groupTitle = when (group.scope) {
            StunScope.GLOBAL -> getString(R.string.main_card_call_transport_stun_group_global)
            StunScope.RU -> getString(R.string.main_card_call_transport_stun_group_ru)
        }
        val respondedCount = group.respondedCount
        val totalCount = group.totalCount
        val statusLabel = if (respondedCount > 0) {
            getString(R.string.main_card_call_transport_stun_responded, respondedCount, totalCount)
        } else {
            getString(R.string.main_card_call_transport_stun_none_responded)
        }

        val card = com.google.android.material.card.MaterialCardView(themedContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = 8.dp }
            radius = 14.dp.toFloat()
            strokeWidth = 1.dp
            strokeColor = outlineVariantColor()
            setCardBackgroundColor(surfaceColor())
        }

        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(12.dp, 12.dp, 12.dp, 12.dp)
        }

        val header = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val title = TextView(themedContext()).apply {
            text = groupTitle
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val statusView = TextView(themedContext()).apply {
            text = statusLabel
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(statusColor(if (respondedCount > 0) StatusSemantic.CLEAN else StatusSemantic.REVIEW))
        }

        val expanded = respondedCount > 0
        val toggle = TextView(themedContext()).apply {
            text = if (expanded) "▼" else "▶"
            textSize = 12f
            setPadding(8.dp, 0, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val details = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            visibility = if (expanded) View.VISIBLE else View.GONE
            setPadding(0, 8.dp, 0, 0)
        }

        for (result in group.results) {
            details.addView(createStunProbeResultView(result, privacyMode))
        }

        val toggleDetails = {
            val nextExpanded = details.visibility != View.VISIBLE
            details.visibility = if (nextExpanded) View.VISIBLE else View.GONE
            toggle.text = if (nextExpanded) "▼" else "▶"
        }
        header.setOnClickListener { toggleDetails() }

        header.addView(title)
        header.addView(statusView)
        header.addView(toggle)
        container.addView(header)
        container.addView(details)
        card.addView(container)
        return card
    }

    private fun createStunProbeResultView(result: com.notcvnt.rknhardering.model.StunProbeResult, privacyMode: Boolean): View {
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 6.dp, 0, 6.dp)
        }

        val hostRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val hostLabel = TextView(themedContext()).apply {
            text = "${result.host}:${result.port}"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val hasAnyResponse = result.hasResponse
        val hasDualStack = result.mappedIpv4 != null && result.mappedIpv6 != null
        val responseLabel = TextView(themedContext()).apply {
            text = when {
                hasAnyResponse && hasDualStack -> "IPv4 + IPv6"
                hasAnyResponse -> result.mappedIpDisplay?.let { ip ->
                    if (privacyMode) maskIp(ip) else ip
                } ?: getString(R.string.main_card_call_transport_stun_no_response)
                result.error != null -> getString(R.string.main_card_call_transport_stun_error)
                else -> getString(R.string.main_card_call_transport_stun_no_response)
            }
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(statusColor(if (hasAnyResponse) StatusSemantic.CLEAN else StatusSemantic.REVIEW))
        }

        hostRow.addView(hostLabel)
        hostRow.addView(responseLabel)
        container.addView(hostRow)

        if (result.mappedIpv4 != null && result.mappedIpv6 != null) {
            container.addView(findingViews.createInfoView(
                getString(R.string.main_card_call_transport_stun_ipv4),
                if (privacyMode) maskIp(result.mappedIpv4) else result.mappedIpv4,
            ))
            container.addView(findingViews.createInfoView(
                getString(R.string.main_card_call_transport_stun_ipv6),
                if (privacyMode) maskIp(result.mappedIpv6) else result.mappedIpv6,
            ))
        }

        result.error?.takeIf { it.isNotBlank() && !hasAnyResponse }?.let { err ->
            container.addView(TextView(themedContext()).apply {
                text = err
                textSize = 11f
                setTextColor(onSurfaceVariantColor())
                setPadding(0, 2.dp, 0, 0)
            })
        }

        return container
    }

    private fun createCallTransportLeakView(leak: CallTransportLeakResult, privacyMode: Boolean): View {
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val statusLabel = when (leak.status) {
            CallTransportStatus.BASELINE -> getString(R.string.main_card_call_transport_status_baseline)
            CallTransportStatus.NO_SIGNAL -> getString(R.string.main_card_call_transport_status_no_signal)
            CallTransportStatus.NEEDS_REVIEW -> getString(R.string.main_card_call_transport_status_needs_review)
            CallTransportStatus.UNSUPPORTED -> getString(R.string.main_card_call_transport_status_unsupported)
            CallTransportStatus.ERROR -> getString(R.string.main_card_call_transport_status_error)
        }
        val pathLabel = when (leak.networkPath) {
            CallTransportNetworkPath.ACTIVE -> getString(R.string.main_card_call_transport_path_active)
            CallTransportNetworkPath.UNDERLYING -> getString(R.string.main_card_call_transport_path_underlying)
            CallTransportNetworkPath.LOCAL_PROXY -> getString(R.string.main_card_call_transport_path_proxy)
        }
        val serviceLabel = when (leak.service) {
            CallTransportService.TELEGRAM -> "Telegram"
            CallTransportService.WHATSAPP -> "WhatsApp"
        }
        val statusColor = when (leak.status) {
            CallTransportStatus.BASELINE -> statusColor(StatusSemantic.CLEAN)
            CallTransportStatus.NEEDS_REVIEW -> statusColor(StatusSemantic.REVIEW)
            CallTransportStatus.ERROR -> statusColor(StatusSemantic.ERROR)
            CallTransportStatus.NO_SIGNAL -> statusColor(StatusSemantic.NEUTRAL)
            CallTransportStatus.UNSUPPORTED -> statusColor(StatusSemantic.NEUTRAL)
        }

        val headerRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val indicator = TextView(themedContext()).apply {
            text = when (leak.status) {
                CallTransportStatus.BASELINE -> "✓"
                CallTransportStatus.NEEDS_REVIEW -> "?"
                CallTransportStatus.ERROR -> "⚠"
                CallTransportStatus.NO_SIGNAL -> "—"
                CallTransportStatus.UNSUPPORTED -> "—"
            }
            setTextColor(statusColor)
            textSize = 14f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
        }
        val headerText = TextView(themedContext()).apply {
            text = getString(
                R.string.main_card_call_transport_header,
                serviceLabel,
                pathLabel,
                statusLabel,
            )
            textSize = 13f
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        headerRow.addView(indicator)
        headerRow.addView(headerText)
        container.addView(headerRow)

        formatCallTransportReason(env.context, leak, privacyMode)?.let { reason ->
            val reasonColor = if (leak.status == CallTransportStatus.ERROR) {
                statusColor(StatusSemantic.ERROR)
            } else {
                onSurfaceVariantColor()
            }
            container.addView(TextView(themedContext()).apply {
                text = reason
                textSize = 12f
                setPadding(22.dp, 2.dp, 0, 0)
                setTextColor(reasonColor)
            })
        }

        val target = leak.targetHost
        if (target != null) {
            val port = leak.targetPort
            val targetStr = if (port != null) {
                if (target.contains(':')) "[$target]:$port" else "$target:$port"
            } else target
            container.addView(findingViews.createInfoView(
                label = "target",
                value = if (privacyMode) maskIp(targetStr) else targetStr,
            ))
        }
        val mappedIp = leak.mappedIp
        if (!mappedIp.isNullOrBlank()) {
            container.addView(findingViews.createInfoView(
                label = "mapped IP",
                value = if (privacyMode) maskIp(mappedIp) else mappedIp,
            ))
        }
        val publicIp = leak.observedPublicIp
        if (!publicIp.isNullOrBlank()) {
            container.addView(findingViews.createInfoView(
                label = "public IP",
                value = if (privacyMode) maskIp(publicIp) else publicIp,
            ))
        }

        return container
    }
}
