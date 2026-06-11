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
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.util.maskInfoValue
import com.notcvnt.rknhardering.util.maskIp
import com.notcvnt.rknhardering.util.maskIpsInText

/**
 * Renders the CDN-pulling card and its per-target response rows. Moved
 * verbatim from MainActivity.
 */
internal class CdnPullingRenderer(
    env: MainRenderEnvironment,
    private val findingViews: FindingViewFactory,
) : SectionRenderer(env) {

    fun render(
        result: CdnPullingResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        summary: TextView,
        responsesContainer: LinearLayout,
        privacyMode: Boolean,
    ) {
        card.visibility = View.VISIBLE
        bindCardStatus(result.detected, result.needsReview, icon, status, hasError = result.hasError)
        summary.text = if (privacyMode) maskIpsInText(result.summary) else result.summary

        responsesContainer.removeAllViews()
        responsesContainer.visibility = if (result.responses.isEmpty()) View.GONE else View.VISIBLE
        result.responses.forEach { response ->
            responsesContainer.addView(createCdnPullingResponseView(response, privacyMode))
        }
    }

    fun createCdnPullingResponseView(response: CdnPullingResponse, privacyMode: Boolean = false): View {
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 8.dp, 0, 8.dp)
        }

        val topRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val label = TextView(themedContext()).apply {
            text = response.targetLabel
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val hasDualStack = response.ipv4 != null && response.ipv6 != null
        val hasIpv6Only = response.ipv6 != null && response.ipv4 == null
        val primaryDisplayIp = response.ip

        val valueText = when {
            hasDualStack -> if (privacyMode) maskIp(response.ipv4!!) else response.ipv4!!
            hasIpv6Only && response.ipv4Unavailable -> if (privacyMode) maskIp(response.ipv6!!) else response.ipv6!!
            primaryDisplayIp != null -> if (privacyMode) maskIp(primaryDisplayIp) else primaryDisplayIp
            response.importantFields.isNotEmpty() -> getString(R.string.main_card_status_detected)
            response.error != null -> getString(R.string.main_card_status_error)
            else -> getString(R.string.main_card_status_clean)
        }
        val value = TextView(themedContext()).apply {
            text = valueText
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(
                statusColor(
                    when {
                        primaryDisplayIp != null -> StatusSemantic.DETECTED
                        response.error != null -> StatusSemantic.ERROR
                        else -> StatusSemantic.CLEAN
                    },
                ),
            )
        }

        val url = TextView(themedContext()).apply {
            text = response.url
            textSize = 12f
            setPadding(0, 4.dp, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        topRow.addView(label)
        topRow.addView(value)
        container.addView(topRow)

        if (hasDualStack) {
            container.addView(
                TextView(themedContext()).apply {
                    text = if (privacyMode) maskIp(response.ipv6!!) else response.ipv6!!
                    textSize = 13f
                    typeface = Typeface.MONOSPACE
                    setPadding(0, 2.dp, 0, 0)
                    setTextColor(statusColor(StatusSemantic.DETECTED))
                },
            )
        } else if (response.ipv4Unavailable && response.ipv6 != null) {
            container.addView(
                TextView(themedContext()).apply {
                    text = getString(R.string.main_ip_comparison_ipv4_unavailable)
                    textSize = 12f
                    typeface = Typeface.MONOSPACE
                    setPadding(0, 2.dp, 0, 0)
                    setTextColor(onSurfaceVariantColor())
                },
            )
            response.ipv4Error?.takeIf { it.isNotBlank() }?.let { reason ->
                container.addView(
                    TextView(themedContext()).apply {
                        text = reason
                        textSize = 11f
                        typeface = Typeface.MONOSPACE
                        setPadding(0, 0, 0, 0)
                        setTextColor(onSurfaceVariantColor())
                    },
                )
            }
        }

        container.addView(url)

        response.importantFields.forEach { (fieldLabel, fieldValue) ->
            if (response.ip != null && fieldLabel.equals("IP", ignoreCase = true)) return@forEach
            container.addView(
                findingViews.createInfoView(
                    fieldLabel,
                    maskInfoValue(fieldValue, privacyMode),
                ),
            )
        }

        return container
    }
}
