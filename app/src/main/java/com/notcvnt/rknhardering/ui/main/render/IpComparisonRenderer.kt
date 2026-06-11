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
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.util.maskIp
import com.notcvnt.rknhardering.util.maskIpsInText

/**
 * Renders the IP-comparison card: RU/non-RU checker groups with expandable
 * per-checker response rows. Moved verbatim from MainActivity.
 */
internal class IpComparisonRenderer(
    env: MainRenderEnvironment,
) : SectionRenderer(env) {

    fun render(
        result: IpComparisonResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        summary: TextView,
        groupsContainer: LinearLayout,
        privacyMode: Boolean,
    ) {
        card.visibility = View.VISIBLE
        bindCardStatus(result.detected, result.needsReview, icon, status, hasError = result.hasError)
        summary.text = if (privacyMode) maskIpsInText(result.summary) else result.summary

        groupsContainer.removeAllViews()
        groupsContainer.visibility = View.VISIBLE
        groupsContainer.addView(
            createIpCheckerGroupView(
                group = result.ruGroup,
                expanded = result.detected || result.needsReview || result.hasError || result.ruGroup.needsReview,
                privacyMode = privacyMode,
            ),
        )
        groupsContainer.addView(
            createIpCheckerGroupView(
                group = result.nonRuGroup,
                expanded = result.detected || result.needsReview || result.hasError || result.nonRuGroup.detected,
                privacyMode = privacyMode,
            ),
        )
    }

    private fun createIpCheckerGroupView(
        group: IpCheckerGroupResult,
        expanded: Boolean,
        privacyMode: Boolean = false,
    ): View {
        val card = MaterialCardView(themedContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = 8.dp
            }
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
            text = group.title
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val status = TextView(themedContext()).apply {
            text = group.statusLabel
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(statusColor(statusSemantic(group.detected, group.needsReview)))
        }

        val toggle = TextView(themedContext()).apply {
            text = if (expanded) "▼" else "▶"
            textSize = 12f
            setPadding(8.dp, 0, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val summary = TextView(themedContext()).apply {
            text = if (privacyMode) maskIpsInText(group.summary) else group.summary
            textSize = 13f
            setPadding(0, 6.dp, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val details = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            visibility = if (expanded) View.VISIBLE else View.GONE
            setPadding(0, 8.dp, 0, 0)
        }
        group.responses.forEach { response ->
            details.addView(createIpCheckerResponseView(response, privacyMode))
        }

        header.addView(title)
        header.addView(status)
        header.addView(toggle)

        val toggleDetails = {
            val nextExpanded = details.visibility != View.VISIBLE
            details.visibility = if (nextExpanded) View.VISIBLE else View.GONE
            toggle.text = if (nextExpanded) "▼" else "▶"
        }
        header.setOnClickListener { toggleDetails() }
        summary.setOnClickListener { toggleDetails() }

        container.addView(header)
        container.addView(summary)
        container.addView(details)
        card.addView(container)
        return card
    }

    fun createIpCheckerResponseView(response: IpCheckerResponse, privacyMode: Boolean = false): View {
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 8.dp, 0, 8.dp)
        }

        val topRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val label = TextView(themedContext()).apply {
            text = response.label
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val displayIp = if (privacyMode && response.ip != null) maskIp(response.ip) else response.ip
        val value = TextView(themedContext()).apply {
            text = displayIp ?: getString(R.string.main_card_status_error)
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(statusColor(if (response.ip != null) StatusSemantic.CLEAN else StatusSemantic.ERROR))
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
        container.addView(url)

        return container
    }
}
