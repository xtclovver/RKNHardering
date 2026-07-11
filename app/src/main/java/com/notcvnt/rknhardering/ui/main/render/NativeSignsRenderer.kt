package com.notcvnt.rknhardering.ui.main.render

import android.content.res.ColorStateList
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.ViewCompat
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.NativeSignalCatalog
import com.notcvnt.rknhardering.NativeSignalCategory
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding

internal class NativeSignsRenderer(
    env: MainRenderEnvironment,
    private val findingViews: FindingViewFactory,
) : SectionRenderer(env) {

    fun render(
        result: CategoryResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        summary: TextView,
        groupsContainer: LinearLayout,
        privacyMode: Boolean,
    ) {
        if (result.findings.isEmpty() && result.evidence.isEmpty()) {
            card.visibility = View.GONE
            return
        }
        card.visibility = View.VISIBLE
        bindCardStatus(result.detected, result.needsReview, icon, status, result.hasError)
        summary.visibility = View.GONE
        groupsContainer.removeAllViews()
        groupsContainer.visibility = View.VISIBLE

        NativeSignalCategory.entries.forEach { category ->
            val findings = result.findings.filter {
                NativeSignalCatalog.info(it.nativeSignalId).category == category
            }
            groupsContainer.addView(createGroup(category, findings, privacyMode))
        }
    }

    private fun createGroup(
        category: NativeSignalCategory,
        findings: List<Finding>,
        privacyMode: Boolean,
    ): View {
        val semantic = statusSemantic(
            detected = findings.any { it.detected },
            needsReview = findings.any { it.needsReview },
            hasError = findings.any { it.isError },
        )
        val visual = statusVisual(semantic)
        val initiallyExpanded = findings.any { it.isError || it.detected || it.needsReview }

        val card = MaterialCardView(themedContext()).apply {
            tag = "native-group:${category.name}"
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
        }
        val header = LinearLayout(themedContext()).apply {
            tag = "native-group-header:${category.name}"
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            minimumHeight = 48.dp
            isClickable = true
            isFocusable = true
            setPaddingRelative(12.dp, 6.dp, 4.dp, 6.dp)
        }
        val title = TextView(themedContext()).apply {
            setText(category.titleRes)
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            textDirection = View.TEXT_DIRECTION_LOCALE
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val groupStatus = TextView(themedContext()).apply {
            setText(visual.labelRes)
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(visual.accentColor)
        }
        val chevron = ImageView(themedContext()).apply {
            setImageResource(R.drawable.ic_chevron_right)
            imageTintList = ColorStateList.valueOf(onSurfaceVariantColor())
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            layoutParams = LinearLayout.LayoutParams(48.dp, 48.dp)
            setPadding(15.dp, 15.dp, 15.dp, 15.dp)
        }
        val details = LinearLayout(themedContext()).apply {
            tag = "native-group-details:${category.name}"
            orientation = LinearLayout.VERTICAL
            setPadding(12.dp, 0, 12.dp, 12.dp)
        }
        findings.forEach { details.addView(findingViews.createNativeFindingView(it, privacyMode)) }

        fun setExpanded(expanded: Boolean) {
            details.visibility = if (expanded) View.VISIBLE else View.GONE
            chevron.rotation = if (expanded) {
                if (isRtlLayout()) -90f else 90f
            } else {
                0f
            }
            val state = getString(
                if (expanded) R.string.accessibility_expanded else R.string.accessibility_collapsed,
            )
            val label = getString(category.titleRes)
            val statusLabel = getString(visual.labelRes)
            header.contentDescription = getString(
                R.string.accessibility_group_state,
                label,
                statusLabel,
                state,
            )
            ViewCompat.setStateDescription(header, state)
        }

        header.addView(title)
        header.addView(groupStatus)
        header.addView(chevron)
        header.setOnClickListener { setExpanded(details.visibility != View.VISIBLE) }
        container.addView(header)
        container.addView(details)
        card.addView(container)
        setExpanded(initiallyExpanded)
        return card
    }
}
