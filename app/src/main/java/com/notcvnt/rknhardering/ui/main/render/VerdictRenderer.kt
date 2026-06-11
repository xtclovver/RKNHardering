package com.notcvnt.rknhardering.ui.main.render

import android.content.res.ColorStateList
import android.graphics.Typeface
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.isNotEmpty
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.StatusSemantic
import com.notcvnt.rknhardering.StatusVisual
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.NarrativeRow
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VerdictNarrative
import com.notcvnt.rknhardering.model.VerdictNarrativeBuilder

/**
 * Bundle of the verdict card and hero views. Built by MainActivity per call;
 * the lateinit view fields stay activity-side.
 */
internal class VerdictViews(
    val cardVerdict: MaterialCardView,
    val iconVerdict: ImageView,
    val textVerdict: TextView,
    val textVerdictExplanation: TextView,
    val textVerdictHomeRoutedRoamingNote: TextView,
    val btnVerdictDetails: MaterialButton,
    val verdictDetailsDivider: View,
    val verdictDetailsContent: LinearLayout,
    val verdictHero: MaterialCardView,
    val verdictAvatar: View,
    val verdictAvatarIcon: ImageView,
    val verdictLabel: TextView,
    val verdictTitle: TextView,
    val verdictSubtitle: TextView,
    val verdictHomeRoutedRoamingNote: TextView,
    val whitelistWarningBanner: View,
)

/**
 * Renders the final verdict card (status, narrative, expandable details) and
 * the verdict hero states. Moved verbatim from MainActivity; owns the
 * details-expanded toggle state that previously lived in the activity.
 */
internal class VerdictRenderer(
    env: MainRenderEnvironment,
    private val findingViews: FindingViewFactory,
) : SectionRenderer(env) {

    private var isVerdictDetailsExpanded = false

    fun displayVerdict(result: CheckResult, views: VerdictViews, privacyMode: Boolean) = with(views) {
        cardVerdict.visibility = View.VISIBLE
        isVerdictDetailsExpanded = false

        when (result.verdict) {
            Verdict.NOT_DETECTED -> {
                val visual = statusVisual(StatusSemantic.CLEAN)
                iconVerdict.setImageResource(visual.iconRes)
                iconVerdict.imageTintList = ColorStateList.valueOf(visual.accentColor)
                textVerdict.text = getString(R.string.main_verdict_not_detected)
                textVerdict.setTextColor(visual.accentColor)
                cardVerdict.setCardBackgroundColor(visual.containerColor)
            }
            Verdict.NEEDS_REVIEW -> {
                val visual = statusVisual(StatusSemantic.REVIEW)
                iconVerdict.setImageResource(visual.iconRes)
                iconVerdict.imageTintList = ColorStateList.valueOf(visual.accentColor)
                textVerdict.text = getString(R.string.main_verdict_needs_review)
                textVerdict.setTextColor(visual.accentColor)
                cardVerdict.setCardBackgroundColor(visual.containerColor)
            }
            Verdict.DETECTED -> {
                val visual = statusVisual(StatusSemantic.DETECTED)
                iconVerdict.setImageResource(visual.iconRes)
                iconVerdict.imageTintList = ColorStateList.valueOf(visual.accentColor)
                textVerdict.text = getString(R.string.main_verdict_detected)
                textVerdict.setTextColor(visual.accentColor)
                cardVerdict.setCardBackgroundColor(visual.containerColor)
            }
        }

        bindVerdictNarrative(views, VerdictNarrativeBuilder.build(env.context, result, privacyMode))
        bindWhitelistWarningBanner(views, result.operatorWhitelistProbe?.whitelistDetected == true)
    }

    fun bindVerdictHeroIdle(views: VerdictViews) = with(views) {
        val visual = statusVisual(StatusSemantic.NEUTRAL)
        applyVerdictHeroColors(views, visual)
        verdictAvatarIcon.setImageResource(visual.iconRes)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(R.string.verdict_title_idle)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_idle)
        bindHomeRoutedRoamingNote(views, null)
        bindWhitelistWarningBanner(views, false)
    }

    fun bindVerdictHeroRunning(views: VerdictViews) = with(views) {
        val visual = statusVisual(StatusSemantic.NEUTRAL)
        applyVerdictHeroColors(views, visual)
        verdictAvatarIcon.setImageResource(visual.iconRes)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(R.string.verdict_title_idle)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_running)
        bindHomeRoutedRoamingNote(views, null)
        bindWhitelistWarningBanner(views, false)
    }

    fun bindVerdictHero(views: VerdictViews, result: CheckResult, tileCount: Int) = with(views) {
        val (semantic, titleRes) = when (result.verdict) {
            Verdict.NOT_DETECTED -> StatusSemantic.CLEAN to R.string.verdict_title_clean
            Verdict.NEEDS_REVIEW -> StatusSemantic.REVIEW to R.string.verdict_title_review
            Verdict.DETECTED -> StatusSemantic.DETECTED to R.string.verdict_title_detected
        }
        val visual = statusVisual(semantic)
        applyVerdictHeroColors(views, visual)
        verdictAvatarIcon.setImageResource(visual.iconRes)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(titleRes)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_done, tileCount)
        bindWhitelistWarningBanner(views, result.operatorWhitelistProbe?.whitelistDetected == true)
    }

    fun clearVerdictCard(views: VerdictViews) = with(views) {
        isVerdictDetailsExpanded = false
        textVerdict.text = ""
        textVerdictExplanation.text = ""
        textVerdictExplanation.visibility = View.GONE
        bindHomeRoutedRoamingNote(views, null)
        bindWhitelistWarningBanner(views, false)
        verdictDetailsDivider.visibility = View.GONE
        btnVerdictDetails.visibility = View.GONE
        btnVerdictDetails.text = getString(R.string.main_verdict_details)
        verdictDetailsContent.removeAllViews()
        verdictDetailsContent.visibility = View.GONE
    }

    fun toggleVerdictDetails(views: VerdictViews, animateContentReveal: (View) -> Unit) = with(views) {
        if (btnVerdictDetails.visibility != View.VISIBLE) return@with
        isVerdictDetailsExpanded = !isVerdictDetailsExpanded
        verdictDetailsContent.visibility = if (isVerdictDetailsExpanded) View.VISIBLE else View.GONE
        updateVerdictDetailsButton(views)
        if (isVerdictDetailsExpanded) {
            animateContentReveal(verdictDetailsContent)
        }
    }

    private fun bindWhitelistWarningBanner(views: VerdictViews, show: Boolean) {
        views.whitelistWarningBanner.visibility = if (show) View.VISIBLE else View.GONE
    }

    private fun bindVerdictNarrative(views: VerdictViews, narrative: VerdictNarrative) = with(views) {
        textVerdictExplanation.text = narrative.explanation
        textVerdictExplanation.visibility = View.VISIBLE

        bindHomeRoutedRoamingNote(views, narrative.homeRoutedRoamingNote)

        verdictDetailsContent.removeAllViews()
        addVerdictSection(
            views,
            title = getString(R.string.main_verdict_section_meaning),
            content = narrative.meaningRows.map(::createVerdictBulletView),
        )
        addVerdictSection(
            views,
            title = getString(R.string.main_verdict_section_discovered),
            content = narrative.discoveredRows.map(::createVerdictRowView),
        )
        addVerdictSection(
            views,
            title = getString(R.string.main_verdict_section_reasons),
            content = narrative.reasonRows.map(::createVerdictBulletView),
        )

        val hasDetails = verdictDetailsContent.isNotEmpty()
        verdictDetailsDivider.visibility = if (hasDetails) View.VISIBLE else View.GONE
        btnVerdictDetails.visibility = if (hasDetails) View.VISIBLE else View.GONE
        verdictDetailsContent.visibility = if (hasDetails && isVerdictDetailsExpanded) View.VISIBLE else View.GONE
        updateVerdictDetailsButton(views)
    }

    private fun bindHomeRoutedRoamingNote(views: VerdictViews, note: String?) = with(views) {
        if (note != null) {
            textVerdictHomeRoutedRoamingNote.text = note
            textVerdictHomeRoutedRoamingNote.visibility = View.VISIBLE
            textVerdictHomeRoutedRoamingNote.setTextColor(onSurfaceColor())
            textVerdictHomeRoutedRoamingNote.setBackgroundResource(
                R.drawable.bg_verdict_home_routed_roaming_note,
            )
            verdictHomeRoutedRoamingNote.text = note
            verdictHomeRoutedRoamingNote.visibility = View.VISIBLE
        } else {
            textVerdictHomeRoutedRoamingNote.text = ""
            textVerdictHomeRoutedRoamingNote.visibility = View.GONE
            verdictHomeRoutedRoamingNote.text = ""
            verdictHomeRoutedRoamingNote.visibility = View.GONE
        }
    }

    private fun addVerdictSection(views: VerdictViews, title: String, content: List<View>) = with(views) {
        if (content.isEmpty()) return@with

        if (verdictDetailsContent.isNotEmpty()) {
            verdictDetailsContent.addView(
                View(themedContext()).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        1.dp,
                    ).apply {
                        topMargin = 12.dp
                        bottomMargin = 12.dp
                    }
                    setBackgroundColor(outlineVariantColor())
                    alpha = 0.7f
                },
            )
        }

        verdictDetailsContent.addView(createVerdictSectionTitleView(title))
        content.forEach { verdictDetailsContent.addView(it) }
    }

    private fun createVerdictSectionTitleView(title: String): View {
        return TextView(themedContext()).apply {
            text = title
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = true
            letterSpacing = 0.05f
            setPadding(0, 0, 0, 6.dp)
            setTextColor(onSurfaceVariantColor())
        }
    }

    private fun createVerdictBulletView(text: String): View {
        val row = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val bullet = TextView(themedContext()).apply {
            this.text = "•"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val body = TextView(themedContext()).apply {
            this.text = text
            textSize = 13f
            setLineSpacing(2.dp.toFloat(), 1f)
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        row.addView(bullet)
        row.addView(body)
        return row
    }

    private fun createVerdictRowView(row: NarrativeRow): View {
        return findingViews.createInfoView(row.label, row.value)
    }

    private fun updateVerdictDetailsButton(views: VerdictViews) = with(views) {
        btnVerdictDetails.text = if (isVerdictDetailsExpanded) getString(R.string.main_verdict_hide_details) else getString(R.string.main_verdict_details)
    }

    private fun applyVerdictHeroColors(views: VerdictViews, visual: StatusVisual) = with(views) {
        verdictHero.setCardBackgroundColor(visual.containerColor)
        verdictTitle.setTextColor(visual.accentColor)
        verdictLabel.setTextColor(visual.accentColor)
        val avatarBg = android.graphics.drawable.GradientDrawable().apply {
            shape = android.graphics.drawable.GradientDrawable.OVAL
            setColor(visual.accentColor)
        }
        verdictAvatar.background = avatarBg
    }
}
