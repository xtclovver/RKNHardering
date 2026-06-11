package com.notcvnt.rknhardering.ui.main.render

import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.notcvnt.rknhardering.model.BypassResult

/**
 * Renders the bypass-scan card findings. Moved verbatim from MainActivity;
 * card visibility and the bypass progress text stay activity-side because
 * they are shared with the loading flow.
 */
internal class BypassRenderer(
    env: MainRenderEnvironment,
    private val findingViews: FindingViewFactory,
) : SectionRenderer(env) {

    fun render(
        bypass: BypassResult,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout,
        privacyMode: Boolean,
    ) {
        bindCardStatus(bypass.detected, bypass.needsReview, icon, status, hasError = bypass.hasError)

        findingsContainer.removeAllViews()
        findingsContainer.visibility = View.VISIBLE
        for (finding in bypass.findings) {
            findingsContainer.addView(findingViews.createFindingView(finding, privacyMode))
        }
    }
}
