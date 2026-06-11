package com.notcvnt.rknhardering.ui.main.render

import android.content.Context
import android.content.res.ColorStateList
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.AttrRes
import androidx.annotation.ColorRes
import androidx.core.content.ContextCompat
import androidx.core.text.BidiFormatter
import com.google.android.material.color.MaterialColors
import com.notcvnt.rknhardering.ColorVisionMode
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.StatusSemantic
import com.notcvnt.rknhardering.StatusVisual

/**
 * Shared context for the main-screen result renderers: themed context, theme
 * colors, status semantics and RTL helpers, all moved verbatim out of
 * MainActivity. Target views and privacy mode are passed per render call —
 * the environment never holds references to result views.
 *
 * [statusVisual] and [colorVisionMode] stay as lambdas into MainActivity so
 * the activity-side loading/tile code keeps using the same single resolver.
 */
internal class MainRenderEnvironment(
    val context: Context,
    private val anchorView: View,
    val statusVisual: (StatusSemantic) -> StatusVisual,
    val colorVisionMode: () -> ColorVisionMode,
) {

    fun themedContext(): Context = anchorView.context

    fun themeColor(@AttrRes attrRes: Int, @ColorRes fallbackColorRes: Int): Int {
        return MaterialColors.getColor(
            anchorView,
            attrRes,
            ContextCompat.getColor(themedContext(), fallbackColorRes),
        )
    }

    fun surfaceColor(): Int =
        themeColor(com.google.android.material.R.attr.colorSurface, R.color.md_surface)

    fun onSurfaceColor(): Int =
        themeColor(com.google.android.material.R.attr.colorOnSurface, R.color.md_on_surface)

    fun onSurfaceVariantColor(): Int =
        themeColor(
            com.google.android.material.R.attr.colorOnSurfaceVariant,
            R.color.md_on_surface_variant,
        )

    fun outlineVariantColor(): Int =
        themeColor(com.google.android.material.R.attr.colorOutlineVariant, R.color.md_outline_variant)

    fun statusSemantic(
        detected: Boolean,
        needsReview: Boolean,
        hasError: Boolean = false,
    ): StatusSemantic {
        return when {
            hasError -> StatusSemantic.ERROR
            detected -> StatusSemantic.DETECTED
            needsReview -> StatusSemantic.REVIEW
            else -> StatusSemantic.CLEAN
        }
    }

    fun statusColor(status: StatusSemantic): Int = statusVisual(status).accentColor

    fun statusContainerColor(status: StatusSemantic): Int = statusVisual(status).containerColor

    fun bindCardStatus(
        detected: Boolean,
        needsReview: Boolean,
        icon: ImageView,
        status: TextView,
        hasError: Boolean = false,
    ) {
        val visual = statusVisual(statusSemantic(detected, needsReview, hasError))
        icon.setImageResource(visual.iconRes)
        icon.imageTintList = ColorStateList.valueOf(visual.accentColor)
        status.setText(visual.labelRes)
        status.setTextColor(visual.accentColor)
    }

    fun isRtlLayout(): Boolean =
        context.resources.configuration.layoutDirection == View.LAYOUT_DIRECTION_RTL

    fun wrapForDisplay(text: String): String {
        return if (isRtlLayout()) {
            BidiFormatter.getInstance(true).unicodeWrap(text)
        } else {
            text
        }
    }
}
