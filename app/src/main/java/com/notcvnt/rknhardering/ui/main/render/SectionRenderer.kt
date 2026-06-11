package com.notcvnt.rknhardering.ui.main.render

import android.content.Context
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.StringRes
import com.notcvnt.rknhardering.ColorVisionMode
import com.notcvnt.rknhardering.StatusSemantic
import com.notcvnt.rknhardering.StatusVisual

/**
 * Base class for the per-section result renderers. Mirrors the helper
 * surface the rendering methods used while they lived in MainActivity
 * (themedContext()/getString()/dp/status helpers), so their bodies could be
 * moved verbatim.
 */
internal abstract class SectionRenderer(
    protected val env: MainRenderEnvironment,
) {

    protected fun themedContext(): Context = env.themedContext()

    protected fun getString(@StringRes resId: Int): String = env.context.getString(resId)

    protected fun getString(@StringRes resId: Int, vararg formatArgs: Any): String =
        env.context.getString(resId, *formatArgs)

    protected val Int.dp: Int
        get() = (this * env.context.resources.displayMetrics.density).toInt()

    protected fun statusVisual(status: StatusSemantic): StatusVisual = env.statusVisual(status)

    protected fun statusSemantic(
        detected: Boolean,
        needsReview: Boolean,
        hasError: Boolean = false,
    ): StatusSemantic = env.statusSemantic(detected, needsReview, hasError)

    protected fun statusColor(status: StatusSemantic): Int = env.statusColor(status)

    protected fun statusContainerColor(status: StatusSemantic): Int =
        env.statusContainerColor(status)

    protected fun colorVisionMode(): ColorVisionMode = env.colorVisionMode()

    protected fun surfaceColor(): Int = env.surfaceColor()

    protected fun onSurfaceColor(): Int = env.onSurfaceColor()

    protected fun onSurfaceVariantColor(): Int = env.onSurfaceVariantColor()

    protected fun outlineVariantColor(): Int = env.outlineVariantColor()

    protected fun isRtlLayout(): Boolean = env.isRtlLayout()

    protected fun wrapForDisplay(text: String): String = env.wrapForDisplay(text)

    protected fun bindCardStatus(
        detected: Boolean,
        needsReview: Boolean,
        icon: ImageView,
        status: TextView,
        hasError: Boolean = false,
    ) = env.bindCardStatus(detected, needsReview, icon, status, hasError)
}
