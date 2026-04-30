package com.notcvnt.rknhardering

import android.content.Context
import android.graphics.drawable.Drawable
import androidx.annotation.ColorInt
import androidx.annotation.ColorRes
import androidx.annotation.StringRes
import androidx.core.content.ContextCompat

internal enum class StatusSemantic {
    CLEAN,
    REVIEW,
    DETECTED,
    ERROR,
    NEUTRAL,
}

internal data class StatusVisual(
    @param:ColorInt val accentColor: Int,
    @param:ColorInt val containerColor: Int,
    val iconRes: Int,
    @param:StringRes val labelRes: Int,
    val shape: StatusIndicatorShape,
)

internal object StatusVisualResolver {

    fun modeFromPrefs(context: Context): ColorVisionMode {
        return ColorVisionMode.fromPref(
            AppUiSettings.prefs(context).getString(SettingsPrefs.PREF_COLOR_VISION_MODE, null),
        )
    }

    fun resolve(
        context: Context,
        status: StatusSemantic,
        mode: ColorVisionMode = modeFromPrefs(context),
    ): StatusVisual {
        return StatusVisual(
            accentColor = ContextCompat.getColor(context, accentRes(status, mode)),
            containerColor = ContextCompat.getColor(context, containerRes(status, mode)),
            iconRes = iconRes(status),
            labelRes = labelRes(status),
            shape = shape(status),
        )
    }

    fun indicatorDrawable(
        context: Context,
        status: StatusSemantic,
        mode: ColorVisionMode = modeFromPrefs(context),
    ): Drawable {
        val visual = resolve(context, status, mode)
        return StatusShapeDrawable(visual.shape, visual.accentColor)
    }

    private fun shape(status: StatusSemantic): StatusIndicatorShape {
        return when (status) {
            StatusSemantic.CLEAN -> StatusIndicatorShape.CIRCLE
            StatusSemantic.REVIEW -> StatusIndicatorShape.TRIANGLE
            StatusSemantic.DETECTED -> StatusIndicatorShape.DIAMOND
            StatusSemantic.ERROR -> StatusIndicatorShape.SQUARE
            StatusSemantic.NEUTRAL -> StatusIndicatorShape.LINE
        }
    }

    private fun iconRes(status: StatusSemantic): Int {
        return when (status) {
            StatusSemantic.CLEAN -> R.drawable.ic_check_circle
            StatusSemantic.REVIEW -> R.drawable.ic_help
            StatusSemantic.DETECTED -> R.drawable.ic_error
            StatusSemantic.ERROR -> R.drawable.ic_error
            StatusSemantic.NEUTRAL -> R.drawable.ic_minus
        }
    }

    @StringRes
    private fun labelRes(status: StatusSemantic): Int {
        return when (status) {
            StatusSemantic.CLEAN -> R.string.main_card_status_clean
            StatusSemantic.REVIEW -> R.string.main_card_status_needs_review
            StatusSemantic.DETECTED -> R.string.main_card_status_detected
            StatusSemantic.ERROR -> R.string.main_card_status_error
            StatusSemantic.NEUTRAL -> R.string.settings_status_no_data
        }
    }

    @ColorRes
    private fun accentRes(status: StatusSemantic, mode: ColorVisionMode): Int {
        return when (paletteFor(mode)) {
            StatusPalette.STANDARD -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_green
                StatusSemantic.REVIEW -> R.color.status_amber
                StatusSemantic.DETECTED -> R.color.status_red
                StatusSemantic.ERROR -> R.color.status_amber
                StatusSemantic.NEUTRAL -> R.color.status_neutral
            }
            StatusPalette.RED_GREEN_SAFE -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_cvd_clean
                StatusSemantic.REVIEW -> R.color.status_cvd_review
                StatusSemantic.DETECTED -> R.color.status_cvd_detected
                StatusSemantic.ERROR -> R.color.status_cvd_error
                StatusSemantic.NEUTRAL -> R.color.status_neutral
            }
            StatusPalette.TRITAN_SAFE -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_tritan_clean
                StatusSemantic.REVIEW -> R.color.status_tritan_review
                StatusSemantic.DETECTED -> R.color.status_tritan_detected
                StatusSemantic.ERROR -> R.color.status_cvd_error
                StatusSemantic.NEUTRAL -> R.color.status_neutral
            }
            StatusPalette.ACHROMATOPSIA -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_achromatopsia_clean
                StatusSemantic.REVIEW -> R.color.status_achromatopsia_review
                StatusSemantic.DETECTED -> R.color.status_achromatopsia_detected
                StatusSemantic.ERROR -> R.color.status_achromatopsia_error
                StatusSemantic.NEUTRAL -> R.color.status_neutral
            }
        }
    }

    @ColorRes
    private fun containerRes(status: StatusSemantic, mode: ColorVisionMode): Int {
        return when (paletteFor(mode)) {
            StatusPalette.STANDARD -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_green_container
                StatusSemantic.REVIEW -> R.color.status_amber_container
                StatusSemantic.DETECTED -> R.color.status_red_container
                StatusSemantic.ERROR -> R.color.status_amber_container
                StatusSemantic.NEUTRAL -> R.color.status_neutral_container
            }
            StatusPalette.RED_GREEN_SAFE -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_cvd_clean_container
                StatusSemantic.REVIEW -> R.color.status_cvd_review_container
                StatusSemantic.DETECTED -> R.color.status_cvd_detected_container
                StatusSemantic.ERROR -> R.color.status_cvd_error_container
                StatusSemantic.NEUTRAL -> R.color.status_neutral_container
            }
            StatusPalette.TRITAN_SAFE -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_tritan_clean_container
                StatusSemantic.REVIEW -> R.color.status_tritan_review_container
                StatusSemantic.DETECTED -> R.color.status_tritan_detected_container
                StatusSemantic.ERROR -> R.color.status_cvd_error_container
                StatusSemantic.NEUTRAL -> R.color.status_neutral_container
            }
            StatusPalette.ACHROMATOPSIA -> when (status) {
                StatusSemantic.CLEAN -> R.color.status_achromatopsia_clean_container
                StatusSemantic.REVIEW -> R.color.status_achromatopsia_review_container
                StatusSemantic.DETECTED -> R.color.status_achromatopsia_detected_container
                StatusSemantic.ERROR -> R.color.status_achromatopsia_error_container
                StatusSemantic.NEUTRAL -> R.color.status_neutral_container
            }
        }
    }

    private fun paletteFor(mode: ColorVisionMode): StatusPalette {
        return when (mode) {
            ColorVisionMode.OFF -> StatusPalette.STANDARD
            ColorVisionMode.RED_GREEN -> StatusPalette.RED_GREEN_SAFE
            ColorVisionMode.BLUE_YELLOW -> StatusPalette.TRITAN_SAFE
            ColorVisionMode.ACHROMATOPSIA -> StatusPalette.ACHROMATOPSIA
        }
    }

    private enum class StatusPalette {
        STANDARD,
        RED_GREEN_SAFE,
        TRITAN_SAFE,
        ACHROMATOPSIA,
    }
}
