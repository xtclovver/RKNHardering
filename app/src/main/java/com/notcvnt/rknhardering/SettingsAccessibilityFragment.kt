package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import com.google.android.material.chip.ChipGroup

internal class SettingsAccessibilityFragment : Fragment(R.layout.fragment_settings_accessibility) {

    private lateinit var prefs: SharedPreferences
    private lateinit var chipGroupColorVision: ChipGroup

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        chipGroupColorVision = view.findViewById(R.id.chipGroupColorVision)
        loadSettings(view)
        setupListeners(view)
    }

    private fun loadSettings(root: View) {
        val mode = currentMode()
        chipGroupColorVision.check(chipIdForMode(mode))
        renderPreview(root, mode)
    }

    private fun setupListeners(root: View) {
        chipGroupColorVision.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val mode = modeForChipId(checkedIds.first())
            prefs.edit { putString(SettingsPrefs.PREF_COLOR_VISION_MODE, mode.prefValue) }
            renderPreview(root, mode)
        }
    }

    private fun currentMode(): ColorVisionMode {
        return ColorVisionMode.fromPref(
            prefs.getString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.OFF.prefValue),
        )
    }

    private fun renderPreview(root: View, mode: ColorVisionMode) {
        renderPreviewStatus(
            root,
            StatusSemantic.CLEAN,
            R.id.previewStatusCleanRow,
            R.id.previewStatusCleanIndicator,
            R.id.previewStatusCleanText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.REVIEW,
            R.id.previewStatusReviewRow,
            R.id.previewStatusReviewIndicator,
            R.id.previewStatusReviewText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.DETECTED,
            R.id.previewStatusDetectedRow,
            R.id.previewStatusDetectedIndicator,
            R.id.previewStatusDetectedText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.ERROR,
            R.id.previewStatusErrorRow,
            R.id.previewStatusErrorIndicator,
            R.id.previewStatusErrorText,
            mode,
        )
        renderPreviewStatus(
            root,
            StatusSemantic.NEUTRAL,
            R.id.previewStatusNeutralRow,
            R.id.previewStatusNeutralIndicator,
            R.id.previewStatusNeutralText,
            mode,
        )
    }

    private fun renderPreviewStatus(
        root: View,
        status: StatusSemantic,
        rowId: Int,
        indicatorId: Int,
        textId: Int,
        mode: ColorVisionMode,
    ) {
        val visual = StatusVisualResolver.resolve(requireContext(), status, mode)
        val label = getString(visual.labelRes)
        root.findViewById<View>(indicatorId).background =
            StatusVisualResolver.indicatorDrawable(requireContext(), status, mode)
        root.findViewById<TextView>(textId).apply {
            text = label
            setTextColor(visual.accentColor)
        }
        root.findViewById<View>(rowId).contentDescription =
            getString(R.string.settings_accessibility_status_preview_content, label)
    }

    private fun chipIdForMode(mode: ColorVisionMode): Int {
        return when (mode) {
            ColorVisionMode.OFF -> R.id.chipColorVisionOff
            ColorVisionMode.RED_GREEN -> R.id.chipColorVisionRedGreen
            ColorVisionMode.BLUE_YELLOW -> R.id.chipColorVisionBlueYellow
            ColorVisionMode.ACHROMATOPSIA -> R.id.chipColorVisionAchromatopsia
        }
    }

    private fun modeForChipId(chipId: Int): ColorVisionMode {
        return when (chipId) {
            R.id.chipColorVisionRedGreen -> ColorVisionMode.RED_GREEN
            R.id.chipColorVisionBlueYellow -> ColorVisionMode.BLUE_YELLOW
            R.id.chipColorVisionAchromatopsia -> ColorVisionMode.ACHROMATOPSIA
            else -> ColorVisionMode.OFF
        }
    }
}
