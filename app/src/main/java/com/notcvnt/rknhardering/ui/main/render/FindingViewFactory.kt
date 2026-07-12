package com.notcvnt.rknhardering.ui.main.render

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.NativeSignalCatalog
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.StatusVisualResolver
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.displayDescription
import com.notcvnt.rknhardering.util.maskIpsInText

/**
 * Builds the row views shared by all result sections: finding rows,
 * label/value info rows and loading hints. Moved verbatim from MainActivity;
 * privacy mode is passed per call.
 */
internal class FindingViewFactory(
    env: MainRenderEnvironment,
) : SectionRenderer(env) {

    fun createFindingView(finding: Finding, privacyMode: Boolean = false): View {
        val semantic = statusSemantic(finding.detected, finding.needsReview, finding.isError)
        val visual = statusVisual(semantic)
        val displayDescription = finding.displayDescription()
        val descriptionText = if (privacyMode) maskIpsInText(displayDescription) else displayDescription
        val row = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.TOP
            setPadding(0, 3.dp, 0, 3.dp)
            contentDescription = "${getString(visual.labelRes)}. $descriptionText"
        }

        val indicator = View(themedContext()).apply {
            layoutParams = LinearLayout.LayoutParams(8.dp, 8.dp).apply {
                topMargin = 6.dp
                marginEnd = 8.dp
            }
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            background = StatusVisualResolver.indicatorDrawable(themedContext(), semantic, colorVisionMode())
        }

        val description = TextView(themedContext()).apply {
            text = wrapForDisplay(descriptionText)
            textSize = 13f
            setLineSpacing(0f, 1.45f)
            setTextColor(onSurfaceVariantColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = View.TEXT_ALIGNMENT_VIEW_START
        }

        row.addView(indicator)
        row.addView(description)
        finding.packageName
            ?.takeIf { it.isNotBlank() }
            ?.let { packageName ->
                row.isClickable = true
                row.isFocusable = true
                row.setOnClickListener {
                    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.fromParts("package", packageName, null)
                    }
                    env.context.startActivity(intent)
                }
            }
        return row
    }

    fun createNativeFindingView(finding: Finding, privacyMode: Boolean = false): View {
        val info = NativeSignalCatalog.info(finding.nativeSignalId)
        return LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.TOP
            tag = "native-finding:${info.id.name}"
            addView(
                createFindingView(finding, privacyMode),
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
            )
            addView(
                MaterialButton(
                    themedContext(),
                    null,
                    com.google.android.material.R.attr.borderlessButtonStyle,
                ).apply {
                    text = ""
                    setIconResource(R.drawable.ic_help)
                    iconPadding = 0
                    minHeight = 48.dp
                    minimumHeight = 48.dp
                    minWidth = 48.dp
                    minimumWidth = 48.dp
                    contentDescription = getString(
                        R.string.native_help_open_description,
                        NativeSignalCatalog.title(env.context, finding.nativeSignalId),
                    )
                    setOnClickListener {
                        env.openExternalHelp(NativeSignalCatalog.articleUrl(env.context, finding.nativeSignalId))
                    }
                },
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
    }

    fun createInfoView(label: String, value: String): View {
        val rtl = isRtlLayout()
        val row = LinearLayout(themedContext()).apply {
            orientation = if (rtl) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
            gravity = if (rtl) Gravity.END else Gravity.CENTER_VERTICAL
            setPadding(0, 2.dp, 0, if (rtl) 6.dp else 2.dp)
        }

        val labelView = TextView(themedContext()).apply {
            text = wrapForDisplay(label)
            textSize = 13f
            setTextColor(onSurfaceVariantColor())
            layoutParams = if (rtl) {
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                )
            } else {
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.32f)
            }
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = if (rtl) View.TEXT_ALIGNMENT_VIEW_END else View.TEXT_ALIGNMENT_VIEW_START
        }

        val valueView = TextView(themedContext()).apply {
            text = wrapForDisplay(value)
            textSize = 13f
            setTextColor(onSurfaceColor())
            layoutParams = if (rtl) {
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply {
                    topMargin = 2.dp
                }
            } else {
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.68f)
            }
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = if (rtl) View.TEXT_ALIGNMENT_VIEW_END else View.TEXT_ALIGNMENT_VIEW_START
        }

        row.addView(labelView)
        row.addView(valueView)
        return row
    }

    fun splitInfoFinding(description: String): Pair<String, String>? {
        val separatorIndex = sequenceOf(
            description.indexOf(": "),
            description.indexOf('：'),
            description.indexOf(':'),
        ).filter { it >= 0 }.minOrNull() ?: return null
        val separatorLength = when {
            description.startsWith(": ", separatorIndex) -> 2
            else -> 1
        }
        val label = description.substring(0, separatorIndex).trim()
        val value = description.substring(separatorIndex + separatorLength).trim()
        if (label.isBlank() || value.isBlank()) return null
        return label to value
    }

    fun createLoadingHintView(message: String): View {
        return TextView(themedContext()).apply {
            text = message
            textSize = 13f
            setLineSpacing(2.dp.toFloat(), 1f)
            setPadding(0, 8.dp, 0, 2.dp)
            setTextColor(onSurfaceVariantColor())
        }
    }
}
