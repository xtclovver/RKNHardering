package com.notcvnt.rknhardering.ui.main.render

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.diagnostics.DiagnosticEntry
import java.util.Locale

internal class TechnicalDataRenderer(
    private val env: MainRenderEnvironment,
) {
    private val roots = mutableListOf<View>()

    fun render(body: ViewGroup, entries: List<DiagnosticEntry>, runTruncated: Boolean = false) {
        val content = LinearLayout(env.context).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        val toggle = MaterialButton(
            env.context,
            null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle,
        ).apply {
            setText(R.string.technical_data_title)
            gravity = Gravity.START or Gravity.CENTER_VERTICAL
            contentDescription = env.context.getString(R.string.technical_data_expand_content_description)
            setOnClickListener {
                val expanding = content.visibility != View.VISIBLE
                if (expanding && content.childCount == 0) {
                    buildContent(content, entries, runTruncated)
                }
                content.visibility = if (expanding) View.VISIBLE else View.GONE
                this.contentDescription = env.context.getString(
                    if (expanding) {
                        R.string.technical_data_collapse_content_description
                    } else {
                        R.string.technical_data_expand_content_description
                    },
                )
            }
        }
        val root = LinearLayout(env.context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 12.dp, 0, 0)
            addView(toggle, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(content, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        body.addView(root)
        roots += root
    }

    fun clear() {
        roots.forEach { root -> (root.parent as? ViewGroup)?.removeView(root) }
        roots.clear()
    }

    private fun buildContent(
        container: LinearLayout,
        entries: List<DiagnosticEntry>,
        runTruncated: Boolean,
    ) {
        if (runTruncated) {
            container.addView(text(env.context.getString(R.string.technical_data_run_truncated), bold = true))
        }
        if (entries.isEmpty()) {
            container.addView(text(env.context.getString(R.string.technical_data_empty)))
            return
        }
        entries.forEach { entry -> container.addView(entryView(entry)) }
    }

    private fun entryView(entry: DiagnosticEntry): View {
        val metadata = buildMetadata(entry)
        val copiedBlock = buildString {
            appendLine(metadata)
            append(entry.body)
        }
        return LinearLayout(env.context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 10.dp, 0, 8.dp)
            addView(text(entry.source, bold = true))
            addView(text(metadata, secondary = true))
            addView(TextView(env.context).apply {
                text = entry.body.ifBlank { env.context.getString(R.string.technical_data_empty_body) }
                typeface = Typeface.MONOSPACE
                textSize = 12f
                setTextColor(env.onSurfaceColor())
                setTextIsSelectable(true)
                layoutDirection = View.LAYOUT_DIRECTION_LTR
                textDirection = View.TEXT_DIRECTION_LTR
                gravity = Gravity.START
                setHorizontallyScrolling(false)
                setPadding(0, 8.dp, 0, 4.dp)
            })
            addView(MaterialButton(env.context).apply {
                setText(R.string.technical_data_copy_block)
                contentDescription = env.context.getString(
                    R.string.technical_data_copy_block_content_description,
                    entry.source,
                )
                setOnClickListener { copyBlock(copiedBlock) }
            })
        }
    }

    private fun buildMetadata(entry: DiagnosticEntry): String = buildString {
        append(env.context.getString(R.string.technical_data_source, entry.source))
        entry.target?.takeIf { it.isNotBlank() }?.let {
            appendLine()
            append(env.context.getString(R.string.technical_data_target, it))
        }
        appendLine()
        append(env.context.getString(R.string.technical_data_status, entry.status))
        entry.durationMs?.let {
            appendLine()
            append(env.context.getString(R.string.technical_data_duration, it))
        }
        appendLine()
        append(env.context.getString(R.string.technical_data_size, formatBytes(entry.storedBytes)))
        if (entry.truncated) {
            appendLine()
            append(env.context.getString(R.string.technical_data_truncated, formatBytes(entry.originalBytes)))
        }
    }

    private fun copyBlock(value: String) {
        val clipboard = env.context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(env.context.getString(R.string.technical_data_title), value))
        Toast.makeText(env.context, R.string.technical_data_copied, Toast.LENGTH_SHORT).show()
    }

    private fun formatBytes(bytes: Int): String = when {
        bytes < 1024 -> env.context.getString(R.string.technical_data_bytes, bytes)
        else -> String.format(Locale.ROOT, "%.1f KiB", bytes / 1024.0)
    }

    private fun text(value: String, bold: Boolean = false, secondary: Boolean = false): TextView =
        TextView(env.context).apply {
            text = value
            textSize = if (bold) 14f else 12f
            typeface = if (bold) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
            setTextColor(if (secondary) env.onSurfaceVariantColor() else env.onSurfaceColor())
            setLineSpacing(0f, 1.06f)
        }

    private val Int.dp: Int
        get() = (this * env.context.resources.displayMetrics.density).toInt()
}
