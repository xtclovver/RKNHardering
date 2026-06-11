package com.notcvnt.rknhardering.customcheck.ui.editor

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.customcheck.EndpointScope

internal data class EndpointPillData(
    val name: String,
    val url: String,
    val scope: EndpointScope?,
    val onRemove: () -> Unit,
    val onEdit: (() -> Unit)? = null,
)

/** Renders the removable endpoint "pill" rows used by the editor sections. */
internal object EndpointPills {

    fun rebuild(container: LinearLayout, items: List<EndpointPillData>) {
        container.removeAllViews()
        items.forEach { data ->
            container.addView(makePillView(container, data))
        }
    }

    fun makePillView(parent: ViewGroup, data: EndpointPillData): View {
        val ctx = parent.context
        val density = ctx.resources.displayMetrics.density
        val pill = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            background = androidx.core.content.ContextCompat.getDrawable(ctx, R.drawable.bg_endpoint_pill)
            setPadding((10 * density).toInt(), (8 * density).toInt(), (10 * density).toInt(), (8 * density).toInt())
            val lp = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            lp.bottomMargin = (4 * density).toInt()
            layoutParams = lp
            gravity = android.view.Gravity.CENTER_VERTICAL
        }
        val dot = View(ctx).apply {
            setBackgroundResource(R.drawable.dot_status_green)
            layoutParams = LinearLayout.LayoutParams((4 * density).toInt(), (4 * density).toInt())
        }
        pill.addView(dot)

        val texts = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            val lp = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            lp.marginStart = (8 * density).toInt()
            layoutParams = lp
        }
        val name = TextView(ctx).apply {
            text = data.name
            textSize = 12f
            setTextColor(androidx.core.content.ContextCompat.getColor(ctx, R.color.md_on_surface))
        }
        val url = TextView(ctx).apply {
            text = data.url
            textSize = 10f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextColor(androidx.core.content.ContextCompat.getColor(ctx, R.color.md_on_surface_variant))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        texts.addView(name)
        texts.addView(url)
        pill.addView(texts)

        if (data.onEdit != null) {
            // Make the pill body (dot + texts) clickable for editing
            pill.isClickable = true
            pill.isFocusable = true
            pill.setOnClickListener { data.onEdit.invoke() }
        }

        if (data.scope != null) {
            val scopeView = TextView(ctx).apply {
                text = if (data.scope == EndpointScope.NON_RU) "NON_RU" else "RU"
                textSize = 9f
                setPadding((6 * density).toInt(), (2 * density).toInt(), (6 * density).toInt(), (2 * density).toInt())
                setBackgroundResource(R.drawable.bg_endpoint_pill)
                setTextColor(androidx.core.content.ContextCompat.getColor(ctx, R.color.md_on_surface_variant))
            }
            val lp = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            lp.marginStart = (6 * density).toInt()
            scopeView.layoutParams = lp
            pill.addView(scopeView)
        }

        val remove = TextView(ctx).apply {
            text = "✕"
            textSize = 14f
            setPadding((8 * density).toInt(), 0, (4 * density).toInt(), 0)
            setTextColor(androidx.core.content.ContextCompat.getColor(ctx, R.color.md_on_surface_variant))
            isClickable = true
            isFocusable = true
            setOnClickListener { data.onRemove() }
        }
        pill.addView(remove)

        return pill
    }
}
