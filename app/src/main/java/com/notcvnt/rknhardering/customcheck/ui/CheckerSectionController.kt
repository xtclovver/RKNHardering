package com.notcvnt.rknhardering.customcheck.ui

import android.animation.ObjectAnimator
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.transition.AutoTransition
import androidx.transition.TransitionManager
import com.google.android.material.materialswitch.MaterialSwitch
import com.notcvnt.rknhardering.R

/**
 * Controller for an inflated view_checker_section.xml instance.
 *
 * Handles the multi-open accordion behavior, master toggle greyout, chevron rotation,
 * background swap (collapsed/expanded), summary text, and disabled note.
 *
 * Each section is identified by [id] (one of [GEO_IP], [IP_COMPARISON], ...) so that
 * open/disabled state can be persisted across configuration changes.
 */
internal class CheckerSectionController(
    val root: View,
    val id: String,
    private val sectionsContainer: ViewGroup,
) {
    val header: View = root.findViewById(R.id.sectionHeader)
    val statusDot: View = root.findViewById(R.id.sectionStatusDot)
    val iconContainer: View = root.findViewById(R.id.sectionIconContainer)
    val icon: ImageView = root.findViewById(R.id.sectionIcon)
    val titleView: TextView = root.findViewById(R.id.sectionTitle)
    val summaryView: TextView = root.findViewById(R.id.sectionSummary)
    val masterSwitch: MaterialSwitch = root.findViewById(R.id.sectionMasterSwitch)
    val chevron: ImageView = root.findViewById(R.id.sectionChevron)
    val divider: View = root.findViewById(R.id.sectionDivider)
    val body: FrameLayout = root.findViewById(R.id.sectionBody)
    val disabledNote: TextView = root.findViewById(R.id.sectionDisabledNote)

    var summaryProvider: () -> String = { "" }
    var onMasterChanged: ((Boolean) -> Unit)? = null

    private var expanded: Boolean = false
    private var enabled: Boolean = true

    init {
        header.setOnClickListener { toggle() }
        masterSwitch.setOnCheckedChangeListener { _, checked ->
            setEnabled(checked, propagate = true)
        }
    }

    fun setTitle(text: CharSequence) {
        titleView.text = text
    }

    fun setIcon(iconRes: Int) {
        icon.setImageResource(iconRes)
    }

    fun setExpanded(value: Boolean, animate: Boolean = true) {
        if (expanded == value) return
        expanded = value
        if (animate) {
            TransitionManager.beginDelayedTransition(
                sectionsContainer,
                AutoTransition().apply { duration = 180 },
            )
        }
        body.visibility = if (value) View.VISIBLE else View.GONE
        divider.visibility = if (value) View.VISIBLE else View.GONE
        root.setBackgroundResource(
            if (value) R.drawable.bg_checker_section_expanded
            else R.drawable.bg_checker_section_collapsed
        )
        val angle = if (value) 90f else 0f
        ObjectAnimator.ofFloat(chevron, View.ROTATION, chevron.rotation, angle)
            .setDuration(if (animate) 150L else 0L)
            .start()
        updateNoteVisibility()
    }

    fun isExpanded(): Boolean = expanded

    fun setEnabled(value: Boolean, propagate: Boolean) {
        enabled = value
        masterSwitch.setOnCheckedChangeListener(null)
        masterSwitch.isChecked = value
        masterSwitch.setOnCheckedChangeListener { _, checked ->
            setEnabled(checked, propagate = true)
        }
        body.alpha = if (value) 1f else 0.35f
        setSubtreeEnabled(body, value)
        statusDot.setBackgroundResource(
            if (value) R.drawable.dot_status_green
            else R.drawable.dot_status_neutral
        )
        refreshSummary()
        updateNoteVisibility()
        if (propagate) {
            onMasterChanged?.invoke(value)
        }
    }

    fun isMasterEnabled(): Boolean = enabled

    fun refreshSummary() {
        summaryView.text = if (enabled) summaryProvider() else summaryView.context.getString(R.string.checker_section_summary_disabled)
    }

    private fun toggle() {
        setExpanded(!expanded, animate = true)
    }

    private fun updateNoteVisibility() {
        disabledNote.visibility = if (expanded && !enabled) View.VISIBLE else View.GONE
    }

    private fun setSubtreeEnabled(view: View, value: Boolean) {
        view.isEnabled = value
        if (view is ViewGroup) {
            for (i in 0 until view.childCount) {
                setSubtreeEnabled(view.getChildAt(i), value)
            }
        }
    }

    companion object {
        const val GEO_IP = "geo_ip"
        const val IP_COMPARISON = "ip_comparison"
        const val CDN_PULLING = "cdn_pulling"
        const val DIRECT_SIGNS = "direct_signs"
        const val INDIRECT_SIGNS = "indirect_signs"
        const val NATIVE_SIGNS = "native_signs"
        const val LOCATION_SIGNALS = "location_signals"
        const val ICMP_SPOOFING = "icmp_spoofing"
        const val RTT_TRIANGULATION = "rtt_triangulation"
        const val CALL_TRANSPORT = "call_transport"
        const val SPLIT_TUNNEL = "split_tunnel"
        const val DOMAIN_REACHABILITY = "domain_reachability"
    }
}
