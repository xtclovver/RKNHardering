package com.notcvnt.rknhardering.customcheck.ui.editor

import android.view.View
import androidx.annotation.DrawableRes
import androidx.annotation.LayoutRes
import androidx.annotation.StringRes
import androidx.lifecycle.LifecycleCoroutineScope
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile

/**
 * One checker section of the custom-check editor: knows how to load its slice
 * of the profile into the section body views ([bind]), read it back
 * ([collect]) and render the collapsed summary line ([summary]).
 *
 * [collect] must reproduce the exact legacy defaults for absent/invalid input
 * (every `?:` fallback) — the round-trip and defaults tests pin them.
 */
internal abstract class SectionBinder<C>(protected val host: Host) {

    /** The slice of the editor fragment the binders are allowed to touch. */
    interface Host {
        val lifecycleScope: LifecycleCoroutineScope
        fun string(@StringRes res: Int, vararg args: Any): String
        fun refreshSummary(sectionId: String)
    }

    abstract val sectionId: String

    @get:StringRes
    abstract val titleRes: Int

    @get:DrawableRes
    abstract val iconRes: Int

    @get:LayoutRes
    abstract val bodyLayout: Int

    /**
     * Legacy fallback for the master-switch state when the section controller
     * is unavailable at save time (the original saveAndExit `?:` defaults).
     */
    open val enabledFallback: Boolean = true

    /** Populates the inflated body from the profile. */
    abstract fun bind(body: View, profile: CustomCheckProfile)

    /**
     * Reconstructs this section's config slice from the body views.
     * [body] is null when the section body is unavailable; the legacy defaults
     * apply. [enabled] is the master-switch state.
     */
    abstract fun collect(body: View?, enabled: Boolean): C

    /** Collapsed-state summary, or null to keep the controller's default. */
    open fun summary(body: View): String? = null

    protected fun refreshOwnSummary() = host.refreshSummary(sectionId)
}
