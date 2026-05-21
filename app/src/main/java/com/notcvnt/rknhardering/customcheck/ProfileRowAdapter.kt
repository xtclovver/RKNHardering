package com.notcvnt.rknhardering.customcheck

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.PopupMenu
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.R

internal class ProfileRowAdapter(
    private val onActivate: (CustomCheckProfile) -> Unit,
    private val onEdit: (CustomCheckProfile) -> Unit,
    private val onClone: (CustomCheckProfile) -> Unit,
    private val onExport: (CustomCheckProfile) -> Unit,
    private val onDelete: (CustomCheckProfile) -> Unit,
) : ListAdapter<ProfileRowAdapter.Item, ProfileRowAdapter.ViewHolder>(DIFF) {

    data class Item(
        val profile: CustomCheckProfile,
        val isActive: Boolean,
        val isBuiltin: Boolean = false,
        val checkersEnabledCount: Int = 0,
        val checkersTotalCount: Int = TOTAL_CHECKERS,
    )

    companion object {
        private const val MENU_EDIT = 1
        private const val MENU_CLONE = 2
        private const val MENU_EXPORT = 3
        private const val MENU_DELETE = 4

        private val DIFF = object : DiffUtil.ItemCallback<Item>() {
            override fun areItemsTheSame(a: Item, b: Item) = a.profile.id == b.profile.id
            override fun areContentsTheSame(a: Item, b: Item) = a == b
        }

        fun countEnabledCheckers(profile: CustomCheckProfile): Int {
            val c = profile.checksConfig
            var n = 0
            if (c.geoIp.enabled) n++
            if (c.ipComparison.enabled) n++
            if (c.cdnPulling.enabled) n++
            if (c.directSigns.enabled) n++
            if (c.indirectSigns.enabled) n++
            if (c.nativeSigns.enabled) n++
            if (c.locationSignals.enabled) n++
            if (c.icmpSpoofing.enabled) n++
            if (c.rttTriangulation.enabled) n++
            if (c.callTransport.enabled) n++
            if (c.splitTunnel.enabled) n++
            if (c.domainReachabilityEnabled) n++
            return n
        }

        const val TOTAL_CHECKERS = 12
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.view_profile_row, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

        private val card: MaterialCardView = itemView as MaterialCardView
        private val avatarContainer: View = itemView.findViewById(R.id.avatarContainer)
        private val avatarIcon: ImageView = itemView.findViewById(R.id.avatarIcon)
        private val avatarText: TextView = itemView.findViewById(R.id.avatarText)
        private val textName: TextView = itemView.findViewById(R.id.textProfileName)
        private val textSubtitle: TextView = itemView.findViewById(R.id.textProfileSubtitle)
        private val installedMarker: ImageView = itemView.findViewById(R.id.installedMarker)
        private val radioContainer: View = itemView.findViewById(R.id.radioContainer)
        private val radioCheck: View = itemView.findViewById(R.id.radioCheck)
        private val btnMenu: ImageView = itemView.findViewById(R.id.btnMenu)

        fun bind(item: Item) {
            val profile = item.profile
            val ctx = itemView.context

            textName.text = profile.name

            // Avatar
            if (item.isBuiltin) {
                avatarContainer.setBackgroundResource(R.drawable.bg_profile_avatar_builtin)
                avatarIcon.visibility = View.VISIBLE
                avatarText.visibility = View.GONE
            } else {
                avatarIcon.visibility = View.GONE
                avatarText.visibility = View.VISIBLE
                val initials = profile.name.trim().take(1).uppercase().ifBlank { "?" }
                avatarText.text = initials
                avatarContainer.background = makeAvatarGradient(profile.name)
            }

            // Installed marker (from marketplace): blue for official, grey for verified, hidden otherwise
            val mp = profile.marketplaceInfo
            when {
                mp?.official == true -> {
                    installedMarker.visibility = View.VISIBLE
                    installedMarker.setImageResource(R.drawable.ic_verified_blue)
                }
                mp?.verified == true -> {
                    installedMarker.visibility = View.VISIBLE
                    installedMarker.setImageResource(R.drawable.ic_verified_grey)
                }
                else -> installedMarker.visibility = View.GONE
            }

            // Subtitle: "11 checkers · all enabled" / "v1.0.0 · 8 checkers · from marketplace"
            textSubtitle.text = buildSubtitle(item)

            // Active border
            val density = ctx.resources.displayMetrics.density
            card.strokeWidth = (1.5f * density).toInt()
            if (item.isActive) {
                card.strokeColor = resolveAttrColor(ctx, com.google.android.material.R.attr.colorPrimary)
                radioContainer.setBackgroundResource(R.drawable.bg_radio_circle_active)
                radioCheck.visibility = View.VISIBLE
            } else {
                card.strokeColor = Color.TRANSPARENT
                radioContainer.setBackgroundResource(R.drawable.bg_radio_circle_inactive)
                radioCheck.visibility = View.GONE
            }

            // Tap activates
            card.setOnClickListener {
                if (!item.isActive) onActivate(profile)
            }

            // Overflow menu — only for custom (non-builtin) profiles
            if (item.isBuiltin) {
                btnMenu.visibility = View.GONE
            } else {
                btnMenu.visibility = View.VISIBLE
                btnMenu.setOnClickListener { v ->
                    val popup = PopupMenu(v.context, v)
                    popup.menu.add(0, MENU_EDIT, 0, v.context.getString(R.string.action_edit))
                    popup.menu.add(0, MENU_CLONE, 1, v.context.getString(R.string.action_clone))
                    popup.menu.add(0, MENU_EXPORT, 2, v.context.getString(R.string.action_export))
                    popup.menu.add(0, MENU_DELETE, 3, v.context.getString(R.string.action_delete))
                    popup.setOnMenuItemClickListener { menuItem ->
                        when (menuItem.itemId) {
                            MENU_EDIT -> onEdit(profile)
                            MENU_CLONE -> onClone(profile)
                            MENU_EXPORT -> onExport(profile)
                            MENU_DELETE -> onDelete(profile)
                        }
                        true
                    }
                    popup.show()
                }
            }
        }

        private fun buildSubtitle(item: Item): String {
            val profile = item.profile
            val parts = mutableListOf<String>()
            if (profile.version.isNotBlank() && profile.version != "1.0.0") {
                parts.add("v${profile.version}")
            }
            val total = item.checkersTotalCount
            val enabled = item.checkersEnabledCount
            if (enabled == total) {
                parts.add(itemView.context.getString(R.string.profile_subtitle_all_enabled, total))
            } else {
                parts.add(itemView.context.getString(R.string.profile_subtitle_enabled_of, enabled, total))
            }
            if (profile.marketplaceInfo != null) {
                parts.add(itemView.context.getString(R.string.profile_subtitle_from_marketplace))
            }
            return parts.joinToString(" · ")
        }
    }

    private fun makeAvatarGradient(name: String): GradientDrawable {
        val seed = name.firstOrNull()?.code ?: 0
        val hue1 = ((seed * 37) % 360).toFloat()
        val hue2 = ((hue1 + 40f) % 360f)
        val c1 = Color.HSVToColor(floatArrayOf(hue1, 0.50f, 0.64f))
        val c2 = Color.HSVToColor(floatArrayOf(hue2, 0.45f, 0.48f))
        val density = android.content.res.Resources.getSystem().displayMetrics.density
        return GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(c1, c2),
        ).apply {
            cornerRadius = 12f * density
            shape = GradientDrawable.RECTANGLE
        }
    }

    private fun resolveAttrColor(ctx: android.content.Context, attr: Int): Int {
        val arr = ctx.obtainStyledAttributes(intArrayOf(attr))
        val color = arr.getColor(0, Color.TRANSPARENT)
        arr.recycle()
        return color
    }

}
