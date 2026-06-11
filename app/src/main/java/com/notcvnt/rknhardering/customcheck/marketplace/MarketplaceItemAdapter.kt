package com.notcvnt.rknhardering.customcheck.marketplace

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.R

internal class MarketplaceItemAdapter(
    private val onInstall: (MarketplaceEntry) -> Unit,
    private val onOpenInstalled: (MarketplaceEntry) -> Unit,
    private val onUpdate: (MarketplaceEntry) -> Unit = {},
) : ListAdapter<MarketplaceItemAdapter.Item, MarketplaceItemAdapter.ViewHolder>(DIFF) {

    data class Item(
        val entry: MarketplaceEntry,
        val installed: Boolean,
        val hasUpdate: Boolean = false,
    )

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<Item>() {
            override fun areItemsTheSame(a: Item, b: Item) = a.entry.id == b.entry.id
            override fun areContentsTheSame(a: Item, b: Item) = a == b
        }
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val avatarFrame: View = view.findViewById(R.id.marketplaceAvatar)
        val avatarInitial: TextView = view.findViewById(R.id.textAvatarInitial)
        val textName: TextView = view.findViewById(R.id.textItemName)
        val textAuthor: TextView = view.findViewById(R.id.textItemAuthor)
        val textDescription: TextView = view.findViewById(R.id.textItemDescription)
        val badgeOfficial: TextView = view.findViewById(R.id.badgeOfficial)
        val badgeVerified: TextView = view.findViewById(R.id.badgeVerified)
        val installedMarker: ImageView = view.findViewById(R.id.installedMarker)
        val btnInstall: MaterialButton = view.findViewById(R.id.btnInstall)
        val btnInstalled: MaterialButton = view.findViewById(R.id.btnInstalled)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.view_marketplace_item, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        val entry = item.entry
        val ctx = holder.itemView.context

        holder.avatarInitial.text = entry.name.trim().take(1).uppercase().ifBlank { "?" }
        holder.avatarFrame.background = makeAvatarGradient(ctx, entry)

        holder.textName.text = entry.name

        holder.textAuthor.text = ctx.getString(R.string.marketplace_by_author, entry.author)

        if (entry.description.isNotBlank()) {
            holder.textDescription.text = entry.description
            holder.textDescription.visibility = View.VISIBLE
        } else {
            holder.textDescription.visibility = View.GONE
        }

        if (item.installed) {
            holder.badgeOfficial.visibility = View.GONE
            holder.badgeVerified.visibility = View.GONE
            when {
                entry.official -> {
                    holder.installedMarker.visibility = View.VISIBLE
                    holder.installedMarker.setImageResource(R.drawable.ic_verified_blue)
                }
                entry.verified -> {
                    holder.installedMarker.visibility = View.VISIBLE
                    holder.installedMarker.setImageResource(R.drawable.ic_verified_grey)
                }
                else -> holder.installedMarker.visibility = View.GONE
            }
        } else {
            holder.installedMarker.visibility = View.GONE
            holder.badgeOfficial.visibility = if (entry.official) View.VISIBLE else View.GONE
            holder.badgeVerified.visibility = if (entry.verified && !entry.official) View.VISIBLE else View.GONE
        }

        when {
            item.installed && item.hasUpdate -> {
                holder.btnInstall.visibility = View.VISIBLE
                holder.btnInstalled.visibility = View.GONE
                holder.btnInstall.text = ctx.getString(R.string.marketplace_action_update)
                holder.btnInstall.setOnClickListener { onUpdate(entry) }
            }
            item.installed -> {
                holder.btnInstall.visibility = View.GONE
                holder.btnInstalled.visibility = View.VISIBLE
                holder.btnInstalled.setOnClickListener { onOpenInstalled(entry) }
            }
            else -> {
                holder.btnInstall.visibility = View.VISIBLE
                holder.btnInstalled.visibility = View.GONE
                holder.btnInstall.text = ctx.getString(R.string.marketplace_action_install)
                holder.btnInstall.setOnClickListener { onInstall(entry) }
            }
        }
    }

    private fun makeAvatarGradient(ctx: android.content.Context, entry: MarketplaceEntry): GradientDrawable {
        val seed = entry.id.hashCode()
        val hue = ((seed.ushr(0) % 360 + 360) % 360).toFloat()
        val c1 = Color.HSVToColor(floatArrayOf(hue, 0.40f, 0.85f))
        val c2 = Color.HSVToColor(floatArrayOf((hue + 30f) % 360f, 0.55f, 0.60f))
        val density = ctx.resources.displayMetrics.density
        return GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(c1, c2),
        ).apply {
            cornerRadius = 14f * density
            shape = GradientDrawable.RECTANGLE
        }
    }
}
