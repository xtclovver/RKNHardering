package com.notcvnt.rknhardering

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.os.bundleOf
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomCheckRepository
import com.notcvnt.rknhardering.customcheck.CustomCheckSerializer
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceClient
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceEntry
import kotlinx.coroutines.launch

internal class SettingsMarketplaceInstallDialogFragment : BottomSheetDialogFragment() {

    companion object {
        const val REQUEST_KEY = "marketplace_install_result"

        private const val ARG_ID = "entry_id"
        private const val ARG_NAME = "entry_name"
        private const val ARG_DESC = "entry_description"
        private const val ARG_AUTHOR = "entry_author"
        private const val ARG_VERSION = "entry_version"
        private const val ARG_OFFICIAL = "entry_official"
        private const val ARG_VERIFIED = "entry_verified"
        private const val ARG_PROFILE_URL = "entry_profile_url"
        private const val ARG_INSTALL_COUNT = "entry_install_count"

        fun newInstance(entry: MarketplaceEntry) = SettingsMarketplaceInstallDialogFragment().apply {
            arguments = Bundle().apply {
                putString(ARG_ID, entry.id)
                putString(ARG_NAME, entry.name)
                putString(ARG_DESC, entry.description)
                putString(ARG_AUTHOR, entry.author)
                putString(ARG_VERSION, entry.version)
                putBoolean(ARG_OFFICIAL, entry.official)
                putBoolean(ARG_VERIFIED, entry.verified)
                putString(ARG_PROFILE_URL, entry.profileUrl)
                putInt(ARG_INSTALL_COUNT, entry.installCount)
            }
        }
    }

    private fun entryFromArgs(): MarketplaceEntry {
        val args = requireArguments()
        return MarketplaceEntry(
            id = args.getString(ARG_ID, ""),
            name = args.getString(ARG_NAME, ""),
            description = args.getString(ARG_DESC, ""),
            author = args.getString(ARG_AUTHOR, ""),
            version = args.getString(ARG_VERSION, "1.0.0"),
            official = args.getBoolean(ARG_OFFICIAL, false),
            verified = args.getBoolean(ARG_VERIFIED, false),
            profileUrl = args.getString(ARG_PROFILE_URL, ""),
            installCount = args.getInt(ARG_INSTALL_COUNT, 0),
            tags = emptyList(),
            createdAt = "",
            updatedAt = "",
        )
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_marketplace_install, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val entry = entryFromArgs()
        val unverified = !entry.verified && !entry.official
        if (unverified) {
            renderUnverified(view, entry)
        } else {
            renderVerified(view, entry)
        }
    }

    private fun renderVerified(view: View, entry: MarketplaceEntry) {
        val ctx = requireContext()
        val iconWrap = view.findViewById<FrameLayout>(R.id.installHeaderIconWrap)
        val icon = view.findViewById<ImageView>(R.id.installHeaderIcon)
        val title = view.findViewById<TextView>(R.id.installTitle)
        val subtitle = view.findViewById<TextView>(R.id.installSubtitle)
        val body = view.findViewById<TextView>(R.id.installBody)
        val urlBlock = view.findViewById<View>(R.id.installUrlBlock)
        val confirm = view.findViewById<MaterialButton>(R.id.installConfirm)
        val cancel = view.findViewById<MaterialButton>(R.id.installCancel)

        iconWrap.background = avatarSolid(ctx, ContextCompat.getColor(ctx, R.color.md_accent_sky))
        icon.setImageResource(R.drawable.ic_verified_blue)
        title.text = getString(R.string.install_verified_title)
        subtitle.text = getString(R.string.install_subtitle_format, entry.name, entry.author)
        body.text = entry.description
        urlBlock.visibility = View.GONE
        confirm.text = getString(R.string.marketplace_action_install)
        confirm.setOnClickListener { fetchAndInstall(entry) }
        cancel.setOnClickListener { dismiss() }
    }

    private fun renderUnverified(view: View, entry: MarketplaceEntry) {
        val ctx = requireContext()
        val iconWrap = view.findViewById<FrameLayout>(R.id.installHeaderIconWrap)
        val icon = view.findViewById<ImageView>(R.id.installHeaderIcon)
        val title = view.findViewById<TextView>(R.id.installTitle)
        val subtitle = view.findViewById<TextView>(R.id.installSubtitle)
        val body = view.findViewById<TextView>(R.id.installBody)
        val urlBlock = view.findViewById<View>(R.id.installUrlBlock)
        val urlList = view.findViewById<TextView>(R.id.installUrlList)
        val confirm = view.findViewById<MaterialButton>(R.id.installConfirm)
        val cancel = view.findViewById<MaterialButton>(R.id.installCancel)

        iconWrap.background = avatarSolid(ctx, ContextCompat.getColor(ctx, R.color.status_amber))
        icon.setImageResource(R.drawable.ic_warning_amber)
        icon.setColorFilter(Color.parseColor("#FF14121A"))
        title.text = getString(R.string.security_warning_title)
        subtitle.text = getString(R.string.install_subtitle_format, entry.name, entry.author)
        body.text = getString(R.string.security_warning_intro)

        confirm.text = getString(R.string.security_warning_install_anyway)
        confirm.setBackgroundColor(ContextCompat.getColor(ctx, R.color.status_amber))
        confirm.setTextColor(Color.parseColor("#FF14121A"))
        cancel.setOnClickListener { dismiss() }

        lifecycleScope.launch {
            val profile = runCatching { MarketplaceClient.fetchProfile(requireContext(), entry) }.getOrNull()
            if (profile != null) {
                val urls = CustomCheckSerializer.extractAllUrls(profile)
                if (urls.isEmpty()) {
                    urlBlock.visibility = View.GONE
                } else {
                    val grouped = urls.groupBy { it.checkName }
                    urlList.text = grouped.entries.joinToString("\n\n") { (checkName, infos) ->
                        "[$checkName]\n" + infos.joinToString("\n") { info ->
                            "  • ${info.url}" + if (info.purpose.isNotBlank()) " (${info.purpose})" else ""
                        }
                    }
                    urlBlock.visibility = View.VISIBLE
                }
                confirm.setOnClickListener { installProfile(profile, entry) }
            } else {
                confirm.setOnClickListener { fetchAndInstall(entry) }
            }
        }
    }

    private fun fetchAndInstall(entry: MarketplaceEntry) {
        lifecycleScope.launch {
            runCatching {
                val profile = MarketplaceClient.fetchProfile(requireContext(), entry)
                installProfile(profile, entry)
            }.onFailure {
                if (isAdded) {
                    Toast.makeText(requireContext(), getString(R.string.marketplace_install_failed), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun installProfile(profile: CustomCheckProfile, entry: MarketplaceEntry) {
        val originalHash = CustomCheckSerializer.canonicalHash(profile)
        val marketplaceInfo = com.notcvnt.rknhardering.customcheck.MarketplaceInfo(
            sourceUrl = entry.profileUrl,
            official = entry.official,
            verified = entry.verified,
            installCount = entry.installCount,
            marketplaceId = entry.id,
            originalHash = originalHash,
        )
        val finalProfile = profile.copy(
            id = entry.id,
            marketplaceInfo = marketplaceInfo,
        )
        CustomCheckRepository.save(requireContext(), finalProfile)
        if (isAdded) {
            Toast.makeText(
                requireContext(),
                getString(R.string.marketplace_install_done, finalProfile.name),
                Toast.LENGTH_SHORT,
            ).show()
            parentFragmentManager.setFragmentResult(REQUEST_KEY, bundleOf())
        }
        dismiss()
    }

    private fun avatarSolid(ctx: android.content.Context, color: Int): GradientDrawable {
        val density = ctx.resources.displayMetrics.density
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = 12f * density
            setColor(color)
        }
    }
}
