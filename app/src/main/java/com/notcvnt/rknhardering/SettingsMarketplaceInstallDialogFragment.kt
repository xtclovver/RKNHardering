package com.notcvnt.rknhardering

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
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
import com.notcvnt.rknhardering.customcheck.MarketplaceInfo
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceClient
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceEntry
import kotlinx.coroutines.launch

internal class SettingsMarketplaceInstallDialogFragment : BottomSheetDialogFragment() {

    companion object {
        const val REQUEST_KEY = "marketplace_install_result"

        private const val ARG_MODE = "mode"
        private const val MODE_MARKETPLACE = "marketplace"
        private const val MODE_FILE = "file"

        private const val ARG_ID = "entry_id"
        private const val ARG_NAME = "entry_name"
        private const val ARG_DESC = "entry_description"
        private const val ARG_AUTHOR = "entry_author"
        private const val ARG_VERSION = "entry_version"
        private const val ARG_OFFICIAL = "entry_official"
        private const val ARG_VERIFIED = "entry_verified"
        private const val ARG_PROFILE_URL = "entry_profile_url"
        private const val ARG_EXPECTED_HASH = "entry_expected_hash"
        private const val ARG_CATALOG_SIGNED = "entry_catalog_signed"
        private const val ARG_FILE_URI = "file_uri"

        fun newInstance(entry: MarketplaceEntry, catalogSignatureValid: Boolean) =
            SettingsMarketplaceInstallDialogFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_MODE, MODE_MARKETPLACE)
                    putString(ARG_ID, entry.id)
                    putString(ARG_NAME, entry.name)
                    putString(ARG_DESC, entry.description)
                    putString(ARG_AUTHOR, entry.author)
                    putString(ARG_VERSION, entry.version)
                    putBoolean(ARG_OFFICIAL, entry.official)
                    putBoolean(ARG_VERIFIED, entry.verified)
                    putString(ARG_PROFILE_URL, entry.profileUrl)
                    putString(ARG_EXPECTED_HASH, entry.expectedHash)
                    putBoolean(ARG_CATALOG_SIGNED, catalogSignatureValid)
                }
            }

        fun newInstanceForFile(uri: Uri) =
            SettingsMarketplaceInstallDialogFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_MODE, MODE_FILE)
                    putString(ARG_FILE_URI, uri.toString())
                }
            }
    }

    private val isMarketplace: Boolean
        get() = requireArguments().getString(ARG_MODE) == MODE_MARKETPLACE

    private fun marketplaceEntryFromArgs(): MarketplaceEntry {
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
            expectedHash = args.getString(ARG_EXPECTED_HASH),
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
        if (isMarketplace) {
            val entry = marketplaceEntryFromArgs()
            val catalogSigned = requireArguments().getBoolean(ARG_CATALOG_SIGNED, false)
            // verified/official already clamped to false at parse time when catalog
            // signature was missing — but be explicit.
            val trusted = catalogSigned && (entry.official || entry.verified)
            if (trusted) renderVerifiedMarketplace(view, entry, catalogSigned)
            else renderUnverifiedMarketplace(view, entry, catalogSigned)
        } else {
            renderFileImport(view, Uri.parse(requireArguments().getString(ARG_FILE_URI, "")))
        }
    }

    private fun renderVerifiedMarketplace(view: View, entry: MarketplaceEntry, catalogSigned: Boolean) {
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
        confirm.setOnClickListener { fetchAndInstallMarketplace(entry, catalogSigned) }
        cancel.setOnClickListener { dismiss() }
    }

    private fun renderUnverifiedMarketplace(view: View, entry: MarketplaceEntry, catalogSigned: Boolean) {
        renderWarning(
            view = view,
            title = getString(R.string.security_warning_title),
            subtitle = getString(R.string.install_subtitle_format, entry.name, entry.author),
            body = getString(R.string.security_warning_intro),
            fetchProfile = { runCatching { MarketplaceClient.fetchProfile(requireContext(), entry, catalogSigned) }.getOrNull() },
            onConfirm = { profile -> installMarketplaceProfile(profile, entry, catalogSigned) },
            onFallbackConfirm = { fetchAndInstallMarketplace(entry, catalogSigned) },
        )
    }

    private fun renderFileImport(view: View, uri: Uri) {
        renderWarning(
            view = view,
            title = getString(R.string.security_warning_title),
            subtitle = getString(R.string.install_file_subtitle),
            body = getString(R.string.security_warning_intro),
            fetchProfile = { runCatching { CustomCheckRepository.importFromFile(requireContext(), uri) }.getOrNull() },
            onConfirm = { profile -> installImportedProfile(profile) },
            onFallbackConfirm = null,
        )
    }

    private fun renderWarning(
        view: View,
        title: String,
        subtitle: String,
        body: String,
        fetchProfile: suspend () -> CustomCheckProfile?,
        onConfirm: (CustomCheckProfile) -> Unit,
        onFallbackConfirm: (() -> Unit)?,
    ) {
        val ctx = requireContext()
        val iconWrap = view.findViewById<FrameLayout>(R.id.installHeaderIconWrap)
        val icon = view.findViewById<ImageView>(R.id.installHeaderIcon)
        val titleView = view.findViewById<TextView>(R.id.installTitle)
        val subtitleView = view.findViewById<TextView>(R.id.installSubtitle)
        val bodyView = view.findViewById<TextView>(R.id.installBody)
        val urlBlock = view.findViewById<View>(R.id.installUrlBlock)
        val urlList = view.findViewById<TextView>(R.id.installUrlList)
        val confirm = view.findViewById<MaterialButton>(R.id.installConfirm)
        val cancel = view.findViewById<MaterialButton>(R.id.installCancel)

        iconWrap.background = avatarSolid(ctx, ContextCompat.getColor(ctx, R.color.status_amber))
        icon.setImageResource(R.drawable.ic_warning_amber)
        icon.setColorFilter(Color.parseColor("#FF14121A"))
        titleView.text = title
        subtitleView.text = subtitle
        bodyView.text = body

        confirm.text = getString(R.string.security_warning_install_anyway)
        confirm.setBackgroundColor(ContextCompat.getColor(ctx, R.color.status_amber))
        confirm.setTextColor(Color.parseColor("#FF14121A"))
        cancel.setOnClickListener { dismiss() }

        lifecycleScope.launch {
            val profile = fetchProfile()
            if (profile != null) {
                val urls = CustomCheckSerializer.extractAllUrls(profile)
                if (urls.isEmpty()) {
                    urlBlock.visibility = View.GONE
                } else {
                    val grouped = urls.groupBy { it.checkName }
                    val sb = StringBuilder()
                    grouped.forEach { (checkName, infos) ->
                        if (sb.isNotEmpty()) sb.append("\n\n")
                        sb.append("[").append(checkName).append("]\n")
                        infos.forEach { info ->
                            sb.append("  • ").append(info.url)
                            if (info.purpose.isNotBlank()) sb.append(" (").append(info.purpose).append(")")
                            sb.append('\n')
                        }
                    }
                    // Standalone DNS warning if profile overrides DNS — these checks
                    // also live in the URL list but the explicit sentence is louder.
                    if (profile.networkConfig.dohUrl.isNotBlank() ||
                        profile.networkConfig.dnsServers.isNotBlank()
                    ) {
                        sb.append("\n\n⚠ ").append(getString(R.string.install_dns_override_warning))
                    }
                    urlList.text = sb.toString().trimEnd()
                    urlBlock.visibility = View.VISIBLE
                }
                confirm.setOnClickListener { onConfirm(profile) }
            } else if (onFallbackConfirm != null) {
                confirm.setOnClickListener { onFallbackConfirm() }
            } else {
                if (isAdded) {
                    Toast.makeText(requireContext(), getString(R.string.marketplace_install_failed), Toast.LENGTH_LONG).show()
                }
                confirm.isEnabled = false
            }
        }
    }

    private fun fetchAndInstallMarketplace(entry: MarketplaceEntry, catalogSigned: Boolean) {
        lifecycleScope.launch {
            runCatching {
                val profile = MarketplaceClient.fetchProfile(requireContext(), entry, catalogSigned)
                installMarketplaceProfile(profile, entry, catalogSigned)
            }.onFailure { err ->
                if (isAdded) {
                    val msg = if (err is MarketplaceClient.HashMismatchException) {
                        getString(R.string.marketplace_install_hash_mismatch)
                    } else {
                        getString(R.string.marketplace_install_failed)
                    }
                    Toast.makeText(requireContext(), msg, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun installMarketplaceProfile(profile: CustomCheckProfile, entry: MarketplaceEntry, catalogSigned: Boolean) {
        val signatureVerified = catalogSigned && entry.expectedHash != null
        val originalHash = CustomCheckSerializer.canonicalHash(profile)
        val marketplaceInfo = MarketplaceInfo(
            sourceUrl = entry.profileUrl,
            // Only confer official/verified when the catalog signature actually
            // validated AND the per-profile hash matched.
            official = signatureVerified && entry.official,
            verified = signatureVerified && entry.verified,
            signatureVerified = signatureVerified,
            marketplaceId = entry.id,
            originalHash = originalHash,
        )
        val finalProfile = profile.copy(
            id = entry.id,
            marketplaceInfo = marketplaceInfo,
        )
        CustomCheckRepository.save(requireContext(), finalProfile)
        notifyInstalled(finalProfile)
    }

    private fun installImportedProfile(profile: CustomCheckProfile) {
        // File/clipboard imports never get badges, regardless of what the file claims.
        val info = profile.marketplaceInfo?.copy(
            official = false,
            verified = false,
            signatureVerified = false,
            originalHash = null,
        )
        val finalProfile = profile.copy(marketplaceInfo = info)
        CustomCheckRepository.save(requireContext(), finalProfile)
        notifyInstalled(finalProfile)
    }

    private fun notifyInstalled(profile: CustomCheckProfile) {
        if (isAdded) {
            Toast.makeText(
                requireContext(),
                getString(R.string.marketplace_install_done, profile.name),
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
