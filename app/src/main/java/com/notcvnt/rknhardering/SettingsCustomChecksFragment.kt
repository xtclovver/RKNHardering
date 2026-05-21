package com.notcvnt.rknhardering

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomCheckRepository
import com.notcvnt.rknhardering.customcheck.ProfileRowAdapter
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceClient
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceEntry
import kotlinx.coroutines.launch

internal class SettingsCustomChecksFragment : Fragment(R.layout.fragment_settings_custom_checks) {

    companion object {
        private const val ARG_IMPORT_URI = "import_uri"
        private const val BUILTIN_STANDARD_ID = "__builtin_standard__"

        fun newInstance(): SettingsCustomChecksFragment = SettingsCustomChecksFragment()

        fun newInstanceWithImport(uri: Uri): SettingsCustomChecksFragment =
            SettingsCustomChecksFragment().apply {
                arguments = Bundle().apply { putString(ARG_IMPORT_URI, uri.toString()) }
            }
    }

    private lateinit var adapter: ProfileRowAdapter
    private var pendingExportProfile: CustomCheckProfile? = null

    private val exportLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data ?: return@registerForActivityResult
            val profile = pendingExportProfile ?: return@registerForActivityResult
            runCatching {
                CustomCheckRepository.exportToFile(requireContext(), profile, uri)
                Toast.makeText(requireContext(), R.string.settings_custom_check_export_done, Toast.LENGTH_SHORT).show()
            }.onFailure {
                Toast.makeText(requireContext(), R.string.settings_custom_check_export_failed, Toast.LENGTH_SHORT).show()
            }
            pendingExportProfile = null
        }
    }

    private val importLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri ?: return@registerForActivityResult
        runCatching {
            val profile = CustomCheckRepository.importFromFile(requireContext(), uri)
            CustomCheckRepository.save(requireContext(), profile)
            loadProfiles()
            Toast.makeText(requireContext(), R.string.settings_custom_check_import_done, Toast.LENGTH_SHORT).show()
        }.onFailure {
            Toast.makeText(requireContext(), R.string.settings_custom_check_import_failed, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = ProfileRowAdapter(
            onActivate = { profile ->
                if (profile.id == BUILTIN_STANDARD_ID) {
                    CustomCheckRepository.setActiveProfileId(requireContext(), null)
                    AppUiSettings.prefs(requireContext()).edit {
                        putBoolean(SettingsPrefs.PREF_CUSTOM_CHECKS_ENABLED, false)
                    }
                } else {
                    CustomCheckRepository.setActiveProfileId(requireContext(), profile.id)
                    AppUiSettings.prefs(requireContext()).edit {
                        putBoolean(SettingsPrefs.PREF_CUSTOM_CHECKS_ENABLED, true)
                    }
                }
                loadProfiles()
            },
            onEdit = { profile -> openEditor(profile.id) },
            onClone = { profile ->
                runCatching {
                    val newName = "${profile.name} (copy)"
                    CustomCheckRepository.duplicate(requireContext(), profile.id, newName)
                    loadProfiles()
                }.onFailure {
                    Toast.makeText(requireContext(), it.message, Toast.LENGTH_SHORT).show()
                }
            },
            onExport = { profile ->
                pendingExportProfile = profile
                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/octet-stream"
                    putExtra(Intent.EXTRA_TITLE, "${profile.name.replace(" ", "_")}.rkncheck")
                }
                exportLauncher.launch(intent)
            },
            onDelete = { profile -> confirmAndDelete(profile) },
        )

        view.findViewById<RecyclerView>(R.id.recyclerProfiles).apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = this@SettingsCustomChecksFragment.adapter
            isNestedScrollingEnabled = false
        }

        view.findViewById<MaterialButton>(R.id.btnCreateProfile).setOnClickListener {
            openEditor(null)
        }
        view.findViewById<MaterialButton>(R.id.btnImportProfile).setOnClickListener {
            importLauncher.launch(arrayOf("application/octet-stream", "*/*"))
        }
        view.findViewById<MaterialButton>(R.id.btnInstructions).setOnClickListener {
            val url = "https://github.com/xtclovver/RKNHardering/blob/main/marketplace/CONTRIBUTING.md"
            runCatching { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
        }

        // Discover card → Marketplace
        view.findViewById<TextView>(R.id.btnSeeAll).setOnClickListener { openMarketplace() }
        view.findViewById<View>(R.id.discoverCard).setOnClickListener { /* no-op, body clickable via See all */ }

        loadProfiles()
        loadDiscover(view)
        handlePendingImport(view)
    }

    override fun onResume() {
        super.onResume()
        loadProfiles()
        view?.let { loadDiscover(it) }
    }

    private fun openEditor(profileId: String?) {
        val activity = requireActivity() as SettingsActivity
        val fragment = SettingsCustomCheckEditorFragment().apply {
            if (profileId != null) {
                arguments = Bundle().apply { putString("profile_id", profileId) }
            }
        }
        activity.navigateTo(fragment, R.string.settings_custom_check_editor_title)
    }

    private fun openMarketplace() {
        val activity = requireActivity() as SettingsActivity
        activity.navigateTo(SettingsMarketplaceFragment(), R.string.settings_custom_check_marketplace)
    }

    private fun confirmAndDelete(profile: CustomCheckProfile) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(profile.name)
            .setMessage(R.string.settings_custom_check_delete_confirm)
            .setPositiveButton(R.string.action_delete) { _, _ ->
                CustomCheckRepository.delete(requireContext(), profile.id)
                loadProfiles()
            }
            .setNegativeButton(R.string.settings_custom_check_cancel, null)
            .show()
    }

    private fun loadProfiles() {
        val ctx = requireContext()
        val activeId = CustomCheckRepository.getActiveProfileId(ctx)
        val list = CustomCheckRepository.getAll(ctx)

        val items = mutableListOf<ProfileRowAdapter.Item>()
        // Built-in "Standard" profile as a virtual top entry
        items.add(builtinStandardItem(activeId == null))

        list.forEach { profile ->
            items.add(
                ProfileRowAdapter.Item(
                    profile = profile,
                    isActive = profile.id == activeId,
                    isBuiltin = false,
                    checkersEnabledCount = ProfileRowAdapter.countEnabledCheckers(profile),
                    checkersTotalCount = ProfileRowAdapter.TOTAL_CHECKERS,
                )
            )
        }
        adapter.submitList(items)
    }

    private fun builtinStandardItem(isActive: Boolean): ProfileRowAdapter.Item {
        val virtual = CustomCheckProfile(
            id = BUILTIN_STANDARD_ID,
            name = getString(R.string.profile_builtin_standard_name),
            description = getString(R.string.profile_builtin_standard_desc),
            version = "1.0.0",
        )
        return ProfileRowAdapter.Item(
            profile = virtual,
            isActive = isActive,
            isBuiltin = true,
            checkersEnabledCount = ProfileRowAdapter.TOTAL_CHECKERS,
            checkersTotalCount = ProfileRowAdapter.TOTAL_CHECKERS,
        ).also {
            // built-in row activation = clear active id
        }
    }

    private fun loadDiscover(root: View) {
        val card = root.findViewById<View>(R.id.discoverCard)
        val strip = root.findViewById<ViewGroup>(R.id.featuredStrip)
        val empty = root.findViewById<TextView>(R.id.discoverEmpty)

        strip.removeAllViews()
        strip.visibility = View.GONE
        empty.visibility = View.GONE

        viewLifecycleOwner.lifecycleScope.launch {
            val catalogResult = runCatching { MarketplaceClient.fetchCatalog(requireContext()) }
            val entries = catalogResult.getOrNull()?.entries.orEmpty()
            val featured = entries
                .sortedByDescending { it.official }
                .take(3)

            if (featured.isEmpty()) {
                empty.visibility = View.VISIBLE
                return@launch
            }

            val inflater = LayoutInflater.from(card.context)
            featured.forEach { entry ->
                val tile = inflater.inflate(R.layout.view_discover_featured_tile, strip, false)
                val avatarText = tile.findViewById<TextView>(R.id.featuredAvatarText)
                val name = tile.findViewById<TextView>(R.id.featuredName)
                val badgeIcon = tile.findViewById<ImageView>(R.id.featuredBadgeIcon)

                avatarText.text = entry.name.trim().take(1).uppercase().ifBlank { "?" }
                val avatarFrame = avatarText.parent as? View
                avatarFrame?.background = makeMarketAvatarGradient(entry.name)
                name.text = entry.name
                when {
                    entry.official -> {
                        badgeIcon.visibility = View.VISIBLE
                        badgeIcon.setImageResource(R.drawable.ic_verified_blue)
                    }
                    entry.verified -> {
                        badgeIcon.visibility = View.VISIBLE
                        badgeIcon.setImageResource(R.drawable.ic_verified_grey)
                    }
                    else -> badgeIcon.visibility = View.GONE
                }

                // Tap on tile → open marketplace
                tile.setOnClickListener { openMarketplace() }

                // ensure equal width
                val lp = tile.layoutParams as android.widget.LinearLayout.LayoutParams
                lp.weight = 1f
                lp.width = 0
                lp.setMargins(if (strip.childCount == 0) 0 else dp(6), 0, 0, 0)
                tile.layoutParams = lp

                strip.addView(tile)
            }
            strip.visibility = View.VISIBLE
        }
    }

    private fun makeMarketAvatarGradient(name: String): GradientDrawable {
        val seed = name.firstOrNull()?.code ?: 0
        val hue = ((seed * 53) % 360).toFloat()
        val c1 = Color.HSVToColor(floatArrayOf(hue, 0.45f, 0.78f))
        val c2 = Color.HSVToColor(floatArrayOf((hue + 30f) % 360f, 0.55f, 0.55f))
        val density = resources.displayMetrics.density
        return GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(c1, c2),
        ).apply {
            cornerRadius = 8f * density
            shape = GradientDrawable.RECTANGLE
        }
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    private fun handlePendingImport(view: View) {
        arguments?.getString(ARG_IMPORT_URI)?.let { uriStr ->
            arguments?.remove(ARG_IMPORT_URI)
            val uri = Uri.parse(uriStr)
            val profileName = runCatching {
                CustomCheckRepository.importFromFile(requireContext(), uri).name
            }.getOrNull()
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.settings_custom_check_import)
                .setMessage(profileName ?: uri.lastPathSegment ?: uriStr)
                .setPositiveButton(R.string.settings_custom_check_import) { _, _ ->
                    runCatching {
                        val profile = CustomCheckRepository.importFromFile(requireContext(), uri)
                        CustomCheckRepository.save(requireContext(), profile)
                        loadProfiles()
                        Toast.makeText(requireContext(), R.string.settings_custom_check_import_done, Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(requireContext(), R.string.settings_custom_check_import_failed, Toast.LENGTH_SHORT).show()
                    }
                }
                .setNegativeButton(R.string.settings_custom_check_cancel, null)
                .show()
        }
    }
}
