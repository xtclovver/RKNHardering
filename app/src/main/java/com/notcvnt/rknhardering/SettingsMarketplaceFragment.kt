package com.notcvnt.rknhardering

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.ChipGroup
import com.google.android.material.textfield.TextInputEditText
import com.notcvnt.rknhardering.customcheck.CustomCheckRepository
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceClient
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceEntry
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceItemAdapter
import kotlinx.coroutines.launch

internal class SettingsMarketplaceFragment : Fragment(R.layout.fragment_settings_marketplace) {

    private lateinit var adapter: MarketplaceItemAdapter
    private var fullList: List<MarketplaceEntry> = emptyList()
    private var installedIds: Set<String> = emptySet()
    private var currentQuery: String = ""
    private var currentFilter: Filter = Filter.ALL

    private enum class Filter { ALL, OFFICIAL, VERIFIED, RU, PRIVACY, TOR, MOBILE }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        adapter = MarketplaceItemAdapter(
            onInstall = { entry ->
                SettingsMarketplaceInstallDialogFragment.newInstance(entry)
                    .show(childFragmentManager, "install_dialog")
            },
            onOpenInstalled = { entry ->
                val activity = requireActivity() as SettingsActivity
                val fragment = SettingsCustomCheckEditorFragment().apply {
                    arguments = Bundle().apply { putString("profile_id", entry.id) }
                }
                activity.navigateTo(fragment, R.string.settings_custom_check_editor_title)
            },
        )

        view.findViewById<RecyclerView>(R.id.recyclerMarketplace).apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = this@SettingsMarketplaceFragment.adapter
        }

        val editSearch = view.findViewById<TextInputEditText>(R.id.editSearch)
        editSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                currentQuery = s?.toString().orEmpty()
                applyFilter()
            }
        })

        view.findViewById<ChipGroup>(R.id.filterChips).setOnCheckedStateChangeListener { _, checkedIds ->
            val id = checkedIds.firstOrNull() ?: R.id.chipFilterAll
            currentFilter = when (id) {
                R.id.chipFilterOfficial -> Filter.OFFICIAL
                R.id.chipFilterVerified -> Filter.VERIFIED
                R.id.chipFilterRu -> Filter.RU
                R.id.chipFilterPrivacy -> Filter.PRIVACY
                R.id.chipFilterTor -> Filter.TOR
                R.id.chipFilterMobile -> Filter.MOBILE
                else -> Filter.ALL
            }
            applyFilter()
        }

        view.findViewById<MaterialButton>(R.id.btnRetry).setOnClickListener {
            loadCatalog(view)
        }

        childFragmentManager.setFragmentResultListener(
            SettingsMarketplaceInstallDialogFragment.REQUEST_KEY,
            viewLifecycleOwner,
        ) { _, _ ->
            refreshInstalledIds()
            applyFilter()
        }

        loadCatalog(view)
    }

    override fun onResume() {
        super.onResume()
        // Re-check installed state in case user installed/uninstalled something elsewhere
        refreshInstalledIds()
        applyFilter()
    }

    private fun refreshInstalledIds() {
        installedIds = CustomCheckRepository.getAll(requireContext()).map { it.id }.toSet()
    }

    private fun loadCatalog(view: View) {
        val progress = view.findViewById<ProgressBar>(R.id.progressLoading)
        val errorLayout = view.findViewById<View>(R.id.layoutError)
        val textError = view.findViewById<TextView>(R.id.textError)
        val textEmpty = view.findViewById<TextView>(R.id.textEmpty)
        val recycler = view.findViewById<RecyclerView>(R.id.recyclerMarketplace)

        progress.visibility = View.VISIBLE
        errorLayout.visibility = View.GONE
        textEmpty.visibility = View.GONE
        recycler.visibility = View.GONE

        viewLifecycleOwner.lifecycleScope.launch {
            runCatching { MarketplaceClient.fetchCatalog(requireContext()) }
                .onSuccess { catalog ->
                    progress.visibility = View.GONE
                    fullList = catalog.entries
                    refreshInstalledIds()
                    if (fullList.isEmpty()) {
                        textEmpty.visibility = View.VISIBLE
                    } else {
                        recycler.visibility = View.VISIBLE
                        applyFilter()
                    }
                }
                .onFailure { err ->
                    progress.visibility = View.GONE
                    textError.text = err.message ?: getString(R.string.marketplace_error_unknown)
                    errorLayout.visibility = View.VISIBLE
                }
        }
    }

    private fun applyFilter() {
        val q = currentQuery.lowercase()
        val filtered = fullList.asSequence()
            .filter { entry ->
                when (currentFilter) {
                    Filter.ALL -> true
                    Filter.OFFICIAL -> entry.official
                    Filter.VERIFIED -> entry.verified
                    Filter.RU -> entry.tags.any { it.equals("ru", ignoreCase = true) }
                    Filter.PRIVACY -> entry.tags.any { it.equals("privacy", ignoreCase = true) }
                    Filter.TOR -> entry.tags.any { it.equals("tor", ignoreCase = true) }
                    Filter.MOBILE -> entry.tags.any { it.equals("mobile", ignoreCase = true) }
                }
            }
            .filter { entry ->
                q.isBlank() ||
                    entry.name.lowercase().contains(q) ||
                    entry.description.lowercase().contains(q) ||
                    entry.author.lowercase().contains(q) ||
                    entry.tags.any { it.lowercase().contains(q) }
            }
            .map { entry ->
                MarketplaceItemAdapter.Item(entry = entry, installed = entry.id in installedIds)
            }
            .toList()

        adapter.submitList(filtered)
        view?.findViewById<TextView>(R.id.textEmpty)?.visibility =
            if (filtered.isEmpty() && fullList.isNotEmpty()) View.VISIBLE else View.GONE
    }
}
