package com.notcvnt.rknhardering

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.ChipGroup
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.notcvnt.rknhardering.customcheck.ChecksConfig
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomCheckRepository
import com.notcvnt.rknhardering.customcheck.CustomDomain
import com.notcvnt.rknhardering.customcheck.NetworkConfig
import com.notcvnt.rknhardering.customcheck.ui.CheckerSectionController
import com.notcvnt.rknhardering.customcheck.ui.editor.DomainReachabilitySectionBinder
import com.notcvnt.rknhardering.customcheck.ui.editor.EditorSectionBinders
import com.notcvnt.rknhardering.customcheck.ui.editor.EndpointPillData
import com.notcvnt.rknhardering.customcheck.ui.editor.EndpointPills
import com.notcvnt.rknhardering.customcheck.ui.editor.SectionBinder

internal class SettingsCustomCheckEditorFragment :
    Fragment(R.layout.fragment_settings_custom_check_editor) {

    private companion object {
        private const val STATE_OPEN_SECTIONS = "open_sections"
        private const val STATE_DISABLED_SECTIONS = "disabled_sections"
        private const val ARG_PROFILE_ID = "profile_id"
    }

    private var profile: CustomCheckProfile = CustomCheckProfile(name = "New profile")

    private val sections = mutableMapOf<String, CheckerSectionController>()

    /** Generic (non-reachability) custom domains; reachability ones live in the binder. */
    private val customDomains = mutableListOf<CustomDomain>()

    private val openSectionIds = mutableSetOf<String>()
    private val disabledSectionIds = mutableSetOf<String>()

    private val binderHost = object : SectionBinder.Host {
        override val lifecycleScope get() = viewLifecycleOwner.lifecycleScope
        override fun string(res: Int, vararg args: Any): String = getString(res, *args)
        override fun refreshSummary(sectionId: String) {
            sections[sectionId]?.refreshSummary()
        }
    }

    private lateinit var binders: EditorSectionBinders

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        arguments?.getString(ARG_PROFILE_ID)?.let { id ->
            CustomCheckRepository.getById(requireContext(), id)?.let { profile = it }
        }

        savedInstanceState?.getStringArrayList(STATE_OPEN_SECTIONS)?.let {
            openSectionIds.clear()
            openSectionIds.addAll(it)
        }
        savedInstanceState?.getStringArrayList(STATE_DISABLED_SECTIONS)?.let {
            disabledSectionIds.clear()
            disabledSectionIds.addAll(it)
        }

        binders = EditorSectionBinders(binderHost)

        bindMetadata(view)
        bindCustomDomains(view)
        buildAllSections(view)
        bindNetworkConfig(view)
        bindBottomBar(view)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(STATE_OPEN_SECTIONS, ArrayList(openSectionIds))
        outState.putStringArrayList(STATE_DISABLED_SECTIONS, ArrayList(disabledSectionIds))
    }

    // ─── Metadata ────────────────────────────────────────────────────────────

    private fun bindMetadata(view: View) {
        view.findViewById<TextInputEditText>(R.id.editName).setText(profile.name)
        view.findViewById<TextInputEditText>(R.id.editDescription).setText(profile.description)
        view.findViewById<TextInputEditText>(R.id.editAuthor).setText(profile.author)
        view.findViewById<TextInputEditText>(R.id.editVersion).setText(profile.version)
    }

    // ─── Sections ────────────────────────────────────────────────────────────

    private fun buildAllSections(view: View) {
        val container = view.findViewById<LinearLayout>(R.id.sectionsContainer)
        view.findViewById<TextView>(R.id.textCheckersLabel).text =
            getString(R.string.editor_checkers_section_count, 12)

        val cfg = profile.checksConfig
        val initialDisabled: Map<String, Boolean> = mapOf(
            CheckerSectionController.GEO_IP to !cfg.geoIp.enabled,
            CheckerSectionController.IP_COMPARISON to !cfg.ipComparison.enabled,
            CheckerSectionController.CDN_PULLING to !cfg.cdnPulling.enabled,
            CheckerSectionController.DIRECT_SIGNS to !cfg.directSigns.enabled,
            CheckerSectionController.INDIRECT_SIGNS to !cfg.indirectSigns.enabled,
            CheckerSectionController.NATIVE_SIGNS to !cfg.nativeSigns.enabled,
            CheckerSectionController.LOCATION_SIGNALS to !cfg.locationSignals.enabled,
            CheckerSectionController.ICMP_SPOOFING to !cfg.icmpSpoofing.enabled,
            CheckerSectionController.RTT_TRIANGULATION to !cfg.rttTriangulation.enabled,
            CheckerSectionController.CALL_TRANSPORT to !cfg.callTransport.enabled,
            CheckerSectionController.SPLIT_TUNNEL to !cfg.splitTunnel.enabled,
            CheckerSectionController.DOMAIN_REACHABILITY to !cfg.domainReachabilityEnabled,
        )
        if (savedInstanceStateNotRestored()) {
            disabledSectionIds.clear()
            initialDisabled.filterValues { it }.keys.forEach { disabledSectionIds.add(it) }
        }

        binders.ordered.forEach { binder -> addSection(container, binder) }

        // Apply persisted state
        sections.forEach { (id, ctrl) ->
            ctrl.setEnabled(id !in disabledSectionIds, propagate = false)
            ctrl.setExpanded(id in openSectionIds, animate = false)
            ctrl.refreshSummary()
        }
    }

    private fun savedInstanceStateNotRestored(): Boolean =
        disabledSectionIds.isEmpty() && openSectionIds.isEmpty()

    private fun addSection(container: LinearLayout, binder: SectionBinder<*>) {
        val inflater = LayoutInflater.from(container.context)
        val sectionView = inflater.inflate(R.layout.view_checker_section, container, false)
        container.addView(sectionView)

        val id = binder.sectionId
        val controller = CheckerSectionController(sectionView, id, container)
        controller.setTitle(getString(binder.titleRes))
        controller.setIcon(binder.iconRes)
        controller.onMasterChanged = { enabled ->
            if (enabled) {
                disabledSectionIds.remove(id)
                enforceDependenciesOnEnable(id)
            } else {
                disabledSectionIds.add(id)
                enforceDependenciesOnDisable(id)
            }
        }
        sections[id] = controller

        val body = inflater.inflate(binder.bodyLayout, controller.body, false)
        controller.body.addView(body)
        binder.bind(body, profile)
        controller.summaryProvider = { binder.summary(body) ?: "" }

        // Override expansion listener to track openSectionIds
        sectionView.findViewById<View>(R.id.sectionHeader).setOnClickListener {
            val nowOpen = !controller.isExpanded
            controller.setExpanded(nowOpen, animate = true)
            if (nowOpen) openSectionIds.add(id) else openSectionIds.remove(id)
        }
    }

    // ─── Custom domains (compact list) ───────────────────────────────────────

    private fun bindCustomDomains(view: View) {
        val container = view.findViewById<LinearLayout>(R.id.containerCustomDomains)
        customDomains.clear()
        profile.customDomains
            .filterNot { DomainReachabilitySectionBinder.isReachabilityType(it.checkType) }
            .forEach { customDomains.add(it) }
        rebuildDomainList(container)
        view.findViewById<MaterialButton>(R.id.btnAddCustomDomain).setOnClickListener {
            showAddCustomDomainDialog(container)
        }
    }

    private fun rebuildDomainList(container: LinearLayout) {
        container.removeAllViews()
        customDomains.forEachIndexed { idx, cd ->
            val view = EndpointPills.makePillView(
                container,
                EndpointPillData(
                    name = cd.domain,
                    url = "${cd.checkType} · ${cd.description}",
                    scope = null,
                    onRemove = {
                        customDomains.removeAt(idx)
                        rebuildDomainList(container)
                    },
                    onEdit = {
                        showAddCustomDomainDialog(container, editIndex = idx)
                    },
                ),
            )
            container.addView(view)
        }
    }

    private fun showAddCustomDomainDialog(container: LinearLayout, editIndex: Int = -1) {
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddCustomDomain) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotCustomDomain) }

        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) customDomains[editIndex] else null
        val initialValues = existing?.let {
            com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.InitialValues(
                url = it.domain, label = it.description, extraInput = it.checkType,
            )
        }

        val controller = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController(slot, viewLifecycleOwner.lifecycleScope)
        controller.show(
            config = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_custom_domain,
                urlHintRes = R.string.settings_custom_check_domain_field,
                labelHintRes = R.string.settings_custom_check_description_field,
                extraInputHintRes = R.string.settings_custom_check_check_type_field,
                extraSwitchTextRes = null,
                testAction = { domain, _, _ ->
                    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        val result = runCatching {
                            val client = okhttp3.OkHttpClient.Builder()
                                .connectTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                                .build()
                            val req = okhttp3.Request.Builder().url("https://$domain").build()
                            client.newCall(req).execute().use { it.isSuccessful }
                        }.getOrNull()

                        if (result == true) {
                            true to "Reachability OK (HTTPS)"
                        } else {
                            val resolved = runCatching {
                                java.net.InetAddress.getByName(domain)
                            }.isSuccess
                            if (resolved) {
                                true to "Reachability OK (DNS only)"
                            } else {
                                false to "Reachability failed"
                            }
                        }
                    }
                },
                saveAction = { domain, label, checkType, _ ->
                    val ct = checkType.trim()
                    if (DomainReachabilitySectionBinder.isReachabilityType(ct)) {
                        Toast.makeText(
                            requireContext(),
                            R.string.settings_custom_check_reachability_blocked_in_generic,
                            Toast.LENGTH_LONG,
                        ).show()
                        btnAdd.visibility = View.VISIBLE
                        return@Config
                    }
                    val newDomain = CustomDomain(
                        domain = domain,
                        checkType = ct,
                        description = label,
                    )
                    if (editIndex >= 0) {
                        customDomains[editIndex] = newDomain
                    } else {
                        customDomains.add(newDomain)
                    }
                    rebuildDomainList(container)
                    btnAdd.visibility = View.VISIBLE
                }
            ),
            onCancel = { btnAdd.visibility = View.VISIBLE },
            initialValues = initialValues,
        )
    }

    // ─── Network config ──────────────────────────────────────────────────────

    private fun bindNetworkConfig(view: View) {
        val nc = profile.networkConfig
        view.findViewById<MaterialSwitch>(R.id.switchNetworkRequestsEnabled).isChecked = nc.networkRequestsEnabled

        val modeGroup = view.findViewById<ChipGroup>(R.id.chipGroupDnsMode)
        when (nc.dnsMode) {
            "direct" -> modeGroup.check(R.id.chipDnsModeDirect)
            "doh" -> modeGroup.check(R.id.chipDnsModeDoh)
            else -> modeGroup.check(R.id.chipDnsModeSystem)
        }
        val presetGroup = view.findViewById<ChipGroup>(R.id.chipGroupDnsPreset)
        when (nc.dnsPreset) {
            "cloudflare" -> presetGroup.check(R.id.chipDnsPresetCloudflare)
            "google" -> presetGroup.check(R.id.chipDnsPresetGoogle)
            "yandex" -> presetGroup.check(R.id.chipDnsPresetYandex)
            else -> presetGroup.check(R.id.chipDnsPresetCustom)
        }
        view.findViewById<TextInputEditText>(R.id.editDnsServers).setText(nc.dnsServers)
        view.findViewById<TextInputEditText>(R.id.editDohUrl).setText(nc.dohUrl)
        view.findViewById<TextInputEditText>(R.id.editDohBootstrap).setText(nc.dohBootstrap)

        val update = {
            val mode = currentDnsMode(view)
            val preset = currentDnsPreset(view)
            view.findViewById<LinearLayout>(R.id.layoutCustomDnsServers).visibility =
                if (mode == "direct" && preset == "custom") View.VISIBLE else View.GONE
            view.findViewById<LinearLayout>(R.id.layoutCustomDoh).visibility =
                if (mode == "doh" && preset == "custom") View.VISIBLE else View.GONE
        }
        modeGroup.setOnCheckedStateChangeListener { _, _ -> update() }
        presetGroup.setOnCheckedStateChangeListener { _, _ -> update() }
        update()
    }

    private fun currentDnsMode(view: View): String = when (view.findViewById<ChipGroup>(R.id.chipGroupDnsMode).checkedChipId) {
        R.id.chipDnsModeDirect -> "direct"
        R.id.chipDnsModeDoh -> "doh"
        else -> "system"
    }

    private fun currentDnsPreset(view: View): String = when (view.findViewById<ChipGroup>(R.id.chipGroupDnsPreset).checkedChipId) {
        R.id.chipDnsPresetCloudflare -> "cloudflare"
        R.id.chipDnsPresetGoogle -> "google"
        R.id.chipDnsPresetYandex -> "yandex"
        else -> "custom"
    }

    // ─── Dependencies between checkers ──────────────────────────────────────

    // For a given checker id, the list of checkers it requires to function.
    // Enabling a checker auto-enables its requirements; disabling a requirement
    // cascades the disable to anything that depends on it.
    private val checkerDependencies: Map<String, List<String>> = mapOf(
        // CallTransport-probe runs INSIDE IndirectSignsChecker — without it, the
        // probe never executes.
        CheckerSectionController.CALL_TRANSPORT to listOf(CheckerSectionController.INDIRECT_SIGNS),
        // RTT triangulation uses GeoIp.countryCode to determine the home country;
        // falls back to SIM but the result is then mostly inconclusive.
        CheckerSectionController.RTT_TRIANGULATION to listOf(CheckerSectionController.GEO_IP),
        // Split-tunnel bypass detection produces raw proxy/leak signals; the verdict
        // engine needs direct + indirect signs to classify them.
        CheckerSectionController.SPLIT_TUNNEL to listOf(
            CheckerSectionController.DIRECT_SIGNS,
            CheckerSectionController.INDIRECT_SIGNS,
        ),
        // Cross-channel IP consensus requires at least two IP sources to detect
        // mismatches; pair GeoIP and IP comparison together.
        CheckerSectionController.GEO_IP to listOf(CheckerSectionController.IP_COMPARISON),
        CheckerSectionController.IP_COMPARISON to listOf(CheckerSectionController.GEO_IP),
        // ICMP-spoofing interprets blocked-host responses in the context of the
        // operator country; without GeoIP the result is uninterpretable.
        CheckerSectionController.ICMP_SPOOFING to listOf(CheckerSectionController.GEO_IP),
    )

    private fun sectionTitle(id: String): String = sections[id]?.titleView?.text?.toString().orEmpty()

    private fun enforceDependenciesOnEnable(enabledId: String) {
        val required = checkerDependencies[enabledId] ?: return
        required.forEach { reqId ->
            val req = sections[reqId] ?: return@forEach
            if (!req.isMasterEnabled()) {
                req.setEnabled(true, propagate = true)
                Toast.makeText(
                    requireContext(),
                    getString(
                        R.string.settings_custom_check_dependency_required,
                        sectionTitle(enabledId),
                        sectionTitle(reqId),
                    ),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    private fun enforceDependenciesOnDisable(disabledId: String) {
        // When a required checker is disabled, also disable any checker that depends on it.
        checkerDependencies.forEach { (dependent, requirements) ->
            if (disabledId in requirements) {
                sections[dependent]?.let { dep ->
                    if (dep.isMasterEnabled()) {
                        dep.setEnabled(false, propagate = true)
                    }
                }
            }
        }
    }

    // ─── Save / cancel ───────────────────────────────────────────────────────

    private fun bindBottomBar(view: View) {
        view.findViewById<MaterialButton>(R.id.btnSave).setOnClickListener {
            if (saveAndExit(view)) parentFragmentManager.popBackStack()
        }
        view.findViewById<MaterialButton>(R.id.btnCancel).setOnClickListener {
            parentFragmentManager.popBackStack()
        }
    }

    private fun <C> collect(binder: SectionBinder<C>): C {
        val controller = sections[binder.sectionId]
        val body = controller?.body?.getChildAt(0)
        val enabled = controller?.isMasterEnabled() ?: binder.enabledFallback
        return binder.collect(body, enabled)
    }

    private fun saveAndExit(view: View): Boolean {
        val name = view.findViewById<TextInputEditText>(R.id.editName).text?.toString()?.trim().orEmpty()
        if (name.isBlank()) {
            Toast.makeText(requireContext(), R.string.settings_custom_check_name_required, Toast.LENGTH_SHORT).show()
            return false
        }
        val anyChecker = sections.values.any { it.isMasterEnabled() }
        if (!anyChecker) {
            Toast.makeText(
                requireContext(),
                R.string.settings_custom_check_no_checks_enabled,
                Toast.LENGTH_LONG,
            ).show()
            return false
        }

        val newConfig = ChecksConfig(
            geoIp = collect(binders.geoIp),
            ipComparison = collect(binders.ipComparison),
            cdnPulling = collect(binders.cdnPulling),
            directSigns = collect(binders.directSigns),
            indirectSigns = collect(binders.indirectSigns),
            nativeSigns = collect(binders.nativeSigns),
            locationSignals = collect(binders.locationSignals),
            icmpSpoofing = collect(binders.icmpSpoofing),
            rttTriangulation = collect(binders.rttTriangulation),
            callTransport = collect(binders.callTransport),
            splitTunnel = collect(binders.splitTunnel),
            domainReachabilityEnabled = collect(binders.domainReachability),
        )

        val newNetwork = NetworkConfig(
            networkRequestsEnabled = view.findViewById<MaterialSwitch>(R.id.switchNetworkRequestsEnabled).isChecked,
            dnsMode = currentDnsMode(view),
            dnsPreset = currentDnsPreset(view),
            dnsServers = view.findViewById<TextInputEditText>(R.id.editDnsServers).text?.toString()?.trim().orEmpty(),
            dohUrl = view.findViewById<TextInputEditText>(R.id.editDohUrl).text?.toString()?.trim().orEmpty(),
            dohBootstrap = view.findViewById<TextInputEditText>(R.id.editDohBootstrap).text?.toString()?.trim().orEmpty(),
        )

        val isOfficialOrVerified = profile.marketplaceInfo?.official == true ||
            profile.marketplaceInfo?.verified == true

        val editedSuffix = getString(R.string.profile_name_edited_suffix)
        val finalName = if (isOfficialOrVerified && !name.endsWith(editedSuffix)) {
            name + editedSuffix
        } else {
            name
        }

        val updated = profile.copy(
            id = if (isOfficialOrVerified) java.util.UUID.randomUUID().toString() else profile.id,
            name = finalName,
            description = view.findViewById<TextInputEditText>(R.id.editDescription).text?.toString()?.trim().orEmpty(),
            author = view.findViewById<TextInputEditText>(R.id.editAuthor).text?.toString()?.trim().orEmpty(),
            version = view.findViewById<TextInputEditText>(R.id.editVersion).text?.toString()?.trim().takeIf { !it.isNullOrBlank() } ?: "1.0.0",
            checksConfig = newConfig,
            customDomains = (customDomains + binders.domainReachability.domains).toList(),
            networkConfig = newNetwork,
            updatedAt = System.currentTimeMillis(),
            createdAt = if (isOfficialOrVerified) System.currentTimeMillis() else profile.createdAt,
            sourceProfileId = if (isOfficialOrVerified) profile.id else profile.sourceProfileId,
            marketplaceInfo = null,
        )

        CustomCheckRepository.save(requireContext(), updated)
        return true
    }
}
