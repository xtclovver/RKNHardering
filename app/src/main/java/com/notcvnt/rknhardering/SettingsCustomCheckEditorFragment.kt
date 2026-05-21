package com.notcvnt.rknhardering

import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.ChipGroup
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.notcvnt.rknhardering.customcheck.CallTransportConfig
import com.notcvnt.rknhardering.customcheck.CdnPullingConfig
import com.notcvnt.rknhardering.customcheck.ChecksConfig
import com.notcvnt.rknhardering.customcheck.CheckToggle
import com.notcvnt.rknhardering.customcheck.CustomCdnTarget
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomCheckRepository
import com.notcvnt.rknhardering.customcheck.CustomDomain
import com.notcvnt.rknhardering.customcheck.CustomGeoIpProvider
import com.notcvnt.rknhardering.customcheck.CustomIpEndpoint
import com.notcvnt.rknhardering.customcheck.DirectSignsConfig
import com.notcvnt.rknhardering.customcheck.EndpointScope
import com.notcvnt.rknhardering.customcheck.GeoIpConfig
import com.notcvnt.rknhardering.customcheck.IcmpSpoofingConfig
import com.notcvnt.rknhardering.customcheck.IcmpTarget
import com.notcvnt.rknhardering.customcheck.IndirectSignsConfig
import com.notcvnt.rknhardering.customcheck.IpComparisonConfig
import com.notcvnt.rknhardering.customcheck.LocationSignalsConfig
import com.notcvnt.rknhardering.customcheck.NetworkConfig
import com.notcvnt.rknhardering.customcheck.RttTarget
import com.notcvnt.rknhardering.customcheck.RttTriangulationConfig
import com.notcvnt.rknhardering.customcheck.SplitTunnelConfig
import com.notcvnt.rknhardering.customcheck.StunServer
import com.notcvnt.rknhardering.customcheck.ui.CheckerSectionController
import com.notcvnt.rknhardering.customcheck.ui.InlineEndpointEditorController

internal class SettingsCustomCheckEditorFragment :
    Fragment(R.layout.fragment_settings_custom_check_editor) {

    private companion object {
        private const val STATE_OPEN_SECTIONS = "open_sections"
        private const val STATE_DISABLED_SECTIONS = "disabled_sections"
        private const val ARG_PROFILE_ID = "profile_id"
    }

    private var profile: CustomCheckProfile = CustomCheckProfile(name = "New profile")

    private val sections = mutableMapOf<String, CheckerSectionController>()
    private val customDomains = mutableListOf<CustomDomain>()
    private val reachabilityDomains = mutableListOf<CustomDomain>()
    private val customGeoIpProviders = mutableListOf<CustomGeoIpProvider>()
    private val customIpEndpoints = mutableListOf<CustomIpEndpoint>()
    private val customCdnTargets = mutableListOf<CustomCdnTarget>()
    private val customIcmpTargets = mutableListOf<IcmpTarget>()
    private val customRttTargets = mutableListOf<RttTarget>()
    private val customStunServers = mutableListOf<StunServer>()

    private var geoIpEditor: InlineEndpointEditorController? = null
    private var ipEditor: InlineEndpointEditorController? = null
    private var cdnEditor: InlineEndpointEditorController? = null

    private val openSectionIds = mutableSetOf<String>()
    private val disabledSectionIds = mutableSetOf<String>()

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

        addSection(
            container,
            id = CheckerSectionController.GEO_IP,
            title = getString(R.string.settings_custom_check_section_geo_ip),
            iconRes = R.drawable.ic_public,
            bodyLayout = R.layout.section_body_geo_ip,
        ) { body -> bindGeoIpBody(body) }

        addSection(
            container,
            id = CheckerSectionController.IP_COMPARISON,
            title = getString(R.string.settings_custom_check_section_ip_comparison),
            iconRes = R.drawable.ic_compare_arrows,
            bodyLayout = R.layout.section_body_ip_comparison,
        ) { body -> bindIpComparisonBody(body) }

        addSection(
            container,
            id = CheckerSectionController.CDN_PULLING,
            title = getString(R.string.settings_custom_check_section_cdn_pulling),
            iconRes = R.drawable.ic_cloud,
            bodyLayout = R.layout.section_body_cdn_pulling,
        ) { body -> bindCdnPullingBody(body) }

        addSection(
            container,
            id = CheckerSectionController.DIRECT_SIGNS,
            title = getString(R.string.settings_custom_check_section_direct_signs),
            iconRes = R.drawable.ic_security,
            bodyLayout = R.layout.section_body_direct_signs,
        ) { body -> bindDirectSignsBody(body) }

        addSection(
            container,
            id = CheckerSectionController.INDIRECT_SIGNS,
            title = getString(R.string.settings_custom_check_section_indirect_signs),
            iconRes = R.drawable.ic_lan,
            bodyLayout = R.layout.section_body_indirect_signs,
        ) { body -> bindIndirectSignsBody(body) }

        addSection(
            container,
            id = CheckerSectionController.NATIVE_SIGNS,
            title = getString(R.string.settings_custom_check_section_native_signs),
            iconRes = R.drawable.ic_lock,
            bodyLayout = R.layout.section_body_native_signs,
        ) { /* no-op body */ }

        addSection(
            container,
            id = CheckerSectionController.LOCATION_SIGNALS,
            title = getString(R.string.settings_custom_check_section_location_signals),
            iconRes = R.drawable.ic_location_on,
            bodyLayout = R.layout.section_body_location_signals,
        ) { body -> bindLocationSignalsBody(body) }

        addSection(
            container,
            id = CheckerSectionController.ICMP_SPOOFING,
            title = getString(R.string.settings_custom_check_section_icmp_spoofing),
            iconRes = R.drawable.ic_network_check,
            bodyLayout = R.layout.section_body_icmp_spoofing,
        ) { body -> bindIcmpSpoofingBody(body) }

        addSection(
            container,
            id = CheckerSectionController.RTT_TRIANGULATION,
            title = getString(R.string.settings_custom_check_section_rtt_triangulation),
            iconRes = R.drawable.ic_compare_arrows,
            bodyLayout = R.layout.section_body_rtt_triangulation,
        ) { body -> bindRttTriangulationBody(body) }

        addSection(
            container,
            id = CheckerSectionController.CALL_TRANSPORT,
            title = getString(R.string.settings_custom_check_section_call_transport),
            iconRes = R.drawable.ic_call,
            bodyLayout = R.layout.section_body_call_transport,
        ) { body -> bindCallTransportBody(body) }

        addSection(
            container,
            id = CheckerSectionController.SPLIT_TUNNEL,
            title = getString(R.string.settings_custom_check_section_split_tunnel),
            iconRes = R.drawable.ic_call_split,
            bodyLayout = R.layout.section_body_split_tunnel,
        ) { body -> bindSplitTunnelBody(body) }

        addSection(
            container,
            id = CheckerSectionController.DOMAIN_REACHABILITY,
            title = getString(R.string.settings_custom_check_section_domain_reachability),
            iconRes = R.drawable.ic_public,
            bodyLayout = R.layout.section_body_domain_reachability,
        ) { body -> bindDomainReachabilityBody(body) }

        // Apply persisted state
        sections.forEach { (id, ctrl) ->
            ctrl.setEnabled(id !in disabledSectionIds, propagate = false)
            ctrl.setExpanded(id in openSectionIds, animate = false)
            ctrl.refreshSummary()
        }
    }

    private fun savedInstanceStateNotRestored(): Boolean =
        disabledSectionIds.isEmpty() && openSectionIds.isEmpty()

    private fun addSection(
        container: LinearLayout,
        id: String,
        title: String,
        iconRes: Int,
        bodyLayout: Int,
        bindBody: (View) -> Unit,
    ) {
        val inflater = LayoutInflater.from(container.context)
        val sectionView = inflater.inflate(R.layout.view_checker_section, container, false)
        container.addView(sectionView)

        val controller = CheckerSectionController(sectionView, id, container)
        controller.setTitle(title)
        controller.setIcon(iconRes)
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

        val body = inflater.inflate(bodyLayout, controller.body, false)
        controller.body.addView(body)
        bindBody(body)

        // Override expansion listener to track openSectionIds
        sectionView.findViewById<View>(R.id.sectionHeader).setOnClickListener {
            val nowOpen = !controller.isExpanded()
            controller.setExpanded(nowOpen, animate = true)
            if (nowOpen) openSectionIds.add(id) else openSectionIds.remove(id)
        }
    }

    // ─── Section body bindings ───────────────────────────────────────────────

    private fun bindGeoIpBody(body: View) {
        val cfg = profile.checksConfig.geoIp
        body.findViewById<TextInputEditText>(R.id.editGeoIpTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpapiIs).isChecked = cfg.builtinProviders["ipapi.is"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplocate).isChecked = cfg.builtinProviders["iplocate.io"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpquery).isChecked = cfg.builtinProviders["ipquery.io"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplookup).isChecked = cfg.builtinProviders["iplookup.it"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpbot).isChecked = cfg.builtinProviders["ipbot.com"] != false

        customGeoIpProviders.clear()
        customGeoIpProviders.addAll(cfg.customProviders)
        val container = body.findViewById<LinearLayout>(R.id.containerGeoIpEndpoints)
        rebuildGeoIpPills(container)

        val slot = body.findViewById<ViewGroup>(R.id.inlineEditorSlotGeoIp)
        val btnAdd = body.findViewById<MaterialButton>(R.id.btnAddGeoIpEndpoint)
        btnAdd.setOnClickListener {
            if (geoIpEditor?.isShowing() == true) return@setOnClickListener
            btnAdd.visibility = View.GONE
            val editor = InlineEndpointEditorController(slot, viewLifecycleOwner.lifecycleScope)
            geoIpEditor = editor
            editor.show(
                kind = InlineEndpointEditorController.Kind.GEO_IP,
                onCancel = { btnAdd.visibility = View.VISIBLE; geoIpEditor = null },
                onSave = { result ->
                    customGeoIpProviders.add(
                        CustomGeoIpProvider(
                            name = result.label,
                            url = result.url,
                            responseMapping = result.mapping,
                        )
                    )
                    rebuildGeoIpPills(container)
                    btnAdd.visibility = View.VISIBLE
                    geoIpEditor = null
                    sections[CheckerSectionController.GEO_IP]?.refreshSummary()
                },
            )
        }

        sections[CheckerSectionController.GEO_IP]?.summaryProvider = {
            val builtinTotal = 5
            val builtinOn = listOf(
                body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpapiIs).isChecked,
                body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplocate).isChecked,
                body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpquery).isChecked,
                body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplookup).isChecked,
                body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpbot).isChecked,
            ).count { it }
            val custom = customGeoIpProviders.size
            getString(R.string.editor_summary_geoip, builtinOn, builtinTotal, custom)
        }
    }

    private fun bindIpComparisonBody(body: View) {
        val cfg = profile.checksConfig.ipComparison
        body.findViewById<TextInputEditText>(R.id.editIpComparisonTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinRu).isChecked = cfg.builtinRuCheckersEnabled
        body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinNonRu).isChecked = cfg.builtinNonRuCheckersEnabled

        customIpEndpoints.clear()
        customIpEndpoints.addAll(cfg.customEndpoints)
        val container = body.findViewById<LinearLayout>(R.id.containerIpEndpoints)
        rebuildIpPills(container)

        val slot = body.findViewById<ViewGroup>(R.id.inlineEditorSlotIp)
        val btnAdd = body.findViewById<MaterialButton>(R.id.btnAddIpEndpoint)
        btnAdd.setOnClickListener {
            if (ipEditor?.isShowing() == true) return@setOnClickListener
            btnAdd.visibility = View.GONE
            val editor = InlineEndpointEditorController(slot, viewLifecycleOwner.lifecycleScope)
            ipEditor = editor
            editor.show(
                kind = InlineEndpointEditorController.Kind.IP_COMPARISON,
                onCancel = { btnAdd.visibility = View.VISIBLE; ipEditor = null },
                onSave = { result ->
                    customIpEndpoints.add(
                        CustomIpEndpoint(
                            label = result.label,
                            url = result.url,
                            scope = result.scope,
                            responseMapping = result.mapping,
                        )
                    )
                    rebuildIpPills(container)
                    btnAdd.visibility = View.VISIBLE
                    ipEditor = null
                    sections[CheckerSectionController.IP_COMPARISON]?.refreshSummary()
                },
            )
        }

        sections[CheckerSectionController.IP_COMPARISON]?.summaryProvider = {
            val ru = if (body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinRu).isChecked) 1 else 0
            val nonRu = if (body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinNonRu).isChecked) 1 else 0
            getString(R.string.editor_summary_ip_comparison, ru + nonRu, 2, customIpEndpoints.size)
        }
    }

    private fun bindCdnPullingBody(body: View) {
        val cfg = profile.checksConfig.cdnPulling
        body.findViewById<TextInputEditText>(R.id.editCdnTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchCdnBuiltinTargets).isChecked = cfg.builtinTargetsEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCdnMeduza).isChecked = cfg.meduzaEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCdnRutracker).isChecked = cfg.rutrackerEnabled

        customCdnTargets.clear()
        customCdnTargets.addAll(cfg.customTargets)
        val container = body.findViewById<LinearLayout>(R.id.containerCdnEndpoints)
        rebuildCdnPills(container)

        val slot = body.findViewById<ViewGroup>(R.id.inlineEditorSlotCdn)
        val btnAdd = body.findViewById<MaterialButton>(R.id.btnAddCdnEndpoint)
        btnAdd.setOnClickListener {
            if (cdnEditor?.isShowing() == true) return@setOnClickListener
            btnAdd.visibility = View.GONE
            val editor = InlineEndpointEditorController(slot, viewLifecycleOwner.lifecycleScope)
            cdnEditor = editor
            editor.show(
                kind = InlineEndpointEditorController.Kind.CDN,
                onCancel = { btnAdd.visibility = View.VISIBLE; cdnEditor = null },
                onSave = { result ->
                    customCdnTargets.add(
                        CustomCdnTarget(
                            label = result.label,
                            url = result.url,
                            responseMapping = result.mapping,
                        )
                    )
                    rebuildCdnPills(container)
                    btnAdd.visibility = View.VISIBLE
                    cdnEditor = null
                    sections[CheckerSectionController.CDN_PULLING]?.refreshSummary()
                },
            )
        }

        sections[CheckerSectionController.CDN_PULLING]?.summaryProvider = {
            val builtins = (if (body.findViewById<MaterialSwitch>(R.id.switchCdnBuiltinTargets).isChecked) 1 else 0) +
                (if (body.findViewById<MaterialSwitch>(R.id.switchCdnMeduza).isChecked) 1 else 0) +
                (if (body.findViewById<MaterialSwitch>(R.id.switchCdnRutracker).isChecked) 1 else 0)
            getString(R.string.editor_summary_cdn, builtins, 3, customCdnTargets.size)
        }
    }

    private fun bindDirectSignsBody(body: View) {
        val cfg = profile.checksConfig.directSigns
        body.findViewById<MaterialSwitch>(R.id.switchDirectTransportVpn).isChecked = cfg.checkTransportVpn
        body.findViewById<MaterialSwitch>(R.id.switchDirectHttpProxy).isChecked = cfg.checkHttpProxy
        body.findViewById<MaterialSwitch>(R.id.switchDirectSocksProxy).isChecked = cfg.checkSocksProxy
        body.findViewById<MaterialSwitch>(R.id.switchDirectProxyInfo).isChecked = cfg.checkProxyInfo
        body.findViewById<MaterialSwitch>(R.id.switchDirectVpnService).isChecked = cfg.checkVpnService

        sections[CheckerSectionController.DIRECT_SIGNS]?.summaryProvider = {
            val total = 5
            val on = listOf(
                R.id.switchDirectTransportVpn,
                R.id.switchDirectHttpProxy,
                R.id.switchDirectSocksProxy,
                R.id.switchDirectProxyInfo,
                R.id.switchDirectVpnService,
            ).count { body.findViewById<MaterialSwitch>(it).isChecked }
            getString(R.string.editor_summary_x_of_y_active, on, total)
        }
    }

    private fun bindIndirectSignsBody(body: View) {
        val cfg = profile.checksConfig.indirectSigns
        body.findViewById<MaterialSwitch>(R.id.switchIndirectNotVpnCap).isChecked = cfg.checkNotVpnCap
        body.findViewById<MaterialSwitch>(R.id.switchIndirectVpnInterfaces).isChecked = cfg.checkVpnInterfaces
        body.findViewById<MaterialSwitch>(R.id.switchIndirectMtuAnomaly).isChecked = cfg.checkMtuAnomaly
        body.findViewById<MaterialSwitch>(R.id.switchIndirectIpsec).isChecked = cfg.checkIpsec
        body.findViewById<MaterialSwitch>(R.id.switchIndirectRouting).isChecked = cfg.checkRouting
        body.findViewById<MaterialSwitch>(R.id.switchIndirectDns).isChecked = cfg.checkDns
        body.findViewById<MaterialSwitch>(R.id.switchIndirectProxyTools).isChecked = cfg.checkProxyTools
        body.findViewById<MaterialSwitch>(R.id.switchIndirectLocalListeners).isChecked = cfg.checkLocalListeners
        body.findViewById<MaterialSwitch>(R.id.switchIndirectDumpsys).isChecked = cfg.checkDumpsys
        body.findViewById<TextInputEditText>(R.id.editIndirectListenerPortThreshold)
            .setText(cfg.listenerPortThreshold.toString())

        sections[CheckerSectionController.INDIRECT_SIGNS]?.summaryProvider = {
            val ids = listOf(
                R.id.switchIndirectNotVpnCap, R.id.switchIndirectVpnInterfaces,
                R.id.switchIndirectMtuAnomaly, R.id.switchIndirectIpsec,
                R.id.switchIndirectRouting, R.id.switchIndirectDns,
                R.id.switchIndirectProxyTools, R.id.switchIndirectLocalListeners,
                R.id.switchIndirectDumpsys,
            )
            val on = ids.count { body.findViewById<MaterialSwitch>(it).isChecked }
            getString(R.string.editor_summary_x_of_y_active, on, ids.size)
        }
    }

    private fun bindLocationSignalsBody(body: View) {
        val cfg = profile.checksConfig.locationSignals
        body.findViewById<MaterialSwitch>(R.id.switchLocationBeacondb).isChecked = cfg.checkBeacondb
        body.findViewById<MaterialSwitch>(R.id.switchLocationCellTowers).isChecked = cfg.checkCellTowers
        body.findViewById<MaterialSwitch>(R.id.switchLocationWifiSignals).isChecked = cfg.checkWifiSignals

        sections[CheckerSectionController.LOCATION_SIGNALS]?.summaryProvider = {
            val ids = listOf(
                R.id.switchLocationBeacondb,
                R.id.switchLocationCellTowers,
                R.id.switchLocationWifiSignals,
            )
            val on = ids.count { body.findViewById<MaterialSwitch>(it).isChecked }
            getString(R.string.editor_summary_x_of_y_active, on, ids.size)
        }
    }

    private fun bindIcmpSpoofingBody(body: View) {
        val cfg = profile.checksConfig.icmpSpoofing
        body.findViewById<TextInputEditText>(R.id.editIcmpTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<TextInputEditText>(R.id.editIcmpPingCount).setText(cfg.pingCount.toString())
        body.findViewById<MaterialSwitch>(R.id.switchIcmpBuiltinTargets).isChecked = cfg.builtinTargetsEnabled

        customIcmpTargets.clear()
        customIcmpTargets.addAll(cfg.customTargets)
        val container = body.findViewById<LinearLayout>(R.id.containerIcmpTargets)
        rebuildIcmpPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddIcmpTarget).setOnClickListener {
            showAddIcmpTargetDialog(container)
        }

        sections[CheckerSectionController.ICMP_SPOOFING]?.summaryProvider = {
            val builtin = if (body.findViewById<MaterialSwitch>(R.id.switchIcmpBuiltinTargets).isChecked) 1 else 0
            getString(R.string.editor_summary_targets, builtin + customIcmpTargets.size)
        }
    }

    private fun bindRttTriangulationBody(body: View) {
        val cfg = profile.checksConfig.rttTriangulation
        body.findViewById<TextInputEditText>(R.id.editRttTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<TextInputEditText>(R.id.editRttPingCount).setText(cfg.pingCount.toString())
        body.findViewById<MaterialSwitch>(R.id.switchRttBuiltinTargets).isChecked = cfg.builtinTargetsEnabled

        customRttTargets.clear()
        customRttTargets.addAll(cfg.customTargets)
        val container = body.findViewById<LinearLayout>(R.id.containerRttTargets)
        rebuildRttPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddRttTarget).setOnClickListener {
            showAddRttTargetDialog(container)
        }

        sections[CheckerSectionController.RTT_TRIANGULATION]?.summaryProvider = {
            val builtin = if (body.findViewById<MaterialSwitch>(R.id.switchRttBuiltinTargets).isChecked) 1 else 0
            getString(R.string.editor_summary_targets, builtin + customRttTargets.size)
        }
    }

    private fun bindCallTransportBody(body: View) {
        val cfg = profile.checksConfig.callTransport
        body.findViewById<TextInputEditText>(R.id.editCallTransportTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinGlobalStun).isChecked = cfg.builtinGlobalStunEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinRuStun).isChecked = cfg.builtinRuStunEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCallTransportMtproto).isChecked = cfg.checkMtproto

        customStunServers.clear()
        customStunServers.addAll(cfg.customStunServers)
        val container = body.findViewById<LinearLayout>(R.id.containerStunServers)
        rebuildStunPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddStunServer).setOnClickListener {
            showAddStunDialog(container)
        }

        sections[CheckerSectionController.CALL_TRANSPORT]?.summaryProvider = {
            val builtin = (if (body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinGlobalStun).isChecked) 1 else 0) +
                (if (body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinRuStun).isChecked) 1 else 0)
            getString(R.string.editor_summary_targets, builtin + customStunServers.size)
        }
    }

    private fun bindSplitTunnelBody(body: View) {
        val cfg = profile.checksConfig.splitTunnel
        body.findViewById<MaterialSwitch>(R.id.switchSplitProxyScan).isChecked = cfg.proxyScan
        body.findViewById<MaterialSwitch>(R.id.switchSplitXrayApiScan).isChecked = cfg.xrayApiScan
        body.findViewById<TextInputEditText>(R.id.editSplitConnectTimeout).setText(cfg.connectTimeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchSplitCheckUnderlyingNetwork).isChecked = cfg.checkUnderlyingNetwork
        body.findViewById<MaterialSwitch>(R.id.switchSplitCheckVpnNetworkBinding).isChecked = cfg.checkVpnNetworkBinding
        body.findViewById<MaterialSwitch>(R.id.switchSplitCheckMtprotoViaProxy).isChecked = cfg.checkMtprotoViaProxy

        val chipGroup = body.findViewById<ChipGroup>(R.id.chipGroupPortRange)
        val layoutCustom = body.findViewById<LinearLayout>(R.id.layoutCustomPortRange)
        when (cfg.portRange) {
            "full" -> chipGroup.check(R.id.chipPortRangeFull)
            "custom" -> { chipGroup.check(R.id.chipPortRangeCustom); layoutCustom.visibility = View.VISIBLE }
            else -> chipGroup.check(R.id.chipPortRangePopular)
        }
        body.findViewById<TextInputEditText>(R.id.editPortRangeStart).setText(cfg.portRangeStart.toString())
        body.findViewById<TextInputEditText>(R.id.editPortRangeEnd).setText(cfg.portRangeEnd.toString())

        chipGroup.setOnCheckedStateChangeListener { _, _ ->
            layoutCustom.visibility = if (chipGroup.checkedChipId == R.id.chipPortRangeCustom) View.VISIBLE else View.GONE
        }

        sections[CheckerSectionController.SPLIT_TUNNEL]?.summaryProvider = {
            val ids = listOf(
                R.id.switchSplitProxyScan,
                R.id.switchSplitXrayApiScan,
                R.id.switchSplitCheckUnderlyingNetwork,
                R.id.switchSplitCheckVpnNetworkBinding,
                R.id.switchSplitCheckMtprotoViaProxy,
            )
            val on = ids.count { body.findViewById<MaterialSwitch>(it).isChecked }
            getString(R.string.editor_summary_x_of_y_active, on, ids.size)
        }
    }

    // ─── Domain reachability ─────────────────────────────────────────────────

    private fun bindDomainReachabilityBody(body: View) {
        val container = body.findViewById<LinearLayout>(R.id.containerReachabilityDomains)
        rebuildReachabilityPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddReachabilityDomain).setOnClickListener {
            showAddReachabilityDomainDialog(container)
        }

        sections[CheckerSectionController.DOMAIN_REACHABILITY]?.summaryProvider = {
            getString(R.string.editor_summary_domain_reachability, reachabilityDomains.size)
        }
    }

    private fun rebuildReachabilityPills(container: LinearLayout) {
        rebuildEndpointPills(container, reachabilityDomains.mapIndexed { idx, d ->
            EndpointPillData(
                name = d.domain,
                url = d.description.ifEmpty { d.domain },
                scope = null,
                onRemove = {
                    reachabilityDomains.removeAt(idx)
                    rebuildReachabilityPills(container)
                    sections[CheckerSectionController.DOMAIN_REACHABILITY]?.refreshSummary()
                },
                onEdit = {
                    showAddReachabilityDomainDialog(container, editIndex = idx)
                },
            )
        })
    }

    private fun showAddReachabilityDomainDialog(container: LinearLayout, editIndex: Int = -1) {
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddReachabilityDomain) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotDomainReachability) }
        
        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) reachabilityDomains[editIndex] else null
        val initialValues = existing?.let {
            com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.InitialValues(
                url = it.domain,
                label = it.description,
                expectedDns = it.expectedDnsAvailable,
                expectedTcp = it.expectedTcpAvailable,
                expectedTls = it.expectedTlsAvailable,
            )
        }
        
        val controller = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController(slot, viewLifecycleOwner.lifecycleScope)
        controller.show(
            config = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_reachability_domain,
                urlHintRes = R.string.settings_custom_check_domain_field,
                labelHintRes = R.string.settings_custom_check_description_field,
                extraInputHintRes = null,
                extraSwitchTextRes = null,
                showExpectedChecks = true,
                testAction = { domain, _, _ ->
                    val response = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        com.notcvnt.rknhardering.checker.DomainReachabilityChecker.checkSingleDomain(
                            domain = domain,
                            label = domain,
                        )
                    }
                    // Auto-set expected booleans from test result (on Main thread)
                    val dnsOk = response.dnsStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK
                    val tcpOk = response.tcpStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK
                    val tlsOk = response.tlsStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK
                    controller.setExpectedChecks(dnsOk, tcpOk, tlsOk)

                    val statusIcon = { ok: Boolean -> if (ok) "\u2705" else "\u274c" }
                    val msg = getString(
                        R.string.domain_reachability_test_result,
                        statusIcon(dnsOk),
                        statusIcon(tcpOk),
                        statusIcon(tlsOk),
                    )
                    val allOk = dnsOk && tcpOk && tlsOk
                    allOk to msg
                },
                saveAction = { _, _, _, _ -> },
                saveActionEx = { domain, label, _, _, expectedDns, expectedTcp, expectedTls ->
                    val newDomain = CustomDomain(
                        domain = domain,
                        checkType = "reachability",
                        description = label,
                        expectedDnsAvailable = expectedDns,
                        expectedTcpAvailable = expectedTcp,
                        expectedTlsAvailable = expectedTls,
                    )
                    if (editIndex >= 0) {
                        reachabilityDomains[editIndex] = newDomain
                    } else {
                        reachabilityDomains.add(newDomain)
                    }
                    rebuildReachabilityPills(container)
                    sections[CheckerSectionController.DOMAIN_REACHABILITY]?.refreshSummary()
                    btnAdd.visibility = View.VISIBLE
                }
            ),
            onCancel = { btnAdd.visibility = View.VISIBLE },
            initialValues = initialValues,
        )
    }

    // ─── Endpoint pills (reusable) ───────────────────────────────────────────

    private data class EndpointPillData(
        val name: String,
        val url: String,
        val scope: EndpointScope?,
        val onRemove: () -> Unit,
        val onEdit: (() -> Unit)? = null,
    )

    private fun rebuildEndpointPills(container: LinearLayout, items: List<EndpointPillData>) {
        container.removeAllViews()
        items.forEach { data ->
            container.addView(makePillView(container, data))
        }
    }

    private fun rebuildGeoIpPills(container: LinearLayout) {
        rebuildEndpointPills(container, customGeoIpProviders.mapIndexed { idx, p ->
            EndpointPillData(
                name = p.name.ifBlank { p.url },
                url = p.url,
                scope = null,
                onRemove = {
                    customGeoIpProviders.removeAt(idx)
                    rebuildGeoIpPills(container)
                    sections[CheckerSectionController.GEO_IP]?.refreshSummary()
                },
                onEdit = {
                    showEditGeoIpEndpoint(container, idx)
                },
            )
        })
    }

    private fun rebuildIpPills(container: LinearLayout) {
        rebuildEndpointPills(container, customIpEndpoints.mapIndexed { idx, ep ->
            EndpointPillData(
                name = ep.label.ifBlank { ep.url },
                url = ep.url,
                scope = ep.scope,
                onRemove = {
                    customIpEndpoints.removeAt(idx)
                    rebuildIpPills(container)
                    sections[CheckerSectionController.IP_COMPARISON]?.refreshSummary()
                },
                onEdit = {
                    showEditIpEndpoint(container, idx)
                },
            )
        })
    }

    private fun rebuildCdnPills(container: LinearLayout) {
        rebuildEndpointPills(container, customCdnTargets.mapIndexed { idx, t ->
            EndpointPillData(
                name = t.label.ifBlank { t.url },
                url = t.url,
                scope = null,
                onRemove = {
                    customCdnTargets.removeAt(idx)
                    rebuildCdnPills(container)
                    sections[CheckerSectionController.CDN_PULLING]?.refreshSummary()
                },
                onEdit = {
                    showEditCdnEndpoint(container, idx)
                },
            )
        })
    }

    private fun rebuildIcmpPills(container: LinearLayout) {
        rebuildEndpointPills(container, customIcmpTargets.mapIndexed { idx, t ->
            EndpointPillData(
                name = t.label.ifBlank { t.host },
                url = "ping ${t.host}",
                scope = null,
                onRemove = {
                    customIcmpTargets.removeAt(idx)
                    rebuildIcmpPills(container)
                    sections[CheckerSectionController.ICMP_SPOOFING]?.refreshSummary()
                },
                onEdit = {
                    showAddIcmpTargetDialog(container, editIndex = idx)
                },
            )
        })
    }

    private fun rebuildRttPills(container: LinearLayout) {
        rebuildEndpointPills(container, customRttTargets.mapIndexed { idx, t ->
            EndpointPillData(
                name = t.label.ifBlank { t.host },
                url = "ping ${t.host}",
                scope = null,
                onRemove = {
                    customRttTargets.removeAt(idx)
                    rebuildRttPills(container)
                    sections[CheckerSectionController.RTT_TRIANGULATION]?.refreshSummary()
                },
                onEdit = {
                    showAddRttTargetDialog(container, editIndex = idx)
                },
            )
        })
    }

    private fun rebuildStunPills(container: LinearLayout) {
        rebuildEndpointPills(container, customStunServers.mapIndexed { idx, s ->
            EndpointPillData(
                name = s.label.ifBlank { "${s.host}:${s.port}" },
                url = "stun://${s.host}:${s.port}",
                scope = null,
                onRemove = {
                    customStunServers.removeAt(idx)
                    rebuildStunPills(container)
                    sections[CheckerSectionController.CALL_TRANSPORT]?.refreshSummary()
                },
                onEdit = {
                    showAddStunDialog(container, editIndex = idx)
                },
            )
        })
    }

    private fun makePillView(parent: ViewGroup, data: EndpointPillData): View {
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
    // ─── Edit existing endpoint (InlineEndpointEditorController) ─────────────

    private fun showEditGeoIpEndpoint(container: LinearLayout, idx: Int) {
        val body = container.parent as ViewGroup
        val slot = body.findViewById<ViewGroup>(R.id.inlineEditorSlotGeoIp)
        val btnAdd = body.findViewById<MaterialButton>(R.id.btnAddGeoIpEndpoint)
        btnAdd.visibility = View.GONE

        val p = customGeoIpProviders[idx]
        val editor = InlineEndpointEditorController(slot, viewLifecycleOwner.lifecycleScope)
        geoIpEditor = editor
        editor.show(
            kind = InlineEndpointEditorController.Kind.GEO_IP,
            onCancel = { btnAdd.visibility = View.VISIBLE; geoIpEditor = null },
            onSave = { result ->
                customGeoIpProviders[idx] = CustomGeoIpProvider(
                    name = result.label,
                    url = result.url,
                    responseMapping = result.mapping,
                )
                rebuildGeoIpPills(container)
                btnAdd.visibility = View.VISIBLE
                geoIpEditor = null
                sections[CheckerSectionController.GEO_IP]?.refreshSummary()
            },
            editData = InlineEndpointEditorController.EditData(
                url = p.url,
                label = p.name,
                mapping = p.responseMapping,
            ),
        )
    }

    private fun showEditIpEndpoint(container: LinearLayout, idx: Int) {
        val body = container.parent as ViewGroup
        val slot = body.findViewById<ViewGroup>(R.id.inlineEditorSlotIp)
        val btnAdd = body.findViewById<MaterialButton>(R.id.btnAddIpEndpoint)
        btnAdd.visibility = View.GONE

        val ep = customIpEndpoints[idx]
        val editor = InlineEndpointEditorController(slot, viewLifecycleOwner.lifecycleScope)
        ipEditor = editor
        editor.show(
            kind = InlineEndpointEditorController.Kind.IP_COMPARISON,
            onCancel = { btnAdd.visibility = View.VISIBLE; ipEditor = null },
            onSave = { result ->
                customIpEndpoints[idx] = CustomIpEndpoint(
                    label = result.label,
                    url = result.url,
                    scope = result.scope,
                    responseMapping = result.mapping,
                )
                rebuildIpPills(container)
                btnAdd.visibility = View.VISIBLE
                ipEditor = null
                sections[CheckerSectionController.IP_COMPARISON]?.refreshSummary()
            },
            editData = InlineEndpointEditorController.EditData(
                url = ep.url,
                label = ep.label,
                mapping = ep.responseMapping,
                scope = ep.scope,
            ),
        )
    }

    private fun showEditCdnEndpoint(container: LinearLayout, idx: Int) {
        val body = container.parent as ViewGroup
        val slot = body.findViewById<ViewGroup>(R.id.inlineEditorSlotCdn)
        val btnAdd = body.findViewById<MaterialButton>(R.id.btnAddCdnEndpoint)
        btnAdd.visibility = View.GONE

        val t = customCdnTargets[idx]
        val editor = InlineEndpointEditorController(slot, viewLifecycleOwner.lifecycleScope)
        cdnEditor = editor
        editor.show(
            kind = InlineEndpointEditorController.Kind.CDN,
            onCancel = { btnAdd.visibility = View.VISIBLE; cdnEditor = null },
            onSave = { result ->
                customCdnTargets[idx] = CustomCdnTarget(
                    label = result.label,
                    url = result.url,
                    responseMapping = result.mapping,
                )
                rebuildCdnPills(container)
                btnAdd.visibility = View.VISIBLE
                cdnEditor = null
                sections[CheckerSectionController.CDN_PULLING]?.refreshSummary()
            },
            editData = InlineEndpointEditorController.EditData(
                url = t.url,
                label = t.label,
                mapping = t.responseMapping,
            ),
        )
    }

    // ─── Add target dialogs (no inline editor for these — keep MaterialAlertDialog) ──

    private fun showAddIcmpTargetDialog(container: LinearLayout, editIndex: Int = -1) {
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddIcmpTarget) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotIcmp) }
        
        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) customIcmpTargets[editIndex] else null
        val initialValues = existing?.let {
            com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.InitialValues(
                url = it.host, label = it.label, switchChecked = it.isControl,
            )
        }
        
        val controller = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController(slot, viewLifecycleOwner.lifecycleScope)
        controller.show(
            config = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_icmp_target,
                urlHintRes = R.string.settings_custom_check_target_host,
                labelHintRes = R.string.settings_custom_check_target_label,
                extraInputHintRes = null,
                extraSwitchTextRes = R.string.settings_custom_check_icmp_target_is_control,
                testAction = { host, _, _ ->
                    val result = runCatching { com.notcvnt.rknhardering.probe.SystemPingProber.probe(host, count = 1, replyTimeoutSeconds = 3) }.getOrNull()
                    if (result != null && result.hasReplies) {
                        true to "Ping OK: ${result.avgRttMs}ms"
                    } else {
                        false to "Ping failed or timeout"
                    }
                },
                saveAction = { host, label, _, isControl ->
                    val l = label.ifBlank { host }
                    val target = IcmpTarget(host = host, label = l, isControl = isControl)
                    if (editIndex >= 0) {
                        customIcmpTargets[editIndex] = target
                    } else {
                        customIcmpTargets.add(target)
                    }
                    rebuildIcmpPills(container)
                    sections[CheckerSectionController.ICMP_SPOOFING]?.refreshSummary()
                    btnAdd.visibility = View.VISIBLE
                }
            ),
            onCancel = { btnAdd.visibility = View.VISIBLE },
            initialValues = initialValues,
        )
    }

    private fun showAddRttTargetDialog(container: LinearLayout, editIndex: Int = -1) {
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddRttTarget) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotRtt) }
        
        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) customRttTargets[editIndex] else null
        val initialValues = existing?.let {
            com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.InitialValues(
                url = it.host, label = it.label, extraInput = it.expectedLocation,
            )
        }
        
        val controller = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController(slot, viewLifecycleOwner.lifecycleScope)
        controller.show(
            config = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_rtt_target,
                urlHintRes = R.string.settings_custom_check_target_host,
                labelHintRes = R.string.settings_custom_check_target_label,
                extraInputHintRes = R.string.settings_custom_check_rtt_expected_location,
                extraSwitchTextRes = null,
                testAction = { host, _, _ ->
                    val result = runCatching { com.notcvnt.rknhardering.probe.SystemPingProber.probe(host, count = 1, replyTimeoutSeconds = 3) }.getOrNull()
                    if (result != null && result.hasReplies) {
                        true to "Ping OK: ${result.avgRttMs}ms"
                    } else {
                        false to "Ping failed or timeout"
                    }
                },
                saveAction = { host, label, loc, _ ->
                    val l = label.ifBlank { host }
                    val target = RttTarget(host = host, label = l, expectedLocation = loc)
                    if (editIndex >= 0) {
                        customRttTargets[editIndex] = target
                    } else {
                        customRttTargets.add(target)
                    }
                    rebuildRttPills(container)
                    sections[CheckerSectionController.RTT_TRIANGULATION]?.refreshSummary()
                    btnAdd.visibility = View.VISIBLE
                }
            ),
            onCancel = { btnAdd.visibility = View.VISIBLE },
            initialValues = initialValues,
        )
    }

    private fun showAddStunDialog(container: LinearLayout, editIndex: Int = -1) {
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddStunServer) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotStun) }
        
        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) customStunServers[editIndex] else null
        val initialValues = existing?.let {
            com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.InitialValues(
                url = it.host, label = it.label, extraInput = it.port.toString(),
            )
        }
        
        val controller = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController(slot, viewLifecycleOwner.lifecycleScope)
        controller.show(
            config = com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_stun_server,
                urlHintRes = R.string.settings_custom_check_target_host,
                labelHintRes = R.string.settings_custom_check_target_label,
                extraInputHintRes = R.string.settings_custom_check_stun_port,
                extraSwitchTextRes = null,
                testAction = { host, portStr, _ ->
                    val port = portStr.toIntOrNull() ?: 3478
                    val result = runCatching { 
                        com.notcvnt.rknhardering.probe.StunBindingClient.probeDualStack(
                            host = host,
                            port = port,
                            resolverConfig = com.notcvnt.rknhardering.network.DnsResolverConfig.system(),
                            binding = null
                        )
                    }.getOrNull()
                    
                    val mappedIp = result?.ipv4Result?.getOrNull()?.mappedIp ?: result?.ipv6Result?.getOrNull()?.mappedIp
                    if (mappedIp != null) {
                        true to "STUN OK. Mapped IP: $mappedIp"
                    } else {
                        false to "STUN failed"
                    }
                },
                saveAction = { host, label, portStr, _ ->
                    val p = portStr.toIntOrNull() ?: 3478
                    val l = label.ifBlank { host }
                    val server = StunServer(host = host, port = p, label = l)
                    if (editIndex >= 0) {
                        customStunServers[editIndex] = server
                    } else {
                        customStunServers.add(server)
                    }
                    rebuildStunPills(container)
                    sections[CheckerSectionController.CALL_TRANSPORT]?.refreshSummary()
                    btnAdd.visibility = View.VISIBLE
                }
            ),
            onCancel = { btnAdd.visibility = View.VISIBLE },
            initialValues = initialValues,
        )
    }

    private fun makeDialogContainer(ctx: android.content.Context): LinearLayout =
        LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (24 * resources.displayMetrics.density).toInt()
            setPadding(pad, (12 * resources.displayMetrics.density).toInt(), pad, 0)
        }

    private fun makeDialogEdit(
        ctx: android.content.Context,
        hint: String,
        inputType: Int = InputType.TYPE_CLASS_TEXT,
        default: String = "",
    ): TextInputLayout {
        val til = TextInputLayout(
            ctx, null,
            com.google.android.material.R.attr.textInputOutlinedStyle,
        ).apply {
            this.hint = hint
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
            lp.bottomMargin = (8 * resources.displayMetrics.density).toInt()
            layoutParams = lp
        }
        val edit = TextInputEditText(til.context).apply {
            this.inputType = inputType
            setText(default)
        }
        til.addView(edit)
        return til
    }

    // ─── Custom domains (compact list) ───────────────────────────────────────

    private fun bindCustomDomains(view: View) {
        val container = view.findViewById<LinearLayout>(R.id.containerCustomDomains)
        customDomains.clear()
        reachabilityDomains.clear()
        profile.customDomains.forEach { d ->
            if (isReachabilityType(d.checkType)) {
                reachabilityDomains.add(d.copy(checkType = "reachability"))
            } else {
                customDomains.add(d)
            }
        }
        rebuildDomainList(container)
        view.findViewById<MaterialButton>(R.id.btnAddCustomDomain).setOnClickListener {
            showAddCustomDomainDialog(container)
        }
    }

    private fun isReachabilityType(checkType: String): Boolean {
        val ct = checkType.trim().lowercase()
        return ct == "reachability" || ct == "dpi"
    }

    private fun rebuildDomainList(container: LinearLayout) {
        container.removeAllViews()
        customDomains.forEachIndexed { idx, cd ->
            val view = makePillView(
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
                testAction = { domain, checkType, _ ->
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
                    if (isReachabilityType(ct)) {
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

        val geoBody = sections[CheckerSectionController.GEO_IP]?.body?.getChildAt(0)
        val ipBody = sections[CheckerSectionController.IP_COMPARISON]?.body?.getChildAt(0)
        val cdnBody = sections[CheckerSectionController.CDN_PULLING]?.body?.getChildAt(0)
        val directBody = sections[CheckerSectionController.DIRECT_SIGNS]?.body?.getChildAt(0)
        val indirectBody = sections[CheckerSectionController.INDIRECT_SIGNS]?.body?.getChildAt(0)
        val locBody = sections[CheckerSectionController.LOCATION_SIGNALS]?.body?.getChildAt(0)
        val icmpBody = sections[CheckerSectionController.ICMP_SPOOFING]?.body?.getChildAt(0)
        val rttBody = sections[CheckerSectionController.RTT_TRIANGULATION]?.body?.getChildAt(0)
        val callBody = sections[CheckerSectionController.CALL_TRANSPORT]?.body?.getChildAt(0)
        val splitBody = sections[CheckerSectionController.SPLIT_TUNNEL]?.body?.getChildAt(0)

        val newConfig = ChecksConfig(
            geoIp = GeoIpConfig(
                enabled = sections[CheckerSectionController.GEO_IP]?.isMasterEnabled() ?: true,
                timeoutMs = geoBody?.findViewById<TextInputEditText>(R.id.editGeoIpTimeout)?.text?.toString()?.toIntOrNull() ?: 10_000,
                builtinProviders = mapOf(
                    "ipapi.is" to (geoBody?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpapiIs)?.isChecked ?: true),
                    "iplocate.io" to (geoBody?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplocate)?.isChecked ?: true),
                    "ipquery.io" to (geoBody?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpquery)?.isChecked ?: true),
                    "iplookup.it" to (geoBody?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplookup)?.isChecked ?: true),
                    "ipbot.com" to (geoBody?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpbot)?.isChecked ?: true),
                ),
                customProviders = customGeoIpProviders.toList(),
            ),
            ipComparison = IpComparisonConfig(
                enabled = sections[CheckerSectionController.IP_COMPARISON]?.isMasterEnabled() ?: true,
                timeoutMs = ipBody?.findViewById<TextInputEditText>(R.id.editIpComparisonTimeout)?.text?.toString()?.toIntOrNull() ?: 8_000,
                builtinRuCheckersEnabled = ipBody?.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinRu)?.isChecked ?: true,
                builtinNonRuCheckersEnabled = ipBody?.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinNonRu)?.isChecked ?: true,
                customEndpoints = customIpEndpoints.toList(),
            ),
            cdnPulling = CdnPullingConfig(
                enabled = sections[CheckerSectionController.CDN_PULLING]?.isMasterEnabled() ?: false,
                timeoutMs = cdnBody?.findViewById<TextInputEditText>(R.id.editCdnTimeout)?.text?.toString()?.toIntOrNull() ?: 10_000,
                builtinTargetsEnabled = cdnBody?.findViewById<MaterialSwitch>(R.id.switchCdnBuiltinTargets)?.isChecked ?: true,
                meduzaEnabled = cdnBody?.findViewById<MaterialSwitch>(R.id.switchCdnMeduza)?.isChecked ?: true,
                rutrackerEnabled = cdnBody?.findViewById<MaterialSwitch>(R.id.switchCdnRutracker)?.isChecked ?: true,
                customTargets = customCdnTargets.toList(),
            ),
            directSigns = DirectSignsConfig(
                enabled = sections[CheckerSectionController.DIRECT_SIGNS]?.isMasterEnabled() ?: true,
                checkTransportVpn = directBody?.findViewById<MaterialSwitch>(R.id.switchDirectTransportVpn)?.isChecked ?: true,
                checkHttpProxy = directBody?.findViewById<MaterialSwitch>(R.id.switchDirectHttpProxy)?.isChecked ?: true,
                checkSocksProxy = directBody?.findViewById<MaterialSwitch>(R.id.switchDirectSocksProxy)?.isChecked ?: true,
                checkProxyInfo = directBody?.findViewById<MaterialSwitch>(R.id.switchDirectProxyInfo)?.isChecked ?: true,
                checkVpnService = directBody?.findViewById<MaterialSwitch>(R.id.switchDirectVpnService)?.isChecked ?: true,
            ),
            indirectSigns = IndirectSignsConfig(
                enabled = sections[CheckerSectionController.INDIRECT_SIGNS]?.isMasterEnabled() ?: true,
                checkNotVpnCap = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectNotVpnCap)?.isChecked ?: true,
                checkVpnInterfaces = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectVpnInterfaces)?.isChecked ?: true,
                checkMtuAnomaly = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectMtuAnomaly)?.isChecked ?: true,
                checkIpsec = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectIpsec)?.isChecked ?: true,
                checkRouting = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectRouting)?.isChecked ?: true,
                checkDns = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectDns)?.isChecked ?: true,
                checkProxyTools = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectProxyTools)?.isChecked ?: true,
                checkLocalListeners = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectLocalListeners)?.isChecked ?: true,
                checkDumpsys = indirectBody?.findViewById<MaterialSwitch>(R.id.switchIndirectDumpsys)?.isChecked ?: true,
                listenerPortThreshold = indirectBody?.findViewById<TextInputEditText>(R.id.editIndirectListenerPortThreshold)
                    ?.text?.toString()?.toIntOrNull() ?: 5,
            ),
            nativeSigns = CheckToggle(enabled = sections[CheckerSectionController.NATIVE_SIGNS]?.isMasterEnabled() ?: true),
            locationSignals = LocationSignalsConfig(
                enabled = sections[CheckerSectionController.LOCATION_SIGNALS]?.isMasterEnabled() ?: true,
                checkBeacondb = locBody?.findViewById<MaterialSwitch>(R.id.switchLocationBeacondb)?.isChecked ?: true,
                checkCellTowers = locBody?.findViewById<MaterialSwitch>(R.id.switchLocationCellTowers)?.isChecked ?: true,
                checkWifiSignals = locBody?.findViewById<MaterialSwitch>(R.id.switchLocationWifiSignals)?.isChecked ?: true,
            ),
            icmpSpoofing = IcmpSpoofingConfig(
                enabled = sections[CheckerSectionController.ICMP_SPOOFING]?.isMasterEnabled() ?: false,
                timeoutMs = icmpBody?.findViewById<TextInputEditText>(R.id.editIcmpTimeout)?.text?.toString()?.toIntOrNull() ?: 5_000,
                pingCount = icmpBody?.findViewById<TextInputEditText>(R.id.editIcmpPingCount)?.text?.toString()?.toIntOrNull() ?: 3,
                builtinTargetsEnabled = icmpBody?.findViewById<MaterialSwitch>(R.id.switchIcmpBuiltinTargets)?.isChecked ?: true,
                customTargets = customIcmpTargets.toList(),
            ),
            rttTriangulation = RttTriangulationConfig(
                enabled = sections[CheckerSectionController.RTT_TRIANGULATION]?.isMasterEnabled() ?: false,
                timeoutMs = rttBody?.findViewById<TextInputEditText>(R.id.editRttTimeout)?.text?.toString()?.toIntOrNull() ?: 5_000,
                pingCount = rttBody?.findViewById<TextInputEditText>(R.id.editRttPingCount)?.text?.toString()?.toIntOrNull() ?: 5,
                builtinTargetsEnabled = rttBody?.findViewById<MaterialSwitch>(R.id.switchRttBuiltinTargets)?.isChecked ?: true,
                customTargets = customRttTargets.toList(),
            ),
            callTransport = CallTransportConfig(
                enabled = sections[CheckerSectionController.CALL_TRANSPORT]?.isMasterEnabled() ?: false,
                timeoutMs = callBody?.findViewById<TextInputEditText>(R.id.editCallTransportTimeout)?.text?.toString()?.toIntOrNull() ?: 5_000,
                builtinGlobalStunEnabled = callBody?.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinGlobalStun)?.isChecked ?: true,
                builtinRuStunEnabled = callBody?.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinRuStun)?.isChecked ?: true,
                checkMtproto = callBody?.findViewById<MaterialSwitch>(R.id.switchCallTransportMtproto)?.isChecked ?: true,
                customStunServers = customStunServers.toList(),
            ),
            splitTunnel = SplitTunnelConfig(
                enabled = sections[CheckerSectionController.SPLIT_TUNNEL]?.isMasterEnabled() ?: true,
                proxyScan = splitBody?.findViewById<MaterialSwitch>(R.id.switchSplitProxyScan)?.isChecked ?: true,
                xrayApiScan = splitBody?.findViewById<MaterialSwitch>(R.id.switchSplitXrayApiScan)?.isChecked ?: true,
                portRange = when (splitBody?.findViewById<ChipGroup>(R.id.chipGroupPortRange)?.checkedChipId) {
                    R.id.chipPortRangeFull -> "full"
                    R.id.chipPortRangeCustom -> "custom"
                    else -> "popular"
                },
                portRangeStart = splitBody?.findViewById<TextInputEditText>(R.id.editPortRangeStart)?.text?.toString()?.toIntOrNull() ?: 1024,
                portRangeEnd = splitBody?.findViewById<TextInputEditText>(R.id.editPortRangeEnd)?.text?.toString()?.toIntOrNull() ?: 65535,
                connectTimeoutMs = splitBody?.findViewById<TextInputEditText>(R.id.editSplitConnectTimeout)?.text?.toString()?.toIntOrNull() ?: 300,
                checkUnderlyingNetwork = splitBody?.findViewById<MaterialSwitch>(R.id.switchSplitCheckUnderlyingNetwork)?.isChecked ?: true,
                checkVpnNetworkBinding = splitBody?.findViewById<MaterialSwitch>(R.id.switchSplitCheckVpnNetworkBinding)?.isChecked ?: true,
                checkMtprotoViaProxy = splitBody?.findViewById<MaterialSwitch>(R.id.switchSplitCheckMtprotoViaProxy)?.isChecked ?: true,
            ),
            domainReachabilityEnabled = sections[CheckerSectionController.DOMAIN_REACHABILITY]?.isMasterEnabled() ?: true,
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
            customDomains = (customDomains + reachabilityDomains).toList(),
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
