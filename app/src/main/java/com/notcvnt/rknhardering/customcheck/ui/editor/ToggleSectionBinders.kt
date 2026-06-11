package com.notcvnt.rknhardering.customcheck.ui.editor

import android.view.View
import android.widget.LinearLayout
import com.google.android.material.chip.ChipGroup
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.customcheck.CheckToggle
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.DirectSignsConfig
import com.notcvnt.rknhardering.customcheck.IndirectSignsConfig
import com.notcvnt.rknhardering.customcheck.LocationSignalsConfig
import com.notcvnt.rknhardering.customcheck.SplitTunnelConfig
import com.notcvnt.rknhardering.customcheck.ui.CheckerSectionController

internal class DirectSignsSectionBinder(host: SectionBinder.Host) : SectionBinder<DirectSignsConfig>(host) {

    override val sectionId = CheckerSectionController.DIRECT_SIGNS
    override val titleRes = R.string.settings_custom_check_section_direct_signs
    override val iconRes = R.drawable.ic_security
    override val bodyLayout = R.layout.section_body_direct_signs

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.directSigns
        body.findViewById<MaterialSwitch>(R.id.switchDirectTransportVpn).isChecked = cfg.checkTransportVpn
        body.findViewById<MaterialSwitch>(R.id.switchDirectHttpProxy).isChecked = cfg.checkHttpProxy
        body.findViewById<MaterialSwitch>(R.id.switchDirectSocksProxy).isChecked = cfg.checkSocksProxy
        body.findViewById<MaterialSwitch>(R.id.switchDirectProxyInfo).isChecked = cfg.checkProxyInfo
        body.findViewById<MaterialSwitch>(R.id.switchDirectVpnService).isChecked = cfg.checkVpnService
    }

    override fun collect(body: View?, enabled: Boolean): DirectSignsConfig = DirectSignsConfig(
        enabled = enabled,
        checkTransportVpn = body?.findViewById<MaterialSwitch>(R.id.switchDirectTransportVpn)?.isChecked ?: true,
        checkHttpProxy = body?.findViewById<MaterialSwitch>(R.id.switchDirectHttpProxy)?.isChecked ?: true,
        checkSocksProxy = body?.findViewById<MaterialSwitch>(R.id.switchDirectSocksProxy)?.isChecked ?: true,
        checkProxyInfo = body?.findViewById<MaterialSwitch>(R.id.switchDirectProxyInfo)?.isChecked ?: true,
        checkVpnService = body?.findViewById<MaterialSwitch>(R.id.switchDirectVpnService)?.isChecked ?: true,
    )

    override fun summary(body: View): String {
        val total = 5
        val on = listOf(
            R.id.switchDirectTransportVpn,
            R.id.switchDirectHttpProxy,
            R.id.switchDirectSocksProxy,
            R.id.switchDirectProxyInfo,
            R.id.switchDirectVpnService,
        ).count { body.findViewById<MaterialSwitch>(it).isChecked }
        return host.string(R.string.editor_summary_x_of_y_active, on, total)
    }
}

internal class IndirectSignsSectionBinder(host: SectionBinder.Host) : SectionBinder<IndirectSignsConfig>(host) {

    override val sectionId = CheckerSectionController.INDIRECT_SIGNS
    override val titleRes = R.string.settings_custom_check_section_indirect_signs
    override val iconRes = R.drawable.ic_lan
    override val bodyLayout = R.layout.section_body_indirect_signs

    override fun bind(body: View, profile: CustomCheckProfile) {
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
    }

    override fun collect(body: View?, enabled: Boolean): IndirectSignsConfig = IndirectSignsConfig(
        enabled = enabled,
        checkNotVpnCap = body?.findViewById<MaterialSwitch>(R.id.switchIndirectNotVpnCap)?.isChecked ?: true,
        checkVpnInterfaces = body?.findViewById<MaterialSwitch>(R.id.switchIndirectVpnInterfaces)?.isChecked ?: true,
        checkMtuAnomaly = body?.findViewById<MaterialSwitch>(R.id.switchIndirectMtuAnomaly)?.isChecked ?: true,
        checkIpsec = body?.findViewById<MaterialSwitch>(R.id.switchIndirectIpsec)?.isChecked ?: true,
        checkRouting = body?.findViewById<MaterialSwitch>(R.id.switchIndirectRouting)?.isChecked ?: true,
        checkDns = body?.findViewById<MaterialSwitch>(R.id.switchIndirectDns)?.isChecked ?: true,
        checkProxyTools = body?.findViewById<MaterialSwitch>(R.id.switchIndirectProxyTools)?.isChecked ?: true,
        checkLocalListeners = body?.findViewById<MaterialSwitch>(R.id.switchIndirectLocalListeners)?.isChecked ?: true,
        checkDumpsys = body?.findViewById<MaterialSwitch>(R.id.switchIndirectDumpsys)?.isChecked ?: true,
        listenerPortThreshold = body?.findViewById<TextInputEditText>(R.id.editIndirectListenerPortThreshold)
            ?.text?.toString()?.toIntOrNull() ?: 5,
    )

    override fun summary(body: View): String {
        val ids = listOf(
            R.id.switchIndirectNotVpnCap, R.id.switchIndirectVpnInterfaces,
            R.id.switchIndirectMtuAnomaly, R.id.switchIndirectIpsec,
            R.id.switchIndirectRouting, R.id.switchIndirectDns,
            R.id.switchIndirectProxyTools, R.id.switchIndirectLocalListeners,
            R.id.switchIndirectDumpsys,
        )
        val on = ids.count { body.findViewById<MaterialSwitch>(it).isChecked }
        return host.string(R.string.editor_summary_x_of_y_active, on, ids.size)
    }
}

internal class NativeSignsSectionBinder(host: SectionBinder.Host) : SectionBinder<CheckToggle>(host) {

    override val sectionId = CheckerSectionController.NATIVE_SIGNS
    override val titleRes = R.string.settings_custom_check_section_native_signs
    override val iconRes = R.drawable.ic_lock
    override val bodyLayout = R.layout.section_body_native_signs

    override fun bind(body: View, profile: CustomCheckProfile) {
        // No body content.
    }

    override fun collect(body: View?, enabled: Boolean): CheckToggle = CheckToggle(enabled = enabled)
}

internal class LocationSignalsSectionBinder(host: SectionBinder.Host) : SectionBinder<LocationSignalsConfig>(host) {

    override val sectionId = CheckerSectionController.LOCATION_SIGNALS
    override val titleRes = R.string.settings_custom_check_section_location_signals
    override val iconRes = R.drawable.ic_location_on
    override val bodyLayout = R.layout.section_body_location_signals

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.locationSignals
        body.findViewById<MaterialSwitch>(R.id.switchLocationBeacondb).isChecked = cfg.checkBeacondb
        body.findViewById<MaterialSwitch>(R.id.switchLocationCellTowers).isChecked = cfg.checkCellTowers
        body.findViewById<MaterialSwitch>(R.id.switchLocationWifiSignals).isChecked = cfg.checkWifiSignals
    }

    override fun collect(body: View?, enabled: Boolean): LocationSignalsConfig = LocationSignalsConfig(
        enabled = enabled,
        checkBeacondb = body?.findViewById<MaterialSwitch>(R.id.switchLocationBeacondb)?.isChecked ?: true,
        checkCellTowers = body?.findViewById<MaterialSwitch>(R.id.switchLocationCellTowers)?.isChecked ?: true,
        checkWifiSignals = body?.findViewById<MaterialSwitch>(R.id.switchLocationWifiSignals)?.isChecked ?: true,
    )

    override fun summary(body: View): String {
        val ids = listOf(
            R.id.switchLocationBeacondb,
            R.id.switchLocationCellTowers,
            R.id.switchLocationWifiSignals,
        )
        val on = ids.count { body.findViewById<MaterialSwitch>(it).isChecked }
        return host.string(R.string.editor_summary_x_of_y_active, on, ids.size)
    }
}

internal class SplitTunnelSectionBinder(host: SectionBinder.Host) : SectionBinder<SplitTunnelConfig>(host) {

    override val sectionId = CheckerSectionController.SPLIT_TUNNEL
    override val titleRes = R.string.settings_custom_check_section_split_tunnel
    override val iconRes = R.drawable.ic_call_split
    override val bodyLayout = R.layout.section_body_split_tunnel

    override fun bind(body: View, profile: CustomCheckProfile) {
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
    }

    override fun collect(body: View?, enabled: Boolean): SplitTunnelConfig = SplitTunnelConfig(
        enabled = enabled,
        proxyScan = body?.findViewById<MaterialSwitch>(R.id.switchSplitProxyScan)?.isChecked ?: true,
        xrayApiScan = body?.findViewById<MaterialSwitch>(R.id.switchSplitXrayApiScan)?.isChecked ?: true,
        portRange = when (body?.findViewById<ChipGroup>(R.id.chipGroupPortRange)?.checkedChipId) {
            R.id.chipPortRangeFull -> "full"
            R.id.chipPortRangeCustom -> "custom"
            else -> "popular"
        },
        portRangeStart = body?.findViewById<TextInputEditText>(R.id.editPortRangeStart)?.text?.toString()?.toIntOrNull() ?: 1024,
        portRangeEnd = body?.findViewById<TextInputEditText>(R.id.editPortRangeEnd)?.text?.toString()?.toIntOrNull() ?: 65535,
        connectTimeoutMs = body?.findViewById<TextInputEditText>(R.id.editSplitConnectTimeout)?.text?.toString()?.toIntOrNull() ?: 300,
        checkUnderlyingNetwork = body?.findViewById<MaterialSwitch>(R.id.switchSplitCheckUnderlyingNetwork)?.isChecked ?: true,
        checkVpnNetworkBinding = body?.findViewById<MaterialSwitch>(R.id.switchSplitCheckVpnNetworkBinding)?.isChecked ?: true,
        checkMtprotoViaProxy = body?.findViewById<MaterialSwitch>(R.id.switchSplitCheckMtprotoViaProxy)?.isChecked ?: true,
    )

    override fun summary(body: View): String {
        val ids = listOf(
            R.id.switchSplitProxyScan,
            R.id.switchSplitXrayApiScan,
            R.id.switchSplitCheckUnderlyingNetwork,
            R.id.switchSplitCheckVpnNetworkBinding,
            R.id.switchSplitCheckMtprotoViaProxy,
        )
        val on = ids.count { body.findViewById<MaterialSwitch>(it).isChecked }
        return host.string(R.string.editor_summary_x_of_y_active, on, ids.size)
    }
}
