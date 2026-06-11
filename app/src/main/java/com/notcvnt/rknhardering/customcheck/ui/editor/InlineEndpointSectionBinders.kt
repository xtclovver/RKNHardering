package com.notcvnt.rknhardering.customcheck.ui.editor

import android.view.View
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.customcheck.CdnPullingConfig
import com.notcvnt.rknhardering.customcheck.CustomCdnTarget
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomGeoIpProvider
import com.notcvnt.rknhardering.customcheck.CustomIpEndpoint
import com.notcvnt.rknhardering.customcheck.GeoIpConfig
import com.notcvnt.rknhardering.customcheck.IpComparisonConfig
import com.notcvnt.rknhardering.customcheck.ui.CheckerSectionController
import com.notcvnt.rknhardering.customcheck.ui.InlineEndpointEditorController

internal class GeoIpSectionBinder(host: SectionBinder.Host) : SectionBinder<GeoIpConfig>(host) {

    override val sectionId = CheckerSectionController.GEO_IP
    override val titleRes = R.string.settings_custom_check_section_geo_ip
    override val iconRes = R.drawable.ic_public
    override val bodyLayout = R.layout.section_body_geo_ip

    private val endpoints = InlineEndpointSection<CustomGeoIpProvider>(
        host = host,
        sectionId = sectionId,
        kind = InlineEndpointEditorController.Kind.GEO_IP,
        slotId = R.id.inlineEditorSlotGeoIp,
        addButtonId = R.id.btnAddGeoIpEndpoint,
        containerId = R.id.containerGeoIpEndpoints,
        pillName = { it.name.ifBlank { it.url } },
        pillUrl = { it.url },
        pillScope = { null },
        fromResult = { result ->
            CustomGeoIpProvider(
                name = result.label,
                url = result.url,
                responseMapping = result.mapping,
            )
        },
        toEditData = { p ->
            InlineEndpointEditorController.EditData(
                url = p.url,
                label = p.name,
                mapping = p.responseMapping,
            )
        },
    )

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.geoIp
        body.findViewById<TextInputEditText>(R.id.editGeoIpTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpapiIs).isChecked = cfg.builtinProviders["ipapi.is"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplocate).isChecked = cfg.builtinProviders["iplocate.io"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpquery).isChecked = cfg.builtinProviders["ipquery.io"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplookup).isChecked = cfg.builtinProviders["iplookup.it"] != false
        body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpbot).isChecked = cfg.builtinProviders["ipbot.com"] != false

        endpoints.bind(body, cfg.customProviders)
    }

    override fun collect(body: View?, enabled: Boolean): GeoIpConfig = GeoIpConfig(
        enabled = enabled,
        timeoutMs = body?.findViewById<TextInputEditText>(R.id.editGeoIpTimeout)?.text?.toString()?.toIntOrNull() ?: 10_000,
        builtinProviders = mapOf(
            "ipapi.is" to (body?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpapiIs)?.isChecked ?: true),
            "iplocate.io" to (body?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplocate)?.isChecked ?: true),
            "ipquery.io" to (body?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpquery)?.isChecked ?: true),
            "iplookup.it" to (body?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplookup)?.isChecked ?: true),
            "ipbot.com" to (body?.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpbot)?.isChecked ?: true),
        ),
        customProviders = endpoints.items.toList(),
    )

    override fun summary(body: View): String {
        val builtinTotal = 5
        val builtinOn = listOf(
            body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpapiIs).isChecked,
            body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplocate).isChecked,
            body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpquery).isChecked,
            body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIplookup).isChecked,
            body.findViewById<MaterialSwitch>(R.id.switchGeoIpBuiltinIpbot).isChecked,
        ).count { it }
        return host.string(R.string.editor_summary_geoip, builtinOn, builtinTotal, endpoints.items.size)
    }
}

internal class IpComparisonSectionBinder(host: SectionBinder.Host) : SectionBinder<IpComparisonConfig>(host) {

    override val sectionId = CheckerSectionController.IP_COMPARISON
    override val titleRes = R.string.settings_custom_check_section_ip_comparison
    override val iconRes = R.drawable.ic_compare_arrows
    override val bodyLayout = R.layout.section_body_ip_comparison

    private val endpoints = InlineEndpointSection<CustomIpEndpoint>(
        host = host,
        sectionId = sectionId,
        kind = InlineEndpointEditorController.Kind.IP_COMPARISON,
        slotId = R.id.inlineEditorSlotIp,
        addButtonId = R.id.btnAddIpEndpoint,
        containerId = R.id.containerIpEndpoints,
        pillName = { it.label.ifBlank { it.url } },
        pillUrl = { it.url },
        pillScope = { it.scope },
        fromResult = { result ->
            CustomIpEndpoint(
                label = result.label,
                url = result.url,
                scope = result.scope,
                responseMapping = result.mapping,
            )
        },
        toEditData = { ep ->
            InlineEndpointEditorController.EditData(
                url = ep.url,
                label = ep.label,
                mapping = ep.responseMapping,
                scope = ep.scope,
            )
        },
    )

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.ipComparison
        body.findViewById<TextInputEditText>(R.id.editIpComparisonTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinRu).isChecked = cfg.builtinRuCheckersEnabled
        body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinNonRu).isChecked = cfg.builtinNonRuCheckersEnabled

        endpoints.bind(body, cfg.customEndpoints)
    }

    override fun collect(body: View?, enabled: Boolean): IpComparisonConfig = IpComparisonConfig(
        enabled = enabled,
        timeoutMs = body?.findViewById<TextInputEditText>(R.id.editIpComparisonTimeout)?.text?.toString()?.toIntOrNull() ?: 8_000,
        builtinRuCheckersEnabled = body?.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinRu)?.isChecked ?: true,
        builtinNonRuCheckersEnabled = body?.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinNonRu)?.isChecked ?: true,
        customEndpoints = endpoints.items.toList(),
    )

    override fun summary(body: View): String {
        val ru = if (body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinRu).isChecked) 1 else 0
        val nonRu = if (body.findViewById<MaterialSwitch>(R.id.switchIpComparisonBuiltinNonRu).isChecked) 1 else 0
        return host.string(R.string.editor_summary_ip_comparison, ru + nonRu, 2, endpoints.items.size)
    }
}

internal class CdnPullingSectionBinder(host: SectionBinder.Host) : SectionBinder<CdnPullingConfig>(host) {

    override val sectionId = CheckerSectionController.CDN_PULLING
    override val titleRes = R.string.settings_custom_check_section_cdn_pulling
    override val iconRes = R.drawable.ic_cloud
    override val bodyLayout = R.layout.section_body_cdn_pulling
    override val enabledFallback = false

    private val endpoints = InlineEndpointSection<CustomCdnTarget>(
        host = host,
        sectionId = sectionId,
        kind = InlineEndpointEditorController.Kind.CDN,
        slotId = R.id.inlineEditorSlotCdn,
        addButtonId = R.id.btnAddCdnEndpoint,
        containerId = R.id.containerCdnEndpoints,
        pillName = { it.label.ifBlank { it.url } },
        pillUrl = { it.url },
        pillScope = { null },
        fromResult = { result ->
            CustomCdnTarget(
                label = result.label,
                url = result.url,
                responseMapping = result.mapping,
            )
        },
        toEditData = { t ->
            InlineEndpointEditorController.EditData(
                url = t.url,
                label = t.label,
                mapping = t.responseMapping,
            )
        },
    )

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.cdnPulling
        body.findViewById<TextInputEditText>(R.id.editCdnTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchCdnBuiltinTargets).isChecked = cfg.builtinTargetsEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCdnMeduza).isChecked = cfg.meduzaEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCdnRutracker).isChecked = cfg.rutrackerEnabled

        endpoints.bind(body, cfg.customTargets)
    }

    override fun collect(body: View?, enabled: Boolean): CdnPullingConfig = CdnPullingConfig(
        enabled = enabled,
        timeoutMs = body?.findViewById<TextInputEditText>(R.id.editCdnTimeout)?.text?.toString()?.toIntOrNull() ?: 10_000,
        builtinTargetsEnabled = body?.findViewById<MaterialSwitch>(R.id.switchCdnBuiltinTargets)?.isChecked ?: true,
        meduzaEnabled = body?.findViewById<MaterialSwitch>(R.id.switchCdnMeduza)?.isChecked ?: true,
        rutrackerEnabled = body?.findViewById<MaterialSwitch>(R.id.switchCdnRutracker)?.isChecked ?: true,
        customTargets = endpoints.items.toList(),
    )

    override fun summary(body: View): String {
        val builtins = (if (body.findViewById<MaterialSwitch>(R.id.switchCdnBuiltinTargets).isChecked) 1 else 0) +
            (if (body.findViewById<MaterialSwitch>(R.id.switchCdnMeduza).isChecked) 1 else 0) +
            (if (body.findViewById<MaterialSwitch>(R.id.switchCdnRutracker).isChecked) 1 else 0)
        return host.string(R.string.editor_summary_cdn, builtins, 3, endpoints.items.size)
    }
}
