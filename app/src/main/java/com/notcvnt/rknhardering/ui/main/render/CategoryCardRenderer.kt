package com.notcvnt.rknhardering.ui.main.render

import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.VpnAppTechnicalMetadata
import com.notcvnt.rknhardering.util.maskInfoValue

/**
 * Renders the plain category result cards (geo IP, direct/indirect signs,
 * location, ICMP, RTT) and the native-signs card. Moved verbatim from
 * MainActivity's displayCategory/displayNativeSigns; the optional
 * info-section views are resolved by the caller and passed per call.
 */
internal class CategoryCardRenderer(
    env: MainRenderEnvironment,
    private val findingViews: FindingViewFactory,
) : SectionRenderer(env) {

    fun render(
        category: CategoryResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout,
        infoSection: LinearLayout?,
        infoDivider: View?,
        privacyMode: Boolean,
    ) {
        card.visibility = View.VISIBLE
        findingsContainer.visibility = View.VISIBLE

        bindCardStatus(category.detected, category.needsReview, icon, status, hasError = category.hasError)

        if (infoSection != null && infoDivider != null) {
            val infoFindings = category.findings.filter { it.isInformational }
            val husiModelFindings = buildHusiModelFindings(category)
            val checkFindings = category.findings.filterNot { it.isInformational || it.isError }

            bindInfoSection(infoFindings + husiModelFindings, infoSection, infoDivider, checkFindings.isNotEmpty(), privacyMode)
            findingsContainer.removeAllViews()
            for (finding in checkFindings) {
                if (finding.description.startsWith("network_mcc_ru:")) continue
                findingsContainer.addView(findingViews.createFindingView(finding, privacyMode))
            }
            return
        }

        findingsContainer.removeAllViews()
        for (finding in category.findings + buildHusiModelFindings(category)) {
            if (finding.isError) continue
            if (finding.description.startsWith("network_mcc_ru:")) continue
            findingsContainer.addView(findingViews.createFindingView(finding, privacyMode))
        }
    }

    fun renderNativeSigns(
        result: CategoryResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        summary: TextView,
        findingsContainer: LinearLayout,
        privacyMode: Boolean,
    ) {
        if (result.findings.isEmpty() && result.evidence.isEmpty()) {
            card.visibility = View.GONE
            return
        }
        card.visibility = View.VISIBLE

        bindCardStatus(
            detected = result.detected,
            needsReview = result.needsReview,
            icon = icon,
            status = status,
            hasError = result.hasError,
        )

        val summaryFinding = result.findings.firstOrNull { finding ->
            finding.description.startsWith("getifaddrs():") ||
                finding.description.startsWith("Native library not loaded")
        }
        if (summaryFinding != null) {
            summary.text = summaryFinding.description
            summary.visibility = View.VISIBLE
        } else {
            summary.visibility = View.GONE
        }

        findingsContainer.removeAllViews()
        val rest = result.findings.filter { it !== summaryFinding }
        if (rest.isNotEmpty()) {
            findingsContainer.visibility = View.VISIBLE
            for (finding in rest) {
                findingsContainer.addView(findingViews.createFindingView(finding, privacyMode))
            }
        } else {
            findingsContainer.visibility = View.GONE
        }
    }

    private fun buildHusiModelFindings(category: CategoryResult): List<Finding> {
        val findings = buildList {
            category.matchedApps.forEach { app ->
                husiModelFinding(
                    label = app.appName,
                    packageName = app.packageName,
                    serviceName = app.technicalMetadata?.serviceNames?.firstOrNull(),
                    metadata = app.technicalMetadata,
                    source = app.source,
                )?.let(::add)
            }
            category.activeApps.forEach { app ->
                husiModelFinding(
                    label = app.packageName ?: app.serviceName ?: "active VPN",
                    packageName = app.packageName,
                    serviceName = app.serviceName,
                    metadata = app.technicalMetadata,
                    source = app.source,
                )?.let(::add)
            }
        }
        return findings.distinctBy { it.packageName.orEmpty() to it.description }
    }

    private fun husiModelFinding(
        label: String,
        packageName: String?,
        serviceName: String?,
        metadata: VpnAppTechnicalMetadata?,
        source: com.notcvnt.rknhardering.model.EvidenceSource?,
    ): Finding? {
        val hasMeaningfulMetadata = metadata != null || !serviceName.isNullOrBlank() || !packageName.isNullOrBlank()
        if (!hasMeaningfulMetadata) return null

        val description = buildString {
            append("HUSI model: ")
            append(label)
            packageName?.takeIf { it.isNotBlank() }?.let {
                append(" · package: ")
                append(it)
            }
            metadata?.versionName?.takeIf { it.isNotBlank() }?.let {
                append(" · app version: ")
                append(it)
            }
            append(" · app type: ")
            append(metadata?.appType ?: "Other")
            append(" · core type: ")
            append(metadata?.coreType ?: "Unknown")
            metadata?.corePath?.takeIf { it.isNotBlank() }?.let {
                append(" · core path: ")
                append(it)
            }
            metadata?.goVersion?.takeIf { it.isNotBlank() }?.let {
                append(" · Go: ")
                append(it)
            }
            serviceName?.takeIf { it.isNotBlank() }?.let {
                append(" · service: ")
                append(it)
            }
        }
        return Finding(
            description = description,
            isInformational = true,
            source = source,
            packageName = packageName,
        )
    }

    private fun bindInfoSection(
        infoFindings: List<Finding>,
        infoSection: LinearLayout,
        infoDivider: View,
        hasCheckFindings: Boolean,
        privacyMode: Boolean,
    ) {
        infoSection.removeAllViews()
        infoSection.visibility = if (infoFindings.isNotEmpty()) View.VISIBLE else View.GONE
        for (finding in infoFindings) {
            val parts = findingViews.splitInfoFinding(finding.description)
            if (parts != null) {
                val value = maskInfoValue(parts.second, privacyMode)
                infoSection.addView(findingViews.createInfoView(parts.first, value))
            } else {
                infoSection.addView(findingViews.createFindingView(finding, privacyMode))
            }
        }
        infoDivider.visibility = if (infoFindings.isNotEmpty() && hasCheckFindings) View.VISIBLE else View.GONE
    }
}
