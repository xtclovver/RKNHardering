package com.notcvnt.rknhardering.checker

import android.content.Context
import android.os.Build
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import com.notcvnt.rknhardering.vpn.VpnAppMetadataScanner
import com.notcvnt.rknhardering.vpn.VpnDumpsysParser

internal fun checkDumpsysVpn(
    context: Context,
    findings: MutableList<Finding>,
    evidence: MutableList<EvidenceItem>,
    activeApps: MutableList<ActiveVpnApp>,
): SignalOutcome {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return SignalOutcome()
    return try {
        val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "vpn_management"))
        val output = process.inputStream.bufferedReader().readText()
        process.waitFor()

        if (VpnDumpsysParser.isUnavailable(output)) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_vpn_unavailable)))
            return SignalOutcome()
        }

        val records = VpnDumpsysParser.parseVpnManagement(output)
            .filter { it.packageName != null || it.serviceName != null }
        if (records.isEmpty()) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_vpn_none)))
            return SignalOutcome()
        }

        var detected = false
        var needsReview = false
        for (record in records) {
            val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
            val metadata = VpnAppMetadataScanner.scan(
                context = context,
                packageName = record.packageName,
                serviceNames = listOfNotNull(record.serviceName),
            )
            val appLabel = VpnAppMetadataScanner.resolveAppLabel(context, record.packageName)
            val confidence = when {
                signature != null -> EvidenceConfidence.HIGH
                record.packageName != null -> EvidenceConfidence.MEDIUM
                else -> EvidenceConfidence.LOW
            }
            val familySuffix = signature?.family?.let { " [$it]" }.orEmpty()
            val description = buildString {
                append(context.getString(R.string.checker_indirect_dumpsys_vpn_line, record.rawLine))
                appLabel?.let { append(" ($it)") }
                append(familySuffix)
                append(VpnAppMetadataScanner.formatMetadataSuffix(metadata))
            }
            findings.add(
                Finding(
                    description = description,
                    detected = true,
                    source = EvidenceSource.ACTIVE_VPN,
                    confidence = confidence,
                    family = signature?.family,
                    packageName = record.packageName,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.ACTIVE_VPN,
                    detected = true,
                    confidence = confidence,
                    description = record.rawLine,
                    family = signature?.family,
                    packageName = record.packageName,
                    kind = signature?.kind,
                ),
            )
            activeApps.add(
                ActiveVpnApp(
                    packageName = record.packageName,
                    serviceName = record.serviceName,
                    family = signature?.family,
                    kind = signature?.kind,
                    source = EvidenceSource.ACTIVE_VPN,
                    confidence = confidence,
                    technicalMetadata = metadata,
                ),
            )
            detected = true
            needsReview = needsReview || signature == null
        }

        SignalOutcome(detected = detected, needsReview = needsReview)
    } catch (e: Exception) {
        findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_vpn_error, e.message)))
        SignalOutcome()
    }
}

internal fun checkDumpsysVpnService(
    context: Context,
    findings: MutableList<Finding>,
    evidence: MutableList<EvidenceItem>,
    activeApps: MutableList<ActiveVpnApp>,
): SignalOutcome {
    return try {
        val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "activity", "services", "android.net.VpnService"))
        val output = process.inputStream.bufferedReader().readText()
        process.waitFor()

        if (VpnDumpsysParser.isUnavailable(output)) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_service_unavailable)))
            return SignalOutcome()
        }

        val records = VpnDumpsysParser.parseVpnServices(output)
        if (records.isEmpty()) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_service_none)))
            return SignalOutcome()
        }

        var detected = false
        var needsReview = false
        for (record in records) {
            val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
            val metadata = VpnAppMetadataScanner.scan(
                context = context,
                packageName = record.packageName,
                serviceNames = listOfNotNull(record.serviceName),
            )
            val appLabel = VpnAppMetadataScanner.resolveAppLabel(context, record.packageName)
            val confidence = when {
                signature != null -> EvidenceConfidence.HIGH
                record.packageName != null -> EvidenceConfidence.MEDIUM
                else -> EvidenceConfidence.LOW
            }
            val serviceDisplay = if (record.packageName != null && record.serviceName != null) {
                "${record.packageName}/${record.serviceName}"
            } else {
                record.rawLine
            }
            val familySuffix = signature?.family?.let { " [$it]" }.orEmpty()
            val description = buildString {
                append(context.getString(R.string.checker_indirect_dumpsys_service_active, serviceDisplay))
                appLabel?.let { append(" ($it)") }
                append(familySuffix)
                append(VpnAppMetadataScanner.formatMetadataSuffix(metadata))
            }
            findings.add(
                Finding(
                    description = description,
                    detected = true,
                    source = EvidenceSource.ACTIVE_VPN,
                    confidence = confidence,
                    family = signature?.family,
                    packageName = record.packageName,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.ACTIVE_VPN,
                    detected = true,
                    confidence = confidence,
                    description = serviceDisplay,
                    family = signature?.family,
                    packageName = record.packageName,
                    kind = signature?.kind,
                ),
            )
            activeApps.add(
                ActiveVpnApp(
                    packageName = record.packageName,
                    serviceName = record.serviceName,
                    family = signature?.family,
                    kind = signature?.kind,
                    source = EvidenceSource.ACTIVE_VPN,
                    confidence = confidence,
                    technicalMetadata = metadata,
                ),
            )
            detected = true
            needsReview = needsReview || signature == null
        }

        SignalOutcome(detected = detected, needsReview = needsReview)
    } catch (e: Exception) {
        findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_service_error, e.message)))
        SignalOutcome()
    }
}
