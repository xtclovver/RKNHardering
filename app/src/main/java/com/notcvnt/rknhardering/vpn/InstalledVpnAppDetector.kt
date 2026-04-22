package com.notcvnt.rknhardering.vpn

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.model.VpnAppKind

data class InstalledVpnDetectionResult(
    val findings: List<Finding>,
    val evidence: List<EvidenceItem>,
    val matchedApps: List<MatchedVpnApp>,
    val needsReview: Boolean,
)

object InstalledVpnAppDetector {

    fun detect(context: Context): InstalledVpnDetectionResult {
        val pm = context.packageManager
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val matchedApps = linkedMapOf<String, MatchedVpnApp>()

        detectKnownInstalledPackages(context, pm, findings, evidence, matchedApps)
        detectDeclaredVpnServices(context, pm, findings, evidence, matchedApps)
        detectPackagesWithVpnInName(context, pm, findings, evidence, matchedApps)

        if (matchedApps.isEmpty()) {
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_vpn_known_apps_none),
                ),
            )
        }

        return InstalledVpnDetectionResult(
            findings = findings,
            evidence = evidence,
            matchedApps = matchedApps.values.toList(),
            needsReview = false,
        )
    }

    private fun detectKnownInstalledPackages(
        context: Context,
        pm: PackageManager,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        matchedApps: MutableMap<String, MatchedVpnApp>,
    ) {
        for (signature in VpnAppCatalog.signatures) {
            if (!isPackageInstalled(pm, signature.packageName)) continue

            val confidence = when (signature.kind) {
                VpnAppKind.TARGETED_BYPASS -> EvidenceConfidence.MEDIUM
                VpnAppKind.GENERIC_VPN -> EvidenceConfidence.LOW
            }
            val description = context.getString(
                R.string.checker_vpn_installed_app,
                signature.appName,
                signature.packageName,
            )

            findings.add(
                Finding(
                    description = description,
                    isInformational = true,
                    source = EvidenceSource.INSTALLED_APP,
                    confidence = confidence,
                    family = signature.family,
                    packageName = signature.packageName,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.INSTALLED_APP,
                    detected = true,
                    confidence = confidence,
                    description = description,
                    family = signature.family,
                    packageName = signature.packageName,
                    kind = signature.kind,
                ),
            )
            matchedApps.putIfAbsent(
                signature.packageName,
                MatchedVpnApp(
                    packageName = signature.packageName,
                    appName = signature.appName,
                    family = signature.family,
                    kind = signature.kind,
                    source = EvidenceSource.INSTALLED_APP,
                    active = false,
                    confidence = confidence,
                ),
            )
        }
    }

    private fun detectDeclaredVpnServices(
        context: Context,
        pm: PackageManager,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        matchedApps: MutableMap<String, MatchedVpnApp>,
    ) {
        for ((packageName, serviceNames) in queryVpnServiceProviders(pm)) {
            val signature = VpnAppCatalog.findByPackageName(packageName)
            val appName = signature?.appName ?: resolveAppName(pm, packageName)
            val family = signature?.family
            val kind = signature?.kind ?: VpnAppKind.GENERIC_VPN
            val confidence = when (kind) {
                VpnAppKind.TARGETED_BYPASS -> EvidenceConfidence.MEDIUM
                VpnAppKind.GENERIC_VPN -> EvidenceConfidence.MEDIUM
            }
            val serviceSuffix = serviceNames.takeIf { it.isNotEmpty() }?.joinToString()
            val description = buildString {
                append(
                    context.getString(
                        R.string.checker_vpn_declares_service,
                        appName,
                        packageName,
                    ),
                )
                if (!serviceSuffix.isNullOrBlank()) {
                    append(" -> ")
                    append(serviceSuffix)
                }
            }

            findings.add(
                Finding(
                    description = description,
                    isInformational = true,
                    source = EvidenceSource.VPN_SERVICE_DECLARATION,
                    confidence = confidence,
                    family = family,
                    packageName = packageName,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.VPN_SERVICE_DECLARATION,
                    detected = true,
                    confidence = confidence,
                    description = description,
                    family = family,
                    packageName = packageName,
                    kind = kind,
                ),
            )

            matchedApps[packageName] = MatchedVpnApp(
                packageName = packageName,
                appName = appName,
                family = family,
                kind = kind,
                source = EvidenceSource.VPN_SERVICE_DECLARATION,
                active = false,
                confidence = confidence,
            )
        }
    }

    private fun detectPackagesWithVpnInName(
        context: Context,
        pm: PackageManager,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        matchedApps: MutableMap<String, MatchedVpnApp>,
    ) {
        val installedPackages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }

        for (pkg in installedPackages) {
            val packageName = pkg.packageName
            if (matchedApps.containsKey(packageName)) continue

            val appName = resolveAppName(pm, packageName)
            if (!appName.contains("VPN", ignoreCase = true)) continue

            val confidence = EvidenceConfidence.LOW
            val description = context.getString(
                R.string.checker_vpn_installed_app_by_name,
                appName,
                packageName,
            )

            findings.add(
                Finding(
                    description = description,
                    isInformational = true,
                    source = EvidenceSource.INSTALLED_APP,
                    confidence = confidence,
                    packageName = packageName,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.INSTALLED_APP,
                    detected = true,
                    confidence = confidence,
                    description = description,
                    packageName = packageName,
                    kind = VpnAppKind.GENERIC_VPN,
                ),
            )
            matchedApps.putIfAbsent(
                packageName,
                MatchedVpnApp(
                    packageName = packageName,
                    appName = appName,
                    family = null,
                    kind = VpnAppKind.GENERIC_VPN,
                    source = EvidenceSource.INSTALLED_APP,
                    active = false,
                    confidence = confidence,
                ),
            )
        }
    }

    private fun queryVpnServiceProviders(pm: PackageManager): Map<String, List<String>> {
        val intent = Intent(VpnService.SERVICE_INTERFACE)
        val resolveInfos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentServices(intent, PackageManager.ResolveInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentServices(intent, 0)
        }

        return resolveInfos
            .mapNotNull { resolveInfo ->
                val serviceInfo = resolveInfo.serviceInfo ?: return@mapNotNull null
                serviceInfo.packageName to serviceInfo.name
            }
            .groupBy(keySelector = { it.first }, valueTransform = { it.second })
    }

    private fun isPackageInstalled(pm: PackageManager, packageName: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun resolveAppName(pm: PackageManager, packageName: String): String {
        return try {
            val appInfo = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            packageName
        }
    }
}
