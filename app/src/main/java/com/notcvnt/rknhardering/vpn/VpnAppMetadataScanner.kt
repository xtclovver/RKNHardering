package com.notcvnt.rknhardering.vpn

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.notcvnt.rknhardering.model.VpnAppTechnicalMetadata

object VpnAppMetadataScanner {

    fun scan(
        context: Context,
        packageName: String?,
        serviceNames: List<String> = emptyList(),
        matchedByNameHeuristic: Boolean = false,
    ): VpnAppTechnicalMetadata? {
        if (packageName.isNullOrBlank()) {
            return serviceNames
                .normalizeServiceNames()
                .takeIf { it.isNotEmpty() }
                ?.let { VpnAppTechnicalMetadata(serviceNames = it, matchedByNameHeuristic = matchedByNameHeuristic) }
        }

        val pm = context.packageManager
        val packageInfo = getPackageInfo(pm, packageName)
        val appInfo = packageInfo?.applicationInfo
        val apkInspection = appInfo
            ?.let(::apkPaths)
            ?.let(VpnApkInspector::inspect)
            ?.takeUnless { it.isEmpty }

        if (packageInfo == null && apkInspection == null && serviceNames.isEmpty() && !matchedByNameHeuristic) {
            return null
        }

        return VpnAppTechnicalMetadata(
            versionName = packageInfo?.versionName?.takeIf { it.isNotBlank() },
            serviceNames = (serviceNames + packageInfo.vpnServiceNames()).normalizeServiceNames(),
            appType = apkInspection?.appType,
            coreType = apkInspection?.coreType,
            corePath = apkInspection?.corePath,
            goVersion = apkInspection?.goVersion,
            systemApp = appInfo?.isSystemApp() == true,
            matchedByNameHeuristic = matchedByNameHeuristic,
        )
    }

    fun resolveAppLabel(context: Context, packageName: String?): String? {
        if (packageName.isNullOrBlank()) return null
        val pm = context.packageManager
        return runCatching {
            val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(packageName, 0)
            }
            pm.getApplicationLabel(appInfo)?.toString()?.trim()?.takeIf { it.isNotBlank() }
        }.getOrNull()
    }

    fun formatMetadataSuffix(metadata: VpnAppTechnicalMetadata?): String {
        val details = metadataDetails(metadata)
        return if (details.isEmpty()) "" else " [${details.joinToString(", ")}]"
    }

    fun metadataDetails(metadata: VpnAppTechnicalMetadata?): List<String> {
        if (metadata == null) return emptyList()
        return buildList {
            metadata.versionName?.let { add("version=$it") }
            metadata.appType?.let { add("app=$it") }
            metadata.coreType?.let { add("core=$it") }
            metadata.corePath?.let { add("path=$it") }
            metadata.goVersion?.let { add("go=$it") }
            if (metadata.serviceNames.isNotEmpty()) {
                add("services=${metadata.serviceNames.take(3).joinToString()}")
            }
            if (metadata.matchedByNameHeuristic) add("nameHeuristic=true")
            if (metadata.systemApp) add("systemApp=true")
        }
    }

    private fun getPackageInfo(pm: PackageManager, packageName: String): PackageInfo? {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_SERVICES.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, PackageManager.GET_SERVICES)
            }
        }.getOrNull()
    }

    private fun PackageInfo?.vpnServiceNames(): List<String> {
        return this
            ?.services
            ?.filter { it.permission == Manifest.permission.BIND_VPN_SERVICE }
            ?.mapNotNull { it.name?.trim()?.takeIf(String::isNotEmpty) }
            .orEmpty()
    }

    private fun apkPaths(appInfo: ApplicationInfo): List<String> {
        return buildList {
            appInfo.publicSourceDir?.takeIf { it.isNotBlank() }?.let(::add)
            appInfo.splitPublicSourceDirs?.filter { it.isNotBlank() }?.let(::addAll)
        }
    }

    private fun ApplicationInfo.isSystemApp(): Boolean {
        val system = flags and ApplicationInfo.FLAG_SYSTEM != 0
        val updatedSystem = flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
        return system || updatedSystem
    }

    private fun List<String>.normalizeServiceNames(): List<String> =
        map(String::trim).filter(String::isNotEmpty).distinct()
}
