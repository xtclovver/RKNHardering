package com.notcvnt.rknhardering.vpn

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

data class VpnApkInspectionResult(
    val appType: String? = null,
    val coreType: String? = null,
    val corePath: String? = null,
    val goVersion: String? = null,
) {
    val isEmpty: Boolean
        get() = appType == null && coreType == null && corePath == null && goVersion == null
}

object VpnApkInspector {
    private const val MAX_DEX_BYTES = 15L * 1024L * 1024L
    private const val MAX_NATIVE_LIB_BYTES = 64L * 1024L * 1024L

    fun inspect(apkPaths: List<String>): VpnApkInspectionResult {
        var appType: String? = null
        var core: VpnCoreInspectionResult? = null

        for (path in apkPaths.filter { it.isNotBlank() }.distinct()) {
            val file = File(path)
            if (!file.isFile) continue

            runCatching {
                ZipFile(file).use { zip ->
                    val entries = zip.entries().asSequence().filterNot(ZipEntry::isDirectory).toList()
                    if (appType == null) {
                        appType = inspectAppType(zip, entries)
                    }
                    if (core == null) {
                        core = inspectCoreType(zip, entries)
                    }
                }
            }

            if (appType != null && core != null) break
        }

        return VpnApkInspectionResult(
            appType = appType,
            coreType = core?.coreType,
            corePath = core?.corePath,
            goVersion = core?.goVersion,
        )
    }

    private fun inspectAppType(zip: ZipFile, entries: List<ZipEntry>): String? {
        var fallbackType: String? = null
        for (entry in entries) {
            if (!entry.name.startsWith("classes") || !entry.name.endsWith(".dex")) continue
            if (entry.size < 0L || entry.size > MAX_DEX_BYTES) continue
            val content = runCatching { zip.getInputStream(entry).use { it.readBytes() } }.getOrNull() ?: continue
            val appType = VpnAppClassifier.detectAppType(content) ?: continue
            if (appType == VpnAppClassifier.APP_TYPE_SHADOWSOCKS_ANDROID) {
                fallbackType = appType
            } else {
                return appType
            }
        }
        return fallbackType
    }

    private fun inspectCoreType(zip: ZipFile, entries: List<ZipEntry>): VpnCoreInspectionResult? {
        for (entry in entries) {
            if (!entry.name.startsWith("lib/") || !entry.name.endsWith(".so")) continue
            if (entry.size < 0L || entry.size > MAX_NATIVE_LIB_BYTES) continue
            val content = runCatching { zip.getInputStream(entry).use { it.readBytes() } }.getOrNull() ?: continue
            VpnAppClassifier.detectCore(content, entry.name)?.let { return it }
        }
        return null
    }
}
