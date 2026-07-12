package com.notcvnt.rknhardering.checker

import android.content.Context
import android.os.Build
import android.system.Os
import androidx.core.content.edit
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.model.PrivilegedProbeProvider
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

internal data class BetaCapabilityFingerprint(
    val sdk: Int,
    val manufacturer: String,
    val model: String,
    val buildFingerprint: String,
    val kernelRelease: String,
    val appVersionCode: Long,
    val abi: String,
    val selinuxEnforcing: Boolean?,
    val privilegedProvider: PrivilegedProbeProvider = PrivilegedProbeProvider.NONE,
    val privilegedProviderUid: Int? = null,
    val privilegedProtocolVersion: Int? = null,
    val privilegedBackendVersion: Int? = null,
) {
    fun cacheKey(): String {
        val canonical = listOf(
            sdk,
            manufacturer,
            model,
            buildFingerprint,
            kernelRelease,
            appVersionCode,
            abi,
            selinuxEnforcing,
            privilegedProvider.name,
            privilegedProviderUid,
            privilegedProtocolVersion,
            privilegedBackendVersion,
        ).joinToString("\u0000")
        return MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }
}

internal object BetaCapabilityCache {
    private const val PREFS_NAME = "beta_capability_cache"
    private const val PREF_FINGERPRINT = "fingerprint"
    private const val PREF_AVAILABILITY = "availability"

    fun currentFingerprint(
        context: Context,
        privilegedProvider: PrivilegedProbeProvider = PrivilegedProbeProvider.NONE,
        privilegedProviderUid: Int? = null,
        privilegedProtocolVersion: Int? = null,
        privilegedBackendVersion: Int? = null,
    ): BetaCapabilityFingerprint {
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
        return BetaCapabilityFingerprint(
            sdk = Build.VERSION.SDK_INT,
            manufacturer = Build.MANUFACTURER.orEmpty(),
            model = Build.MODEL.orEmpty(),
            buildFingerprint = Build.FINGERPRINT.orEmpty(),
            kernelRelease = runCatching { Os.uname().release }.getOrDefault("unknown"),
            appVersionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            },
            abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
            selinuxEnforcing = readSelinuxEnforcing(),
            privilegedProvider = privilegedProvider,
            privilegedProviderUid = privilegedProviderUid,
            privilegedProtocolVersion = privilegedProtocolVersion,
            privilegedBackendVersion = privilegedBackendVersion,
        )
    }

    fun load(
        context: Context,
        fingerprint: BetaCapabilityFingerprint = currentFingerprint(context),
    ): Map<String, ProbeAvailability> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (prefs.getString(PREF_FINGERPRINT, null) != fingerprint.cacheKey()) return emptyMap()
        val serialized = prefs.getString(PREF_AVAILABILITY, null) ?: return emptyMap()
        return runCatching {
            val json = JSONObject(serialized)
            buildMap {
                json.keys().forEach { checkId ->
                    val availability = runCatching {
                        ProbeAvailability.valueOf(json.getString(checkId))
                    }.getOrNull()
                    if (availability != null) put(checkId, availability)
                }
            }
        }.getOrDefault(emptyMap())
    }

    fun store(
        context: Context,
        availability: Map<String, ProbeAvailability>,
        fingerprint: BetaCapabilityFingerprint = currentFingerprint(context),
    ) {
        val json = JSONObject()
        availability.toSortedMap().forEach { (checkId, value) -> json.put(checkId, value.name) }
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit(commit = true) {
            putString(PREF_FINGERPRINT, fingerprint.cacheKey())
            putString(PREF_AVAILABILITY, json.toString())
        }
    }

    private fun readSelinuxEnforcing(): Boolean? = runCatching {
        when (File("/sys/fs/selinux/enforce").readText().trim()) {
            "1" -> true
            "0" -> false
            else -> null
        }
    }.getOrNull()
}
