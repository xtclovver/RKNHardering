package com.notcvnt.rknhardering.customcheck

import android.content.Context
import android.net.Uri
import androidx.core.content.edit
import java.io.File
import java.util.UUID

object CustomCheckRepository {

    private const val DIR_NAME = "custom_checks"
    private const val FILE_EXT = ".rkncheck"
    private const val PREFS_NAME = "custom_check_prefs"
    // Key owned by SettingsPrefs (Phase 3). Inline here to avoid dependency.
    private const val KEY_ACTIVE_PROFILE_ID = "pref_active_custom_profile_id"
    // Flips to true after a one-time pass that strips official/verified flags
    // from any profile saved before the signature-required model landed.
    private const val KEY_LEGACY_MIGRATION_DONE = "pref_marketplace_signature_migration_v1"
    // Per-profile expected canonical hash, written at install time and read by
    // verifyIntegrity. Stored outside the profile file so an attacker who can
    // overwrite the .rkncheck file cannot also rewrite the trusted hash.
    private const val KEY_PREFIX_TRUSTED_HASH = "pref_trusted_hash_"

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun checksDir(context: Context): File =
        File(context.filesDir, DIR_NAME).also { it.mkdirs() }

    private fun profileFile(context: Context, id: String): File =
        File(checksDir(context), "$id$FILE_EXT")

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // ── CRUD ──────────────────────────────────────────────────────────────────

    fun getAll(context: Context): List<CustomCheckProfile> {
        ensureLegacyMigration(context)
        val dir = checksDir(context)
        return dir.listFiles { f -> f.extension == "rkncheck" }
            ?.mapNotNull { f ->
                runCatching { CustomCheckSerializer.deserializeFromStorage(f.readText()) }
                    .map { CustomCheckSerializer.verifyIntegrity(it, trustedHash(context, it.id)) }
                    .getOrNull()
            }
            ?.sortedBy { it.name }
            ?: emptyList()
    }

    fun getById(context: Context, id: String): CustomCheckProfile? {
        ensureLegacyMigration(context)
        val file = profileFile(context, id)
        if (!file.exists()) return null
        return runCatching { CustomCheckSerializer.deserializeFromStorage(file.readText()) }
            .map { CustomCheckSerializer.verifyIntegrity(it, trustedHash(context, id)) }
            .getOrNull()
    }

    fun save(context: Context, profile: CustomCheckProfile) {
        profileFile(context, profile.id).writeText(CustomCheckSerializer.serialize(profile))
        // Mirror originalHash into SharedPrefs for verified profiles so verifyIntegrity
        // has a tamper-evident reference even if the .rkncheck file is later overwritten.
        val info = profile.marketplaceInfo
        if (info?.signatureVerified == true && info.originalHash != null) {
            prefs(context).edit { putString(KEY_PREFIX_TRUSTED_HASH + profile.id, info.originalHash) }
        } else {
            prefs(context).edit { remove(KEY_PREFIX_TRUSTED_HASH + profile.id) }
        }
    }

    internal fun trustedHash(context: Context, profileId: String): String? =
        prefs(context).getString(KEY_PREFIX_TRUSTED_HASH + profileId, null)

    // One-time pass: strip official/verified from any profile stored before the
    // signature-required model landed. Older builds wrote those flags directly
    // from the catalog with no Ed25519 step; we cannot retroactively trust them.
    private fun ensureLegacyMigration(context: Context) {
        val prefs = prefs(context)
        if (prefs.getBoolean(KEY_LEGACY_MIGRATION_DONE, false)) return
        val dir = checksDir(context)
        dir.listFiles { f -> f.extension == "rkncheck" }?.forEach { f ->
            runCatching {
                val profile = CustomCheckSerializer.deserializeFromStorage(f.readText())
                val info = profile.marketplaceInfo
                // Pre-signature builds had no Ed25519 path, so any official/verified
                // flag on an existing profile is unbacked by definition. Force-clear
                // and never write a trusted hash for these files — the user will see
                // an unverified badge until they reinstall from the signed catalog.
                if (info != null) {
                    val downgraded = profile.copy(
                        marketplaceInfo = info.copy(
                            official = false,
                            verified = false,
                            signatureVerified = false,
                        ),
                    )
                    f.writeText(CustomCheckSerializer.serialize(downgraded))
                    prefs.edit { remove(KEY_PREFIX_TRUSTED_HASH + profile.id) }
                }
            }
        }
        prefs.edit { putBoolean(KEY_LEGACY_MIGRATION_DONE, true) }
    }

    fun delete(context: Context, id: String) {
        profileFile(context, id).delete()
        prefs(context).edit { remove(KEY_PREFIX_TRUSTED_HASH + id) }
        // Clear active profile if deleted
        if (getActiveProfileId(context) == id) {
            setActiveProfileId(context, null)
        }
    }

    fun duplicate(context: Context, id: String, newName: String): CustomCheckProfile {
        val original = getById(context, id) ?: error("Profile not found: $id")
        val copy = original.copy(
            id = UUID.randomUUID().toString(),
            name = newName,
            updatedAt = System.currentTimeMillis(),
            createdAt = System.currentTimeMillis(),
            sourceProfileId = original.id,
        )
        save(context, copy)
        return copy
    }

    // ── active profile ────────────────────────────────────────────────────────

    fun getActiveProfileId(context: Context): String? =
        prefs(context).getString(KEY_ACTIVE_PROFILE_ID, null)

    fun setActiveProfileId(context: Context, id: String?) {
        prefs(context).edit { putString(KEY_ACTIVE_PROFILE_ID, id) }
    }

    // ── export / import via ContentResolver ───────────────────────────────────

    fun exportToFile(context: Context, profile: CustomCheckProfile, uri: Uri) {
        context.contentResolver.openOutputStream(uri)?.use { out ->
            out.write(CustomCheckSerializer.serialize(profile).toByteArray(Charsets.UTF_8))
        } ?: error("Cannot open output stream for $uri")
    }

    fun importFromFile(context: Context, uri: Uri): CustomCheckProfile {
        val json = context.contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) }
            ?: error("Cannot open input stream for $uri")
        val result = CustomCheckSerializer.validate(json)
        if (result is ValidationResult.Error) error("Invalid profile: ${result.message}")
        // Untrusted import: deserialize() strips signature_verified and downgrades
        // official/verified — caller must NOT promote those flags without a verified
        // catalog round-trip.
        return CustomCheckSerializer.deserialize(json)
    }
}
