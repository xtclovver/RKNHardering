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

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun checksDir(context: Context): File =
        File(context.filesDir, DIR_NAME).also { it.mkdirs() }

    private fun profileFile(context: Context, id: String): File =
        File(checksDir(context), "$id$FILE_EXT")

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // ── CRUD ──────────────────────────────────────────────────────────────────

    fun getAll(context: Context): List<CustomCheckProfile> {
        val dir = checksDir(context)
        return dir.listFiles { f -> f.extension == "rkncheck" }
            ?.mapNotNull { f ->
                runCatching { CustomCheckSerializer.deserialize(f.readText()) }
                    .map { CustomCheckSerializer.verifyIntegrity(it) }
                    .getOrNull()
            }
            ?.sortedBy { it.name }
            ?: emptyList()
    }

    fun getById(context: Context, id: String): CustomCheckProfile? {
        val file = profileFile(context, id)
        if (!file.exists()) return null
        return runCatching { CustomCheckSerializer.deserialize(file.readText()) }
            .map { CustomCheckSerializer.verifyIntegrity(it) }
            .getOrNull()
    }

    fun save(context: Context, profile: CustomCheckProfile) {
        profileFile(context, profile.id).writeText(CustomCheckSerializer.serialize(profile))
    }

    fun delete(context: Context, id: String) {
        profileFile(context, id).delete()
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
        return CustomCheckSerializer.deserialize(json)
    }
}
