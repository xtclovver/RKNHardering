package com.notcvnt.rknhardering.customcheck

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object CustomCheckExportSupport {

    private val DATE_FORMAT = SimpleDateFormat("yyyy-MM-dd", Locale.US)

    // ── file I/O — delegates to repository ───────────────────────────────────

    fun exportToFile(context: Context, profile: CustomCheckProfile, uri: Uri) {
        CustomCheckRepository.exportToFile(context, profile, uri)
    }

    fun importFromFile(context: Context, uri: Uri): CustomCheckProfile =
        CustomCheckRepository.importFromFile(context, uri)

    // ── clipboard ─────────────────────────────────────────────────────────────

    fun exportToClipboard(context: Context, profile: CustomCheckProfile) {
        val json = CustomCheckSerializer.serialize(profile)
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("rkncheck", json))
    }

    fun importFromClipboard(context: Context): CustomCheckProfile? {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip
            ?.getItemAt(0)
            ?.coerceToText(context)
            ?.toString()
            ?: return null
        val validation = CustomCheckSerializer.validate(text)
        if (validation is ValidationResult.Error) return null
        return runCatching { CustomCheckSerializer.deserialize(text) }.getOrNull()
    }

    // ── filename ──────────────────────────────────────────────────────────────

    fun buildExportFileName(profile: CustomCheckProfile): String {
        val sanitized = profile.name
            .lowercase(Locale.US)
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .take(50)
            .ifEmpty { "profile" }
        val date = DATE_FORMAT.format(Date(profile.updatedAt))
        return "$sanitized-$date.rkncheck"
    }
}
