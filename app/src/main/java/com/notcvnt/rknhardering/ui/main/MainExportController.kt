package com.notcvnt.rknhardering.ui.main

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.export.CheckResultJsonExportFormatter
import com.notcvnt.rknhardering.export.CheckResultMarkdownExportFormatter
import com.notcvnt.rknhardering.export.CompletedExportSnapshot
import com.notcvnt.rknhardering.export.ExportFormat
import com.notcvnt.rknhardering.export.buildDefaultExportFileName
import java.io.IOException

/**
 * Owns the scan-report export flow: format/action dialogs, the
 * CreateDocument launchers, clipboard copy and document writing.
 *
 * Must be constructed as an activity field initializer so the launchers are
 * registered before the activity reaches STARTED.
 */
internal class MainExportController(
    private val activity: AppCompatActivity,
    private val snapshot: () -> CompletedExportSnapshot?,
    private val debugClipboardEnabled: () -> Boolean,
) {

    private val markdownLauncher = activity.registerForActivityResult(
        ActivityResultContracts.CreateDocument(ExportFormat.MARKDOWN.mimeType),
    ) { uri ->
        writeExportDocument(uri, ExportFormat.MARKDOWN)
    }

    private val jsonLauncher = activity.registerForActivityResult(
        ActivityResultContracts.CreateDocument(ExportFormat.JSON.mimeType),
    ) { uri ->
        writeExportDocument(uri, ExportFormat.JSON)
    }

    fun showFormatDialog() {
        if (snapshot() == null) return
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.main_export_title)
            .setPositiveButton(R.string.main_export_markdown) { _, _ ->
                onFormatSelected(ExportFormat.MARKDOWN)
            }
            .setNegativeButton(R.string.main_export_json) { _, _ ->
                onFormatSelected(ExportFormat.JSON)
            }
            .setNeutralButton(android.R.string.cancel, null)
            .show()
    }

    private fun onFormatSelected(format: ExportFormat) {
        if (debugClipboardEnabled()) {
            showActionDialog(format)
        } else {
            launchExport(format)
        }
    }

    private fun showActionDialog(format: ExportFormat) {
        MaterialAlertDialogBuilder(activity)
            .setTitle(
                when (format) {
                    ExportFormat.MARKDOWN -> R.string.main_export_markdown
                    ExportFormat.JSON -> R.string.main_export_json
                },
            )
            .setPositiveButton(R.string.main_export_save_file) { _, _ ->
                launchExport(format)
            }
            .setNegativeButton(R.string.main_export_copy_to_clipboard) { _, _ ->
                copyExportToClipboard(format)
            }
            .setNeutralButton(android.R.string.cancel, null)
            .show()
    }

    private fun launchExport(format: ExportFormat) {
        val snapshot = snapshot() ?: return
        val defaultFileName = buildDefaultExportFileName(format, snapshot.finishedAtMillis)
        when (format) {
            ExportFormat.MARKDOWN -> markdownLauncher.launch(defaultFileName)
            ExportFormat.JSON -> jsonLauncher.launch(defaultFileName)
        }
    }

    private fun copyExportToClipboard(format: ExportFormat) {
        val snapshot = snapshot() ?: return
        val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val labelResId = when (format) {
            ExportFormat.MARKDOWN -> R.string.main_export_markdown
            ExportFormat.JSON -> R.string.main_export_json
        }
        clipboard.setPrimaryClip(
            ClipData.newPlainText(
                activity.getString(labelResId),
                buildExportContent(snapshot, format),
            ),
        )
        Toast.makeText(activity, R.string.main_export_copied, Toast.LENGTH_SHORT).show()
    }

    private fun writeExportDocument(uri: Uri?, format: ExportFormat) {
        val targetUri = uri ?: return
        val snapshot = snapshot() ?: return
        val content = buildExportContent(snapshot, format)
        val exportResult = runCatching {
            activity.contentResolver.openOutputStream(targetUri)?.use { outputStream ->
                outputStream.writer(Charsets.UTF_8).use { writer ->
                    writer.write(content)
                }
            } ?: throw IOException("Unable to open export destination")
        }
        if (exportResult.isSuccess) {
            Toast.makeText(activity, R.string.main_export_saved, Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(activity, R.string.main_export_failed, Toast.LENGTH_SHORT).show()
        }
    }

    private fun buildExportContent(
        snapshot: CompletedExportSnapshot,
        format: ExportFormat,
    ): String {
        return when (format) {
            ExportFormat.MARKDOWN -> CheckResultMarkdownExportFormatter.format(activity, snapshot)
            ExportFormat.JSON -> CheckResultJsonExportFormatter.format(activity, snapshot)
        }
    }
}
