package com.notcvnt.rknhardering.customcheck

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

@RunWith(RobolectricTestRunner::class)
class CustomCheckExportSupportTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        File(context.filesDir, "custom_checks").deleteRecursively()
    }

    private fun makeProfile(
        name: String = "My Profile",
        id: String = "test-id",
        updatedAt: Long = 1735689600000L, // 2026-01-01 00:00:00 UTC
    ): CustomCheckProfile = CustomCheckProfile(id = id, name = name, updatedAt = updatedAt)

    // ── filename generation ───────────────────────────────────────────────────

    @Test
    fun `buildExportFileName produces correct format`() {
        val profile = makeProfile(name = "My Profile", updatedAt = 1735689600000L)
        val name = CustomCheckExportSupport.buildExportFileName(profile)
        assertTrue("Expected .rkncheck extension", name.endsWith(".rkncheck"))
        assertTrue("Expected hyphen-separated name prefix", name.startsWith("my-profile-"))
    }

    @Test
    fun `buildExportFileName sanitizes special characters`() {
        val profile = makeProfile(name = "Test Profile #1 / Special!", updatedAt = 1735689600000L)
        val name = CustomCheckExportSupport.buildExportFileName(profile)
        assertTrue("Name should not contain spaces", !name.contains(' '))
        assertTrue("Name should not contain #", !name.contains('#'))
        assertTrue("Name should not contain /", !name.contains('/'))
        assertTrue(name.endsWith(".rkncheck"))
    }

    @Test
    fun `buildExportFileName falls back to profile for empty name`() {
        val profile = makeProfile(name = "!@#$%", updatedAt = 1735689600000L)
        val name = CustomCheckExportSupport.buildExportFileName(profile)
        assertTrue(name.startsWith("profile-"))
    }

    @Test
    fun `buildExportFileName is lowercase`() {
        val profile = makeProfile(name = "My UPPERCASE Profile", updatedAt = 1735689600000L)
        val name = CustomCheckExportSupport.buildExportFileName(profile)
        assertEquals(name, name.lowercase())
    }

    // ── export/import via temp file ───────────────────────────────────────────

    @Test
    fun `export then import via temp file preserves profile`() {
        val profile = makeProfile("Roundtrip Profile", "rt-id")

        // Write to temp file
        val tempFile = File(context.cacheDir, "test_export.rkncheck")
        tempFile.createNewFile()
        val uri = Uri.fromFile(tempFile)

        CustomCheckExportSupport.exportToFile(context, profile, uri)
        assertTrue("File should be non-empty after export", tempFile.length() > 0)

        val imported = CustomCheckExportSupport.importFromFile(context, uri)
        assertEquals("rt-id", imported.id)
        assertEquals("Roundtrip Profile", imported.name)

        tempFile.delete()
    }

    @Test
    fun `exported file contains valid JSON`() {
        val profile = makeProfile("JSON Profile", "json-id")
        val tempFile = File(context.cacheDir, "test_json.rkncheck")
        tempFile.createNewFile()
        val uri = Uri.fromFile(tempFile)

        CustomCheckExportSupport.exportToFile(context, profile, uri)

        val content = tempFile.readText()
        val validation = CustomCheckSerializer.validate(content)
        assertEquals(ValidationResult.Ok, validation)

        tempFile.delete()
    }
}
