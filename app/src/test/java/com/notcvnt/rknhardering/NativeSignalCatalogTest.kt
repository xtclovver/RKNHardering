package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.NativeSignalId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class NativeSignalCatalogTest {

    @Test
    fun `every signal has a category unique slug and stable url`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val entries = NativeSignalCatalog.entries

        assertEquals(NativeSignalId.entries.size, entries.size)
        assertEquals(entries.size, entries.map { it.slug }.toSet().size)
        assertEquals(NativeSignalId.entries.toSet(), entries.map { it.id }.toSet())
        entries.forEach { entry ->
            assertTrue(entry.slug.matches(Regex("[a-z0-9-]+")))
            assertTrue(NativeSignalCatalog.articleUrl(context, entry.id).endsWith("/native/${entry.slug}/"))
        }
    }

    @Test
    fun `null and unknown kinds use general fallback`() {
        assertEquals(NativeSignalId.UNKNOWN, NativeSignalCatalog.info(null).id)
        assertEquals(NativeSignalId.UNKNOWN, NativeSignalCatalog.fromLegacyVpnKind("future_legacy"))
        assertEquals(NativeSignalId.UNKNOWN, NativeSignalCatalog.fromDeepVpnKind("future_deep"))
        assertEquals(NativeSignalId.UNKNOWN, NativeSignalCatalog.fromRootKind("future_root"))
        assertEquals(NativeSignalId.UNKNOWN, NativeSignalCatalog.fromEmulatorKind("future_emulator"))
        assertEquals(NativeSignalCategory.GENERAL, NativeSignalCatalog.info(null).category)
    }

    @Test
    @Config(qualifiers = "zh-rCN")
    fun `android chinese locale uses pages zh CN path`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals("zh-CN", NativeSignalCatalog.localePath(context))
    }

    @Test
    @Config(qualifiers = "de-rDE")
    fun `unsupported locale falls back to english`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals("en", NativeSignalCatalog.localePath(context))
    }
}
