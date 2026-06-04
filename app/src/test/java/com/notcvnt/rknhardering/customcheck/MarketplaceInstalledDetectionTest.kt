package com.notcvnt.rknhardering.customcheck

import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.customcheck.marketplace.MarketplaceEntry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Verifies that the marketplace screen can derive `installed` state by intersecting
 * the catalog entry id with the local CustomCheckRepository ids.
 */
@RunWith(RobolectricTestRunner::class)
class MarketplaceInstalledDetectionTest {

    @Test
    fun `installed flag reflects repository state`() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val installedProfile = CustomCheckProfile(id = "abc-123", name = "Installed")
        CustomCheckRepository.save(ctx, installedProfile)

        val installedIds = CustomCheckRepository.getAll(ctx).map { it.id }.toSet()

        val installedEntry = makeEntry("abc-123")
        val notInstalledEntry = makeEntry("xyz-999")

        assertTrue(installedEntry.id in installedIds)
        assertFalse(notInstalledEntry.id in installedIds)
    }

    private fun makeEntry(id: String): MarketplaceEntry = MarketplaceEntry(
        id = id,
        name = "Entry $id",
        description = "",
        author = "tester",
        version = "1.0.0",
        official = false,
        verified = false,
        profileUrl = "https://example.invalid/$id.rkncheck",
        
        tags = emptyList(),
        createdAt = "",
        updatedAt = "",
    )
}
