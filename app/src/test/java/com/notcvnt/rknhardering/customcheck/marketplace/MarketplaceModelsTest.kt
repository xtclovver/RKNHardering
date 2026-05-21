package com.notcvnt.rknhardering.customcheck.marketplace

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MarketplaceModelsTest {

    @Test
    fun `MarketplaceEntry default fields`() {
        val entry = MarketplaceEntry(
            id = "test-id",
            name = "Test Profile",
            description = "A test profile",
            author = "tester",
            version = "1.0.0",
            official = false,
            verified = false,
            profileUrl = "https://example.com/profile.rkncheck",
            installCount = 42,
            tags = listOf("test", "demo"),
            createdAt = "2026-01-01T00:00:00Z",
            updatedAt = "2026-01-01T00:00:00Z",
        )

        assertEquals("test-id", entry.id)
        assertEquals("Test Profile", entry.name)
        assertEquals("A test profile", entry.description)
        assertEquals("tester", entry.author)
        assertEquals("1.0.0", entry.version)
        assertFalse(entry.official)
        assertFalse(entry.verified)
        assertEquals("https://example.com/profile.rkncheck", entry.profileUrl)
        assertEquals(42, entry.installCount)
        assertEquals(listOf("test", "demo"), entry.tags)
    }

    @Test
    fun `official entry has both flags set`() {
        val entry = MarketplaceEntry(
            id = "official-id",
            name = "Official",
            description = "",
            author = "xtclovver",
            version = "1.0.0",
            official = true,
            verified = true,
            profileUrl = "https://example.com/official.rkncheck",
            installCount = 0,
            tags = listOf("official"),
            createdAt = "",
            updatedAt = "",
        )
        assertTrue(entry.official)
        assertTrue(entry.verified)
    }

    @Test
    fun `MarketplaceCatalog holds entries`() {
        val entries = listOf(
            MarketplaceEntry(
                id = "1", name = "A", description = "", author = "x", version = "1.0.0",
                official = true, verified = true, profileUrl = "https://example.com/1.rkncheck",
                installCount = 0, tags = emptyList(), createdAt = "", updatedAt = "",
            ),
            MarketplaceEntry(
                id = "2", name = "B", description = "", author = "y", version = "2.0.0",
                official = false, verified = false, profileUrl = "https://example.com/2.rkncheck",
                installCount = 5, tags = listOf("community"), createdAt = "", updatedAt = "",
            ),
        )
        val catalog = MarketplaceCatalog(schemaVersion = 1, updatedAt = "2026-01-01T00:00:00Z", entries = entries)

        assertEquals(1, catalog.schemaVersion)
        assertEquals("2026-01-01T00:00:00Z", catalog.updatedAt)
        assertEquals(2, catalog.entries.size)
        assertEquals("A", catalog.entries[0].name)
        assertEquals("B", catalog.entries[1].name)
    }

    @Test
    fun `empty catalog is valid`() {
        val catalog = MarketplaceCatalog(schemaVersion = 1, updatedAt = "", entries = emptyList())
        assertEquals(0, catalog.entries.size)
    }
}
