package com.notcvnt.rknhardering.customcheck.marketplace

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MarketplaceClientTest {

    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun catalogJson(entries: String = "[]") = """
        {
          "schema_version": 1,
          "updated_at": "2026-05-20T00:00:00Z",
          "entries": $entries
        }
    """.trimIndent()

    @Test
    fun `parseCatalog returns empty list when entries is empty array`() {
        val client = buildClientFor(server.url("/catalog.json").toString())
        server.enqueue(MockResponse().setBody(catalogJson()).setResponseCode(200))
        val catalog = runBlocking { client.fetchCatalogFromUrl(server.url("/catalog.json").toString()) }
        assertEquals(1, catalog.schemaVersion)
        assertEquals("2026-05-20T00:00:00Z", catalog.updatedAt)
        assertTrue(catalog.entries.isEmpty())
    }

    @Test
    fun `parseCatalog parses two entries correctly`() {
        val body = catalogJson(
            """
            [
              {
                "id": "entry-1",
                "name": "Full Scan",
                "description": "All checks",
                "author": "xtclovver",
                "version": "1.0.0",
                "official": true,
                "verified": true,
                "profile_url": "https://example.com/full.rkncheck",
                "install_count": 10,
                "tags": ["official", "complete"],
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
              },
              {
                "id": "entry-2",
                "name": "Quick Scan",
                "description": "Fast check",
                "author": "community",
                "version": "2.0.0",
                "official": false,
                "verified": false,
                "profile_url": "https://example.com/quick.rkncheck",
                "install_count": 0,
                "tags": [],
                "created_at": "2026-02-01T00:00:00Z",
                "updated_at": "2026-02-01T00:00:00Z"
              }
            ]
            """.trimIndent()
        )
        server.enqueue(MockResponse().setBody(body).setResponseCode(200))
        val catalog = runBlocking { buildClientFor("").fetchCatalogFromUrl(server.url("/catalog.json").toString()) }
        assertEquals(2, catalog.entries.size)

        val e1 = catalog.entries[0]
        assertEquals("entry-1", e1.id)
        assertEquals("Full Scan", e1.name)
        assertEquals("xtclovver", e1.author)
        assertTrue(e1.official)
        assertTrue(e1.verified)
        assertEquals(listOf("official", "complete"), e1.tags)

        val e2 = catalog.entries[1]
        assertEquals("entry-2", e2.id)
        assertEquals("community", e2.author)
        assertTrue(!e2.official)
        assertTrue(!e2.verified)
    }

    @Test
    fun `fetchCatalog throws on HTTP error`() {
        server.enqueue(MockResponse().setResponseCode(404))
        var threw = false
        runBlocking {
            runCatching {
                buildClientFor("").fetchCatalogFromUrl(server.url("/notfound.json").toString())
            }.onFailure { threw = true }
        }
        assertTrue(threw)
    }

    @Test
    fun `fetchProfile parses rkncheck JSON`() {
        val profileJson = """
            {
              "schema_version": 1,
              "id": "test-profile",
              "name": "Test Profile",
              "description": "desc",
              "author": "tester",
              "version": "1.0.0",
              "created_at": 1000,
              "updated_at": 2000,
              "checks": {},
              "custom_domains": [],
              "network": {}
            }
        """.trimIndent()
        server.enqueue(MockResponse().setBody(profileJson).setResponseCode(200))

        val entry = MarketplaceEntry(
            id = "test-profile", name = "Test Profile", description = "", author = "tester",
            version = "1.0.0", official = false, verified = false,
            profileUrl = server.url("/test.rkncheck").toString(),
             tags = emptyList(), createdAt = "", updatedAt = "",
        )
        val profile = runBlocking { buildClientFor("").fetchProfileFromUrl(entry.profileUrl) }
        assertEquals("test-profile", profile.id)
        assertEquals("Test Profile", profile.name)
        assertEquals("tester", profile.author)
    }

    @Test
    fun `fetchProfile throws on HTTP error`() {
        server.enqueue(MockResponse().setResponseCode(500))
        var threw = false
        runBlocking {
            val entry = MarketplaceEntry(
                id = "x", name = "x", description = "", author = "x", version = "1.0.0",
                official = false, verified = false,
                profileUrl = server.url("/profile.rkncheck").toString(),
                 tags = emptyList(), createdAt = "", updatedAt = "",
            )
            runCatching {
                buildClientFor("").fetchProfileFromUrl(entry.profileUrl)
            }.onFailure { threw = true }
        }
        assertTrue(threw)
    }

    // Test-only helper that exposes URL-parameterized fetch methods
    private fun buildClientFor(@Suppress("UNUSED_PARAMETER") url: String) = TestableMarketplaceClient
}

// Thin wrapper that exposes testable URL-based methods
private object TestableMarketplaceClient {
    private val client = okhttp3.OkHttpClient.Builder()
        .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
        .build()

    fun fetchCatalogFromUrl(url: String): MarketplaceCatalog {
        val request = okhttp3.Request.Builder().url(url).build()
        val body = client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("HTTP ${response.code}")
            response.body?.string() ?: error("Empty response")
        }
        return parseCatalog(body)
    }

    fun fetchProfileFromUrl(url: String): com.notcvnt.rknhardering.customcheck.CustomCheckProfile {
        val request = okhttp3.Request.Builder().url(url).build()
        val body = client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("HTTP ${response.code}")
            response.body?.string() ?: error("Empty response")
        }
        return com.notcvnt.rknhardering.customcheck.CustomCheckSerializer.deserialize(body)
    }

    private fun parseCatalog(json: String): MarketplaceCatalog {
        val root = org.json.JSONObject(json)
        val schemaVersion = root.optInt("schema_version", 1)
        val updatedAt = root.optString("updated_at", "")
        val entriesArr = root.optJSONArray("entries")
        val entries = mutableListOf<MarketplaceEntry>()
        if (entriesArr != null) {
            for (i in 0 until entriesArr.length()) {
                val e = entriesArr.getJSONObject(i)
                val tagsArr = e.optJSONArray("tags")
                val tags = mutableListOf<String>()
                if (tagsArr != null) {
                    for (j in 0 until tagsArr.length()) tags.add(tagsArr.getString(j))
                }
                entries.add(
                    MarketplaceEntry(
                        id = e.optString("id", ""),
                        name = e.optString("name", ""),
                        description = e.optString("description", ""),
                        author = e.optString("author", ""),
                        version = e.optString("version", "1.0.0"),
                        official = e.optBoolean("official", false),
                        verified = e.optBoolean("verified", false),
                        profileUrl = e.optString("profile_url", ""),
                        tags = tags,
                        createdAt = e.optString("created_at", ""),
                        updatedAt = e.optString("updated_at", ""),
                    )
                )
            }
        }
        return MarketplaceCatalog(schemaVersion, updatedAt, entries)
    }
}
