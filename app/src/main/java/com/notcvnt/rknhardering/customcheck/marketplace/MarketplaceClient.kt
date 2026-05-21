package com.notcvnt.rknhardering.customcheck.marketplace

import android.content.Context
import com.notcvnt.rknhardering.AppUiSettings
import com.notcvnt.rknhardering.SettingsPrefs
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomCheckSerializer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object MarketplaceClient {

    const val CATALOG_URL =
        "https://raw.githubusercontent.com/xtclovver/RKNHardering/main/marketplace/catalog.json"

    class NetworkDisabledException :
        IllegalStateException("Network requests are disabled in settings")

    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
    }

    fun isNetworkAllowed(context: Context): Boolean =
        AppUiSettings.prefs(context)
            .getBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true)

    suspend fun fetchCatalog(context: Context): MarketplaceCatalog = withContext(Dispatchers.IO) {
        if (!isNetworkAllowed(context)) throw NetworkDisabledException()
        val request = Request.Builder().url(CATALOG_URL).build()
        val body = client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("HTTP ${response.code}")
            response.body?.string() ?: error("Empty response body")
        }
        parseCatalog(body)
    }

    suspend fun fetchProfile(context: Context, entry: MarketplaceEntry): CustomCheckProfile =
        withContext(Dispatchers.IO) {
            if (!isNetworkAllowed(context)) throw NetworkDisabledException()
            val request = Request.Builder().url(entry.profileUrl).build()
            val body = client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) error("HTTP ${response.code}")
                response.body?.string() ?: error("Empty response body")
            }
            CustomCheckSerializer.deserialize(body)
        }

    private fun parseCatalog(json: String): MarketplaceCatalog {
        val root = JSONObject(json)
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
                        installCount = e.optInt("install_count", 0),
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
