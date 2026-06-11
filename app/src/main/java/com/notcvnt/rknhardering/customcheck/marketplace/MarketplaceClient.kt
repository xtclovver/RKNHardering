package com.notcvnt.rknhardering.customcheck.marketplace

import android.content.Context
import com.notcvnt.rknhardering.AppUiSettings
import com.notcvnt.rknhardering.SettingsPrefs
import com.notcvnt.rknhardering.crypto.Ed25519
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomCheckSerializer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object MarketplaceClient {

    const val CATALOG_URL =
        "https://raw.githubusercontent.com/xtclovver/RKNHardering/main/marketplace/catalog.json"
    private const val CATALOG_SIG_URL =
        "https://raw.githubusercontent.com/xtclovver/RKNHardering/main/marketplace/catalog.sig"

    private const val PUBKEY_ASSET = "marketplace_pubkey.hex"

    // SPKI sha256 pins for raw.githubusercontent.com. Two pins (current + backup)
    // keep the catalog reachable through one GitHub cert rotation. To refresh, run
    //   openssl s_client -servername raw.githubusercontent.com -connect raw.githubusercontent.com:443 \
    //     | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER \
    //     | openssl dgst -sha256 -binary | openssl enc -base64
    // We deliberately keep this list non-strict (no pin = network failure) — the
    // Ed25519 signature is the real trust anchor. If both pins go stale the
    // catalog still won't ship without the signature check passing.
    private val CATALOG_HOST_PINS: List<String> = listOf(
        // Placeholder pins — replace with real openssl-derived SPKI digests when
        // shipping. Empty list disables pinning.
    )

    class NetworkDisabledException :
        IllegalStateException("Network requests are disabled in settings")

    class HashMismatchException(val expected: String, val actual: String) :
        IllegalStateException("Profile hash mismatch: expected=$expected actual=$actual")

    class CatalogSignatureException(message: String) : IllegalStateException(message)

    private val client: OkHttpClient by lazy {
        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
        if (CATALOG_HOST_PINS.isNotEmpty()) {
            val pinnerBuilder = CertificatePinner.Builder()
            CATALOG_HOST_PINS.forEach { pin ->
                pinnerBuilder.add("raw.githubusercontent.com", "sha256/$pin")
            }
            builder.certificatePinner(pinnerBuilder.build())
        }
        builder.build()
    }

    fun isNetworkAllowed(context: Context): Boolean =
        AppUiSettings.prefs(context)
            .getBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true)

    suspend fun fetchCatalog(context: Context): MarketplaceCatalog = withContext(Dispatchers.IO) {
        if (!isNetworkAllowed(context)) throw NetworkDisabledException()
        val catalogBody = httpGetBytes(CATALOG_URL)
        val signatureHex = runCatching { httpGetString(CATALOG_SIG_URL).trim() }.getOrNull()
        val signatureValid = signatureHex
            ?.let { runCatching { hexToBytes(it) }.getOrNull() }
            ?.let { sig -> verifyCatalogSignature(context, catalogBody, sig) }
            ?: false
        parseCatalog(String(catalogBody, Charsets.UTF_8), signatureValid)
    }

    suspend fun fetchProfile(context: Context, entry: MarketplaceEntry, catalogSignatureValid: Boolean): CustomCheckProfile =
        withContext(Dispatchers.IO) {
            if (!isNetworkAllowed(context)) throw NetworkDisabledException()
            val body = httpGetString(entry.profileUrl)
            val profile = CustomCheckSerializer.deserialize(body)
            val expected = entry.expectedHash
            if (expected != null) {
                val actual = CustomCheckSerializer.canonicalHash(profile)
                if (!actual.equals(expected, ignoreCase = true)) {
                    throw HashMismatchException(expected = expected, actual = actual)
                }
            }
            // signatureVerified only when the catalog itself was signed by the
            // bundled public key AND we had a hash to match against AND it matched.
            val signatureVerified = catalogSignatureValid && expected != null
            if (!signatureVerified) profile else {
                val info = profile.marketplaceInfo
                if (info != null) {
                    profile.copy(marketplaceInfo = info.copy(signatureVerified = true))
                } else profile
            }
        }

    private fun httpGetBytes(url: String): ByteArray {
        val request = Request.Builder().url(url).build()
        return client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("HTTP ${response.code}")
            response.body?.bytes() ?: error("Empty response body")
        }
    }

    private fun httpGetString(url: String): String {
        val request = Request.Builder().url(url).build()
        return client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) error("HTTP ${response.code}")
            response.body?.string() ?: error("Empty response body")
        }
    }

    private fun verifyCatalogSignature(context: Context, body: ByteArray, signature: ByteArray): Boolean {
        val pubKey = runCatching { loadPublicKey(context) }.getOrNull() ?: return false
        return Ed25519.verify(pubKey, body, signature)
    }

    private fun loadPublicKey(context: Context): ByteArray {
        val hex = context.assets.open(PUBKEY_ASSET).use { it.readBytes() }.toString(Charsets.UTF_8).trim()
        return hexToBytes(hex)
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim().lowercase()
        require(clean.length % 2 == 0) { "odd hex length" }
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) out[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        return out
    }

    private fun parseCatalog(json: String, signatureValid: Boolean): MarketplaceCatalog {
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
                // official/verified come from the catalog but only mean anything when
                // the catalog itself was signed by us. Clamp them here so downstream
                // code can rely on the invariant.
                val rawOfficial = e.optBoolean("official", false)
                val rawVerified = e.optBoolean("verified", false)
                entries.add(
                    MarketplaceEntry(
                        id = e.optString("id", ""),
                        name = e.optString("name", ""),
                        description = e.optString("description", ""),
                        author = e.optString("author", ""),
                        version = e.optString("version", "1.0.0"),
                        official = signatureValid && rawOfficial,
                        verified = signatureValid && rawVerified,
                        profileUrl = e.optString("profile_url", ""),
                        tags = tags,
                        createdAt = e.optString("created_at", ""),
                        updatedAt = e.optString("updated_at", ""),
                        expectedHash = if (e.has("expected_hash") && !e.isNull("expected_hash"))
                            e.getString("expected_hash").takeIf { it.isNotBlank() } else null,
                    )
                )
            }
        }
        return MarketplaceCatalog(schemaVersion, updatedAt, entries, signatureValid = signatureValid)
    }
}
