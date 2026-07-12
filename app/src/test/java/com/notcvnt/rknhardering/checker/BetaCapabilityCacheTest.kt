package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.model.PrivilegedProbeProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BetaCapabilityCacheTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun clear() {
        context.getSharedPreferences("beta_capability_cache", Context.MODE_PRIVATE).edit().clear().commit()
    }

    @Test
    fun `cache retains availability only for exact capability fingerprint`() {
        val first = fingerprint(kernel = "6.1", appVersion = 1)
        val changedKernel = fingerprint(kernel = "6.6", appVersion = 1)
        BetaCapabilityCache.store(
            context,
            mapOf("beta.socket_identity" to ProbeAvailability.PERMISSION_DENIED),
            first,
        )

        assertEquals(
            ProbeAvailability.PERMISSION_DENIED,
            BetaCapabilityCache.load(context, first)["beta.socket_identity"],
        )
        assertTrue(BetaCapabilityCache.load(context, changedKernel).isEmpty())
    }

    @Test
    fun `cache key changes with app version and never contains results`() {
        val first = fingerprint(kernel = "6.1", appVersion = 1)
        val updated = fingerprint(kernel = "6.1", appVersion = 2)

        assertTrue(first.cacheKey() != updated.cacheKey())
        assertEquals(64, first.cacheKey().length)
    }

    @Test
    fun `cache key changes with privileged provider identity`() {
        val base = fingerprint(kernel = "6.1", appVersion = 1)
        val privileged = base.copy(
            privilegedProvider = PrivilegedProbeProvider.SHIZUKU,
            privilegedProviderUid = 2_000,
            privilegedProtocolVersion = 1,
            privilegedBackendVersion = 13,
        )

        assertTrue(base.cacheKey() != privileged.cacheKey())
        assertTrue(privileged.cacheKey() != privileged.copy(privilegedProviderUid = 0).cacheKey())
    }

    private fun fingerprint(kernel: String, appVersion: Long) = BetaCapabilityFingerprint(
        sdk = 35,
        manufacturer = "AOSP",
        model = "fixture",
        buildFingerprint = "fixture/build",
        kernelRelease = kernel,
        appVersionCode = appVersion,
        abi = "arm64-v8a",
        selinuxEnforcing = true,
    )
}
