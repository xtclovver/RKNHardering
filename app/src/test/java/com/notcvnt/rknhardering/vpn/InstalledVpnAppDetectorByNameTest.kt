package com.notcvnt.rknhardering.vpn

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.VpnAppKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class InstalledVpnAppDetectorByNameTest {

    private val context = ApplicationProvider.getApplicationContext<android.app.Application>()
    private val pm get() = context.packageManager
    private val shadow get() = shadowOf(pm)

    private fun installApp(packageName: String, label: String, systemApp: Boolean = false) {
        val appInfo = ApplicationInfo().apply {
            this.packageName = packageName
            flags = if (systemApp) ApplicationInfo.FLAG_SYSTEM else 0
            nonLocalizedLabel = label
        }
        val pkgInfo = PackageInfo().apply {
            this.packageName = packageName
            applicationInfo = appInfo
        }
        shadow.installPackage(pkgInfo)
    }

    @Test
    fun `app with VPN in label is detected with low confidence and detected=false`() {
        installApp("com.example.myvpn", "My VPN App")

        val result = InstalledVpnAppDetector.detect(context)

        val evidence = result.evidence.find { it.packageName == "com.example.myvpn" }
        assertTrue("evidence should be present", evidence != null)
        assertFalse("detected must be false for name-based heuristic", evidence!!.detected)
        assertEquals(EvidenceConfidence.LOW, evidence.confidence)
        assertEquals(EvidenceSource.INSTALLED_APP, evidence.source)
        assertEquals(VpnAppKind.GENERIC_VPN, evidence.kind)
    }

    @Test
    fun `app with VPN in label appears in matchedApps`() {
        installApp("com.example.myvpn", "My VPN App")

        val result = InstalledVpnAppDetector.detect(context)

        val matched = result.matchedApps.find { it.packageName == "com.example.myvpn" }
        assertTrue("matched app should be present", matched != null)
        assertEquals("My VPN App", matched!!.appName)
        assertEquals(VpnAppKind.GENERIC_VPN, matched.kind)
        assertFalse(matched.active)
    }

    @Test
    fun `app with lowercase vpn in label is detected (case-insensitive)`() {
        installApp("com.example.vpnapp", "simple vpn tool")

        val result = InstalledVpnAppDetector.detect(context)

        assertTrue(result.matchedApps.any { it.packageName == "com.example.vpnapp" })
    }

    @Test
    fun `app without VPN in label is not detected by name heuristic`() {
        installApp("com.example.browser", "Fast Browser")

        val result = InstalledVpnAppDetector.detect(context)

        assertFalse(result.matchedApps.any { it.packageName == "com.example.browser" })
        assertFalse(result.evidence.any { it.packageName == "com.example.browser" })
    }

    @Test
    fun `system app with VPN in label is not detected`() {
        installApp("com.android.vpndialogs", "VPN Dialogs", systemApp = true)

        val result = InstalledVpnAppDetector.detect(context)

        assertFalse(result.matchedApps.any { it.packageName == "com.android.vpndialogs" })
        assertFalse(result.evidence.any { it.packageName == "com.android.vpndialogs" })
    }

    @Test
    fun `app already matched by catalog is not duplicated by name heuristic`() {
        val catalogPkg = VpnAppCatalog.signatures.first { it.kind == VpnAppKind.TARGETED_BYPASS }
        installApp(catalogPkg.packageName, "${catalogPkg.appName} VPN")

        val result = InstalledVpnAppDetector.detect(context)

        val evidenceForPkg = result.evidence.filter { it.packageName == catalogPkg.packageName }
        assertEquals("catalog match should not be duplicated by name heuristic", 1, evidenceForPkg.size)
        assertTrue("catalog match should have detected=true", evidenceForPkg.first().detected)
    }

    @Test
    fun `name-based finding is informational`() {
        installApp("com.example.myvpn", "VPN Client")

        val result = InstalledVpnAppDetector.detect(context)

        val finding = result.findings.find { it.packageName == "com.example.myvpn" }
        assertTrue("finding should be present", finding != null)
        assertTrue("finding must be informational", finding!!.isInformational)
        assertFalse(finding.detected)
    }

    @Test
    fun `multiple non-vpn apps do not appear in results`() {
        installApp("com.example.app1", "Calculator")
        installApp("com.example.app2", "Notes")
        installApp("com.example.app3", "Camera")

        val result = InstalledVpnAppDetector.detect(context)

        assertFalse(result.matchedApps.any { it.packageName.startsWith("com.example.app") })
    }

    @Test
    fun `two vpn-named apps both appear with low confidence`() {
        installApp("com.one.vpn", "One VPN")
        installApp("com.two.vpn", "Two VPN Pro")

        val result = InstalledVpnAppDetector.detect(context)

        assertTrue(result.matchedApps.any { it.packageName == "com.one.vpn" })
        assertTrue(result.matchedApps.any { it.packageName == "com.two.vpn" })
        result.evidence.filter {
            it.packageName == "com.one.vpn" || it.packageName == "com.two.vpn"
        }.forEach {
            assertEquals(EvidenceConfidence.LOW, it.confidence)
            assertFalse(it.detected)
        }
    }
}
