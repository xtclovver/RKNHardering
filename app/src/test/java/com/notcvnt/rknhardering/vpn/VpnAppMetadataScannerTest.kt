package com.notcvnt.rknhardering.vpn

import android.Manifest
import android.app.Application
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.ServiceInfo
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.rules.TemporaryFolder
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
class VpnAppMetadataScannerTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val context = ApplicationProvider.getApplicationContext<Application>()
    private val pm get() = context.packageManager
    private val shadow get() = shadowOf(pm)

    @Test
    fun `scanner enriches version service app type and core type`() {
        val apk = createApk(
            "classes.dex" to "Lio/nekohasekai/sagernet/fmt/ConfigBuilder;".encodeToByteArray(),
            "lib/arm64-v8a/libbox.so" to "github.com/sagernet/sing-box\u0000go1.24.1".encodeToByteArray(),
        )
        installVpnPackage(
            packageName = "com.example.husi.clone",
            label = "Husi Clone",
            versionName = "1.2.3",
            apkPath = apk,
            serviceName = "com.example.husi.clone.VpnService",
        )

        val metadata = VpnAppMetadataScanner.scan(context, "com.example.husi.clone")

        assertEquals("1.2.3", metadata?.versionName)
        assertEquals(listOf("com.example.husi.clone.VpnService"), metadata?.serviceNames)
        assertEquals(VpnAppClassifier.APP_TYPE_SAGERNET, metadata?.appType)
        assertEquals(VpnAppClassifier.CORE_TYPE_SING_BOX, metadata?.coreType)
        assertEquals("go1.24.1", metadata?.goVersion)
        assertFalse(metadata?.systemApp ?: true)
    }

    @Test
    fun `declared unknown VpnService app is matched with metadata`() {
        val apk = createApk(
            "classes.dex" to "Lio/nekohasekai/sfa/Main;".encodeToByteArray(),
        )
        installVpnPackage(
            packageName = "com.example.unknownvpn",
            label = "Unknown VPN",
            versionName = "9.8.7",
            apkPath = apk,
            serviceName = "com.example.unknownvpn.TunnelService",
        )

        val result = InstalledVpnAppDetector.detect(context)
        val matched = result.matchedApps.firstOrNull { it.packageName == "com.example.unknownvpn" }

        assertTrue(matched != null)
        assertEquals(VpnAppClassifier.APP_TYPE_SING_BOX, matched?.technicalMetadata?.appType)
        assertEquals("9.8.7", matched?.technicalMetadata?.versionName)
        assertEquals(listOf("com.example.unknownvpn.TunnelService"), matched?.technicalMetadata?.serviceNames)
    }

    private fun installVpnPackage(
        packageName: String,
        label: String,
        versionName: String,
        apkPath: String,
        serviceName: String,
    ): ServiceInfo {
        val appInfo = ApplicationInfo().apply {
            this.packageName = packageName
            nonLocalizedLabel = label
            sourceDir = apkPath
            publicSourceDir = apkPath
        }
        val service = ServiceInfo().apply {
            this.packageName = packageName
            name = serviceName
            permission = Manifest.permission.BIND_VPN_SERVICE
            applicationInfo = appInfo
        }
        val pkgInfo = PackageInfo().apply {
            this.packageName = packageName
            applicationInfo = appInfo
            this.versionName = versionName
            services = arrayOf(service)
        }
        shadow.installPackage(pkgInfo)
        return service
    }

    private fun createApk(vararg entries: Pair<String, ByteArray>): String {
        val file = temp.newFile("metadata-${System.nanoTime()}.apk")
        ZipOutputStream(file.outputStream()).use { zip ->
            for ((name, content) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }
        return file.absolutePath
    }
}
