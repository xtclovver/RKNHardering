package com.notcvnt.rknhardering.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class VpnApkInspectorTest {

    @get:Rule
    val temp = TemporaryFolder()

    @Test
    fun `detects app type from dex marker`() {
        val apk = createApk(
            "classes.dex" to "Lio/nekohasekai/sagernet/fmt/ConfigBuilder;".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(apk))

        assertEquals(VpnAppClassifier.APP_TYPE_SAGERNET, result.appType)
    }

    @Test
    fun `detects core type and go version from native library`() {
        val apk = createApk(
            "lib/arm64-v8a/libbox.so" to "github.com/sagernet/sing-box\u0000go1.24.2".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(apk))

        assertEquals(VpnAppClassifier.CORE_TYPE_SING_BOX, result.coreType)
        assertEquals("lib/arm64-v8a/libbox.so", result.corePath)
        assertEquals("go1.24.2", result.goVersion)
    }

    @Test
    fun `corrupt apk falls back without crashing`() {
        val file = temp.newFile("corrupt.apk").apply {
            writeText("not a zip")
        }

        val result = VpnApkInspector.inspect(listOf(file.absolutePath))

        assertNull(result.appType)
        assertNull(result.coreType)
    }

    @Test
    fun `oversized dex is skipped`() {
        val oversizedDex = ByteArray(15 * 1024 * 1024 + 1) { 0 }
        val apk = createApk(
            "classes.dex" to oversizedDex,
            "classes2.dex" to "Lcom/github/shadowsocks/bg/VpnService;".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(apk))

        assertEquals(VpnAppClassifier.APP_TYPE_SHADOWSOCKS_ANDROID, result.appType)
    }

    @Test
    fun `shadowsocks marker is fallback when stronger app type appears later`() {
        val apk = createApk(
            "classes.dex" to "Lcom/github/shadowsocks/bg/VpnService;".encodeToByteArray(),
            "classes2.dex" to "Lio/nekohasekai/sagernet/fmt/ConfigBuilder;".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(apk))

        assertEquals(VpnAppClassifier.APP_TYPE_SAGERNET, result.appType)
    }

    @Test
    fun `missing and blank apk paths yield empty result`() {
        val result = VpnApkInspector.inspect(listOf("", "  ", "E:/definitely/not/there.apk"))

        assertTrue(result.isEmpty)
    }

    @Test
    fun `combines app type and core type from split apks`() {
        val baseApk = createApk(
            "classes.dex" to "Lcom/v2ray/ang/dto/V2rayConfig;".encodeToByteArray(),
        )
        val splitApk = createApk(
            "lib/arm64-v8a/libxray.so" to "xray-core go1.22.1".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(baseApk, splitApk))

        assertEquals(VpnAppClassifier.APP_TYPE_V2RAYNG, result.appType)
        assertEquals(VpnAppClassifier.CORE_TYPE_XRAY_V2RAY, result.coreType)
        assertEquals("lib/arm64-v8a/libxray.so", result.corePath)
        assertEquals("go1.22.1", result.goVersion)
    }

    @Test
    fun `native library outside lib directory is ignored`() {
        val apk = createApk(
            "assets/libxray.so" to "xray-core".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(apk))

        assertNull(result.coreType)
    }

    @Test
    fun `dex entry not named classes is ignored`() {
        val apk = createApk(
            "secondary.dex" to "Lcom/v2ray/ang/dto/V2rayConfig;".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(apk))

        assertNull(result.appType)
    }

    @Test
    fun `duplicate apk paths are inspected once without error`() {
        val apk = createApk(
            "classes.dex" to "Lcom/v2ray/ang/dto/V2rayConfig;".encodeToByteArray(),
        )

        val result = VpnApkInspector.inspect(listOf(apk, apk))

        assertEquals(VpnAppClassifier.APP_TYPE_V2RAYNG, result.appType)
    }

    private fun createApk(vararg entries: Pair<String, ByteArray>): String {
        val file = temp.newFile("test-${System.nanoTime()}.apk")
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
