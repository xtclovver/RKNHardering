package com.notcvnt.rknhardering.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
