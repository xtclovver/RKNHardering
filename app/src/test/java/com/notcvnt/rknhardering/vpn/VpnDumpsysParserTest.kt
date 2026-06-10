package com.notcvnt.rknhardering.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnDumpsysParserTest {

    @Test
    fun `parses active package from vpn management output`() {
        val output = """
            VPNs:
              Active package name: com.v2ray.ang
              Active vpn type: legacy
        """.trimIndent()

        val records = VpnDumpsysParser.parseVpnManagement(output)

        assertEquals(1, records.count { it.packageName == "com.v2ray.ang" })
    }

    @Test
    fun `ignores numbered vpn management service blocks without active package`() {
        val output = """
            VPNs:
              0: service=u0a123 something
              1: state=CONNECTED
        """.trimIndent()

        val records = VpnDumpsysParser.parseVpnManagement(output)

        assertTrue(records.isEmpty())
    }

    @Test
    fun `parses active vpn service record`() {
        val output = """
            ServiceRecord{12345 u0 com.v2ray.ang/com.v2ray.ang.service.VpnService}
        """.trimIndent()

        val records = VpnDumpsysParser.parseVpnServices(output)

        assertEquals("com.v2ray.ang", records.single().packageName)
        assertEquals("com.v2ray.ang.service.VpnService", records.single().serviceName)
    }

    @Test
    fun `treats permission denial as unavailable`() {
        assertTrue(VpnDumpsysParser.isUnavailable("Permission Denial: can't dump"))
        assertTrue(VpnDumpsysParser.parseVpnServices("Permission Denial: can't dump").isEmpty())
    }

    @Test
    fun `treats blank and missing-service output as unavailable`() {
        assertTrue(VpnDumpsysParser.isUnavailable(""))
        assertTrue(VpnDumpsysParser.isUnavailable("   \n  "))
        assertTrue(VpnDumpsysParser.isUnavailable("Can't find service: vpn_management"))
        assertTrue(VpnDumpsysParser.parseVpnManagement("").isEmpty())
        assertTrue(VpnDumpsysParser.parseVpnServices("Can't find service: activity").isEmpty())
    }

    @Test
    fun `garbage output yields no records but is not unavailable`() {
        val garbage = "lorem ipsum dolor sit amet"

        assertEquals(false, VpnDumpsysParser.isUnavailable(garbage))
        assertTrue(VpnDumpsysParser.parseVpnManagement(garbage).isEmpty())
        assertTrue(VpnDumpsysParser.parseVpnServices(garbage).isEmpty())
    }

    @Test
    fun `parses multiple active packages from management output`() {
        val output = """
            VPNs:
              Active package name: com.v2ray.ang
              Active package name: org.amnezia.vpn
        """.trimIndent()

        val records = VpnDumpsysParser.parseVpnManagement(output)

        assertEquals(
            listOf("com.v2ray.ang", "org.amnezia.vpn"),
            records.map { it.packageName },
        )
    }

    @Test
    fun `parses multiple distinct vpn service records and keeps order`() {
        val output = """
            ServiceRecord{1a u0 com.v2ray.ang/com.v2ray.ang.service.VpnService}
            ServiceRecord{2b u0 moe.nb4a/moe.nb4a.bg.VpnService}
        """.trimIndent()

        val records = VpnDumpsysParser.parseVpnServices(output)

        assertEquals(listOf("com.v2ray.ang", "moe.nb4a"), records.map { it.packageName })
        assertEquals(
            listOf("com.v2ray.ang.service.VpnService", "moe.nb4a.bg.VpnService"),
            records.map { it.serviceName },
        )
    }

    @Test
    fun `service record lines without VpnService marker are ignored`() {
        val output = """
            ServiceRecord{1a u0 com.example.music/com.example.music.PlaybackService}
        """.trimIndent()

        assertTrue(VpnDumpsysParser.parseVpnServices(output).isEmpty())
    }

    @Test
    fun `vpn service line without braces yields record with null package`() {
        val output = "ServiceRecord without braces but mentioning VpnService"

        val records = VpnDumpsysParser.parseVpnServices(output)

        assertEquals(1, records.size)
        assertEquals(null, records.single().packageName)
        assertEquals(null, records.single().serviceName)
        assertEquals(output, records.single().rawLine)
    }

    @Test
    fun `identical raw lines are deduplicated`() {
        val line = "ServiceRecord{1a u0 com.v2ray.ang/com.v2ray.ang.service.VpnService}"
        val output = "$line\n$line"

        assertEquals(1, VpnDumpsysParser.parseVpnServices(output).size)
    }
}
