package com.notcvnt.rknhardering

import org.junit.Assert.assertEquals
import org.junit.Test

class MaskIpTest {

    @Test
    fun `masks last two octets of IPv4`() {
        assertEquals("203.0.*.*", maskIp("203.0.113.64"))
    }

    @Test
    fun `masks last four groups of IPv6`() {
        assertEquals("2001:db8:85a3:8d3:*:*:*:*", maskIp("2001:db8:85a3:8d3:1319:8a2e:370:7348"))
    }

    @Test
    fun `returns masked placeholder for unrecognized format`() {
        assertEquals("*.*.*.*", maskIp("not-an-ip"))
    }

    @Test
    fun `handles short IPv4`() {
        assertEquals("*.*.*.*", maskIp("1.2"))
    }

    @Test
    fun `does not mask loopback IPv6`() {
        assertEquals("::1", maskIp("::1"))
    }

    @Test
    fun `masks IPv4 with all zeros`() {
        assertEquals("0.0.*.*", maskIp("0.0.0.0"))
    }

    @Test
    fun `does not mask local IPv4 ranges`() {
        assertEquals("192.168.1.10", maskIp("192.168.1.10"))
        assertEquals("127.0.0.1", maskIp("127.0.0.1"))
        assertEquals("169.254.12.1", maskIp("169.254.12.1"))
    }

    @Test
    fun `does not mask local IPv6 ranges`() {
        assertEquals("fe80::1", maskIp("fe80::1"))
        assertEquals("fd00::1234", maskIp("fd00::1234"))
    }

    @Test
    fun `masks IPv4 inside checker summary text`() {
        assertEquals(
            "Все чекеры вернули один IP: 203.0.*.*",
            maskIpsInText("Все чекеры вернули один IP: 203.0.113.64"),
        )
    }

    @Test
    fun `masks multiple IPs inside checker summary text`() {
        assertEquals(
            "Сервисы вернули разные IP: 203.0.*.*, 198.51.*.*",
            maskIpsInText("Сервисы вернули разные IP: 203.0.113.64, 198.51.100.25"),
        )
    }

    @Test
    fun `preserves local IPs inside text`() {
        assertEquals(
            "Локальный адрес 192.168.1.10 и loopback ::1",
            maskIpsInText("Локальный адрес 192.168.1.10 и loopback ::1"),
        )
    }
}
