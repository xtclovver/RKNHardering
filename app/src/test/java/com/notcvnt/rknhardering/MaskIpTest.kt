package com.notcvnt.rknhardering

import org.junit.Assert.assertEquals
import org.junit.Test

class MaskIpTest {

    @Test
    fun `masks last two octets of IPv4`() {
        assertEquals("185.22.*.*", maskIp("185.22.64.1"))
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
    fun `handles IPv6 with fewer groups`() {
        assertEquals("*.*.*.*", maskIp("::1"))
    }

    @Test
    fun `masks IPv4 with all zeros`() {
        assertEquals("0.0.*.*", maskIp("0.0.0.0"))
    }
}
