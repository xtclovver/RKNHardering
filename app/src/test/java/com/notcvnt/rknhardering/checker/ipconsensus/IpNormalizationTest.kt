package com.notcvnt.rknhardering.checker.ipconsensus

import com.notcvnt.rknhardering.model.IpFamily
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class IpNormalizationTest {

    @Test
    fun `trims and lowercases ipv6`() {
        val result = IpNormalization.parse("  2001:DB8::1  ")
        assertEquals("2001:db8::1", result?.value)
        assertEquals(IpFamily.V6, result?.family)
    }

    @Test
    fun `parses ipv4`() {
        val result = IpNormalization.parse("1.2.3.4")
        assertEquals("1.2.3.4", result?.value)
        assertEquals(IpFamily.V4, result?.family)
    }

    @Test
    fun `collapses ipv4-mapped ipv6 to ipv4`() {
        val result = IpNormalization.parse("::ffff:1.2.3.4")
        assertEquals("1.2.3.4", result?.value)
        assertEquals(IpFamily.V4, result?.family)
    }

    @Test
    fun `rejects blank input`() {
        assertNull(IpNormalization.parse(""))
        assertNull(IpNormalization.parse("   "))
        assertNull(IpNormalization.parse(null))
    }

    @Test
    fun `rejects hostnames (no dns lookup)`() {
        assertNull(IpNormalization.parse("example.com"))
        assertNull(IpNormalization.parse("localhost"))
    }

    @Test
    fun `rejects invalid ip literals`() {
        assertNull(IpNormalization.parse("999.999.999.999"))
        assertNull(IpNormalization.parse("1.2.3"))
        assertNull(IpNormalization.parse("not-an-ip"))
    }
}
