package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IpLiteralsTest {

    @Test
    fun `accepts plain ipv4 literals`() {
        assertTrue(IpLiterals.isIpLiteral("1.2.3.4"))
        assertTrue(IpLiterals.isIpLiteral("255.255.255.255"))
        assertTrue(IpLiterals.isIpLiteral("0.0.0.0"))
        assertTrue(IpLiterals.isIpv4Literal(" 8.8.8.8 "))
    }

    @Test
    fun `rejects malformed ipv4 literals`() {
        assertFalse(IpLiterals.isIpv4Literal("256.1.1.1"))
        assertFalse(IpLiterals.isIpv4Literal("01.2.3.4"))
        assertFalse(IpLiterals.isIpv4Literal("1.2.3"))
        assertFalse(IpLiterals.isIpv4Literal("1.2.3.4.5"))
        assertFalse(IpLiterals.isIpv4Literal("1.2.3."))
        assertFalse(IpLiterals.isIpv4Literal("1.2.3.a"))
        assertFalse(IpLiterals.isIpv4Literal(""))
    }

    @Test
    fun `accepts ipv6 literals`() {
        assertTrue(IpLiterals.isIpLiteral("2a01:4f9:c013:d2ba::1"))
        assertTrue(IpLiterals.isIpv6Literal("::1"))
        // IPv4-mapped literals parse to Inet4Address in the JDK and are
        // therefore rejected as IPv6. Pinned current behavior.
        assertFalse(IpLiterals.isIpv6Literal("::ffff:192.0.2.128"))
    }

    @Test
    fun `rejects malformed ipv6 literals`() {
        assertFalse(IpLiterals.isIpv6Literal("2a01::zzzz"))
        assertFalse(IpLiterals.isIpv6Literal("not-an-ip"))
        assertFalse(IpLiterals.isIpv6Literal("1.2.3.4"))
        assertFalse(IpLiterals.isIpv6Literal(""))
    }

    @Test
    fun `rejects hostnames and garbage`() {
        assertFalse(IpLiterals.isIpLiteral("localhost"))
        assertFalse(IpLiterals.isIpLiteral("meduza.io"))
        assertFalse(IpLiterals.isIpLiteral("example.com"))
        assertFalse(IpLiterals.isIpLiteral("12345"))
        assertFalse(IpLiterals.isIpLiteral(""))
    }

    @Test
    fun `rejects overlong input`() {
        assertFalse(IpLiterals.isIpLiteral("1".repeat(65)))
        assertFalse(IpLiterals.isIpv6Literal("a:".repeat(40)))
    }
}
