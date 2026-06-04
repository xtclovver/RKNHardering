package com.notcvnt.rknhardering.customcheck

import org.junit.Assert.assertEquals
import org.junit.Test

class UrlSanitizerTest {

    @Test fun `https url with public host passes`() {
        assertEquals("https://example.com/api", UrlSanitizer.sanitizeHttpsUrl("https://example.com/api"))
    }

    @Test fun `http url is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("http://example.com"))
    }

    @Test fun `file scheme is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("file:///etc/passwd"))
    }

    @Test fun `content scheme is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("content://com.android.providers/x"))
    }

    @Test fun `javascript scheme is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("javascript:alert(1)"))
    }

    @Test fun `data scheme is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("data:text/html,x"))
    }

    @Test fun `https loopback is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://127.0.0.1/x"))
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://localhost/x"))
    }

    @Test fun `https rfc1918 is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://10.0.0.1/x"))
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://192.168.1.1/x"))
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://172.16.5.5/x"))
    }

    @Test fun `https cgnat is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://100.64.0.1/x"))
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://100.127.255.254/x"))
    }

    @Test fun `https link local is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://169.254.1.1/x"))
    }

    @Test fun `https with mdns is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://router.local/x"))
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://nas.lan/x"))
    }

    @Test fun `host without dot is rejected`() {
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl("https://intranet/x"))
    }

    @Test fun `excessive url length is rejected`() {
        val long = "https://example.com/" + "a".repeat(600)
        assertEquals("", UrlSanitizer.sanitizeHttpsUrl(long))
    }

    @Test fun `host sanitizer accepts public dns name`() {
        assertEquals("stun.example.com", UrlSanitizer.sanitizeHost("stun.example.com"))
    }

    @Test fun `host sanitizer rejects private ip`() {
        assertEquals("", UrlSanitizer.sanitizeHost("192.168.0.1"))
        assertEquals("", UrlSanitizer.sanitizeHost("127.0.0.1"))
    }

    @Test fun `host sanitizer rejects bare hostname`() {
        assertEquals("", UrlSanitizer.sanitizeHost("router"))
    }

    @Test fun `address list filters private`() {
        assertEquals(
            "8.8.8.8, 1.1.1.1",
            UrlSanitizer.sanitizeAddressList("8.8.8.8, 192.168.1.1, 1.1.1.1, 127.0.0.1")
        )
    }

    @Test fun `address list empty stays empty`() {
        assertEquals("", UrlSanitizer.sanitizeAddressList(""))
    }
}
