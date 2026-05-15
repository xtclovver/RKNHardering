package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

class OperatorWhitelistProbeTest {

    // Per-URL response registry
    private val responses = mutableMapOf<String, Pair<Int, String>>()
    // Per-URL exception registry
    private val exceptions = mutableMapOf<String, Throwable>()

    @Before
    fun setUp() {
        responses.clear()
        exceptions.clear()
        OperatorWhitelistProbe.executeOverride = { url, _ ->
            exceptions[url]?.let { throw it }
            responses[url] ?: (200 to "")
        }
    }

    @After
    fun tearDown() {
        OperatorWhitelistProbe.executeOverride = null
    }

    private fun setGoogleOk() {
        responses["https://www.google.com/generate_204"] = 204 to ""
    }

    private fun setAppleOk() {
        responses["https://www.apple.com/library/test/success.html"] =
            200 to "<html><head><TITLE>Success</TITLE></head><BODY>Success</BODY></html>"
    }

    private fun setFirefoxOk() {
        responses["https://detectportal.firefox.com/success.txt"] = 200 to "success\n"
    }

    private fun setRuOk() {
        responses["https://yandex.ru/"] = 200 to ""
    }

    private fun setGoogleFail() {
        exceptions["https://www.google.com/generate_204"] = IOException("blocked")
    }

    private fun setAppleFail() {
        exceptions["https://www.apple.com/library/test/success.html"] = IOException("blocked")
    }

    private fun setFirefoxFail() {
        exceptions["https://detectportal.firefox.com/success.txt"] = IOException("blocked")
    }

    private fun setRuFail() {
        exceptions["https://yandex.ru/"] = IOException("network down")
    }

    @Test
    fun `all three captive portals unreachable and RU works returns whitelistDetected true`() {
        setGoogleFail()
        setAppleFail()
        setFirefoxFail()
        setRuOk()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertTrue(result.whitelistDetected)
        assertFalse(result.googleReachable)
        assertFalse(result.appleReachable)
        assertFalse(result.firefoxReachable)
        assertTrue(result.russianControlReachable)
        assertEquals(3, result.errors.size)
    }

    @Test
    fun `all three captive portals reachable returns whitelistDetected false`() {
        setGoogleOk()
        setAppleOk()
        setFirefoxOk()
        setRuOk()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertFalse(result.whitelistDetected)
        assertTrue(result.googleReachable)
        assertTrue(result.appleReachable)
        assertTrue(result.firefoxReachable)
        assertTrue(result.russianControlReachable)
        assertTrue(result.errors.isEmpty())
    }

    @Test
    fun `all four endpoints unreachable returns whitelistDetected false`() {
        setGoogleFail()
        setAppleFail()
        setFirefoxFail()
        setRuFail()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertFalse(result.whitelistDetected)
        assertFalse(result.googleReachable)
        assertFalse(result.appleReachable)
        assertFalse(result.firefoxReachable)
        assertFalse(result.russianControlReachable)
        assertEquals(4, result.errors.size)
    }

    @Test
    fun `partial captive portal availability returns whitelistDetected false`() {
        // Google blocked, Apple and Firefox reachable, RU reachable
        setGoogleFail()
        setAppleOk()
        setFirefoxOk()
        setRuOk()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertFalse(result.whitelistDetected)
        assertFalse(result.googleReachable)
        assertTrue(result.appleReachable)
        assertTrue(result.firefoxReachable)
        assertTrue(result.russianControlReachable)
    }

    @Test
    fun `google wrong response code is not reachable`() {
        responses["https://www.google.com/generate_204"] = 200 to "some body"
        setAppleFail()
        setFirefoxFail()
        setRuOk()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertTrue(result.whitelistDetected)
        assertFalse(result.googleReachable)
    }

    @Test
    fun `apple wrong body content is not reachable`() {
        setGoogleFail()
        responses["https://www.apple.com/library/test/success.html"] =
            200 to "<html><TITLE>Error</TITLE></html>"
        setFirefoxFail()
        setRuOk()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertTrue(result.whitelistDetected)
        assertFalse(result.appleReachable)
    }

    @Test
    fun `firefox body not starting with success is not reachable`() {
        setGoogleFail()
        setAppleFail()
        responses["https://detectportal.firefox.com/success.txt"] = 200 to "fail"
        setRuOk()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertTrue(result.whitelistDetected)
        assertFalse(result.firefoxReachable)
    }

    @Test
    fun `ru control accepts 3xx redirect as success`() {
        responses["https://yandex.ru/"] = 301 to ""
        setGoogleFail()
        setAppleFail()
        setFirefoxFail()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertTrue(result.russianControlReachable)
        assertTrue(result.whitelistDetected)
    }

    @Test
    fun `duration is non-negative`() {
        setGoogleOk()
        setAppleOk()
        setFirefoxOk()
        setRuOk()

        val result = runBlocking { OperatorWhitelistProbe.probe() }

        assertTrue(result.durationMs >= 0)
    }
}
