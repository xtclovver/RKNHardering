package com.notcvnt.rknhardering.customcheck.mapper

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)

class ResponseMappingParserTest {

    // --- extractJsonPath ---

    @Test
    fun `extractJsonPath top-level field`() {
        val json = JSONObject("""{"ip":"1.2.3.4"}""")
        assertEquals("1.2.3.4", ResponseMappingParser.extractJsonPath(json, "$.ip"))
    }

    @Test
    fun `extractJsonPath nested field`() {
        val json = JSONObject("""{"geo":{"country":"Russia"}}""")
        assertEquals("Russia", ResponseMappingParser.extractJsonPath(json, "$.geo.country"))
    }

    @Test
    fun `extractJsonPath deeply nested field`() {
        val json = JSONObject("""{"a":{"b":{"c":"deep"}}}""")
        assertEquals("deep", ResponseMappingParser.extractJsonPath(json, "$.a.b.c"))
    }

    @Test
    fun `extractJsonPath array index`() {
        val json = JSONObject("""{"data":[{"ip":"5.5.5.5"},{"ip":"6.6.6.6"}]}""")
        assertEquals("5.5.5.5", ResponseMappingParser.extractJsonPath(json, "$.data[0].ip"))
    }

    @Test
    fun `extractJsonPath second array element`() {
        val json = JSONObject("""{"data":[{"ip":"5.5.5.5"},{"ip":"6.6.6.6"}]}""")
        assertEquals("6.6.6.6", ResponseMappingParser.extractJsonPath(json, "$.data[1].ip"))
    }

    @Test
    fun `extractJsonPath missing field returns null`() {
        val json = JSONObject("""{"ip":"1.2.3.4"}""")
        assertNull(ResponseMappingParser.extractJsonPath(json, "$.country"))
    }

    @Test
    fun `extractJsonPath missing nested field returns null`() {
        val json = JSONObject("""{"geo":{"country":"RU"}}""")
        assertNull(ResponseMappingParser.extractJsonPath(json, "$.geo.city"))
    }

    @Test
    fun `extractJsonPath out-of-bounds array index returns null`() {
        val json = JSONObject("""{"arr":[1,2]}""")
        assertNull(ResponseMappingParser.extractJsonPath(json, "$.arr[5]"))
    }

    @Test
    fun `extractJsonPath invalid prefix returns null`() {
        val json = JSONObject("""{"ip":"1.2.3.4"}""")
        assertNull(ResponseMappingParser.extractJsonPath(json, "ip"))
    }

    @Test
    fun `extractJsonPath integer value`() {
        val json = JSONObject("""{"asn":12345}""")
        assertEquals(12345, ResponseMappingParser.extractJsonPath(json, "$.asn"))
    }

    // --- extractKeyValue ---

    @Test
    fun `extractKeyValue finds ip field`() {
        val text = "fl=abc\nip=1.2.3.4\nloc=US\n"
        assertEquals("1.2.3.4", ResponseMappingParser.extractKeyValue(text, "ip"))
    }

    @Test
    fun `extractKeyValue finds loc field`() {
        val text = "ip=1.2.3.4\nloc=US\ncolo=DME\n"
        assertEquals("US", ResponseMappingParser.extractKeyValue(text, "loc"))
    }

    @Test
    fun `extractKeyValue missing key returns null`() {
        val text = "ip=1.2.3.4\nloc=US\n"
        assertNull(ResponseMappingParser.extractKeyValue(text, "asn"))
    }

    @Test
    fun `extractKeyValue value with equals sign`() {
        val text = "token=abc=def\n"
        assertEquals("abc=def", ResponseMappingParser.extractKeyValue(text, "token"))
    }

    // --- extractRegex ---

    @Test
    fun `extractRegex returns first capture group`() {
        assertEquals("1.2.3.4", ResponseMappingParser.extractRegex("ip=1.2.3.4", "ip=(.+)"))
    }

    @Test
    fun `extractRegex no match returns null`() {
        assertNull(ResponseMappingParser.extractRegex("nothing here", "ip=(.+)"))
    }

    @Test
    fun `extractRegex invalid pattern returns null`() {
        assertNull(ResponseMappingParser.extractRegex("text", "[invalid("))
    }

    @Test
    fun `extractRegex no capture group returns null`() {
        // No group → groupValues[1] does not exist
        assertNull(ResponseMappingParser.extractRegex("ip=1.2.3.4", "ip=.+"))
    }
}
