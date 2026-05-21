package com.notcvnt.rknhardering.customcheck.mapper

import com.notcvnt.rknhardering.customcheck.ResponseMapping
import com.notcvnt.rknhardering.customcheck.ResponseType
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)

class EndpointResponseMapperTest {

    // --- autoDetectResponseType ---

    @Test
    fun `autoDetectResponseType detects JSON object`() {
        val raw = """{"ip":"1.2.3.4","country_code":"US"}"""
        assertEquals(ResponseType.JSON, EndpointResponseMapper.autoDetectResponseType(raw))
    }

    @Test
    fun `autoDetectResponseType detects JSON array`() {
        val raw = """[{"ip":"1.2.3.4"}]"""
        assertEquals(ResponseType.JSON, EndpointResponseMapper.autoDetectResponseType(raw))
    }

    @Test
    fun `autoDetectResponseType detects KEY_VALUE cloudflare trace`() {
        val raw = "fl=abc\nip=1.2.3.4\nloc=US\ncolo=DME\n"
        assertEquals(ResponseType.KEY_VALUE, EndpointResponseMapper.autoDetectResponseType(raw))
    }

    @Test
    fun `autoDetectResponseType detects PLAIN_TEXT IPv4`() {
        assertEquals(ResponseType.PLAIN_TEXT, EndpointResponseMapper.autoDetectResponseType("1.2.3.4"))
    }

    @Test
    fun `autoDetectResponseType detects PLAIN_TEXT with whitespace`() {
        assertEquals(ResponseType.PLAIN_TEXT, EndpointResponseMapper.autoDetectResponseType("  1.2.3.4  "))
    }

    @Test
    fun `autoDetectResponseType falls back to REGEX for arbitrary text`() {
        assertEquals(ResponseType.REGEX, EndpointResponseMapper.autoDetectResponseType("Your IP is 1.2.3.4"))
    }

    // --- autoDetectMapping for JSON ---

    @Test
    fun `autoDetect_json_finds_ip_country_asn`() {
        val raw = """{"ip":"1.2.3.4","country_code":"US","asn":{"asn":12345}}"""
        val mapping = EndpointResponseMapper.autoDetectMapping(raw, ResponseType.JSON)
        assertEquals(ResponseType.JSON, mapping.responseType)
        assertEquals("$.ip", mapping.ipPath)
        assertEquals("$.country_code", mapping.countryCodePath)
        assertEquals("$.asn.asn", mapping.asnPath)
    }

    @Test
    fun `autoDetect_json_finds_isp_org_hosting_proxy`() {
        val raw = """{"ip":"1.2.3.4","isp":"Acme","org":"Org","is_hosting":true,"is_proxy":false}"""
        val mapping = EndpointResponseMapper.autoDetectMapping(raw, ResponseType.JSON)
        assertEquals("$.isp", mapping.ispPath)
        assertEquals("$.org", mapping.orgPath)
        assertEquals("$.is_hosting", mapping.isHostingPath)
        assertEquals("$.is_proxy", mapping.isProxyPath)
    }

    @Test
    fun `autoDetect_json_finds_asn_string`() {
        val raw = """{"ip":"1.2.3.4","asn":"AS12345"}"""
        val mapping = EndpointResponseMapper.autoDetectMapping(raw, ResponseType.JSON)
        assertEquals("$.asn", mapping.asnPath)
    }

    @Test
    fun `autoDetect_ipinfo_style`() {
        val raw = """{"ip": "1.2.3.4", "country": "FI", "org": "AS24940 Hetzner"}"""
        val mapping = EndpointResponseMapper.autoDetectMapping(raw, ResponseType.JSON)
        assertEquals("$.ip", mapping.ipPath)
        assertEquals("$.country", mapping.countryCodePath)
        assertNull(mapping.countryNamePath)
        assertEquals("$.org", mapping.orgPath)
        assertEquals("$.org", mapping.asnPath)
    }

    @Test
    fun `autoDetect_ipapi_style`() {
        val raw = """{"query": "1.2.3.4", "country": "Finland", "countryCode": "FI", "as": "AS12345", "isp": "Hetzner"}"""
        val mapping = EndpointResponseMapper.autoDetectMapping(raw, ResponseType.JSON)
        assertEquals("$.query", mapping.ipPath)
        assertEquals("$.countryCode", mapping.countryCodePath)
        assertEquals("$.country", mapping.countryNamePath)
        assertEquals("$.as", mapping.asnPath)
        assertEquals("$.isp", mapping.ispPath)
    }

    // --- autoDetectMapping for KEY_VALUE ---

    @Test
    fun `autoDetect_cloudflare_trace`() {
        val raw = "ip=1.2.3.4\nloc=US\ncolo=DME\n"
        val mapping = EndpointResponseMapper.autoDetectMapping(raw, ResponseType.KEY_VALUE)
        assertEquals(ResponseType.KEY_VALUE, mapping.responseType)
        assertEquals("ip", mapping.ipPath)
        assertEquals("loc", mapping.countryCodePath)
    }

    @Test
    fun `autoDetect_cloudflare_trace_no_ip_field`() {
        val raw = "loc=US\ncolo=DME\n"
        val mapping = EndpointResponseMapper.autoDetectMapping(raw, ResponseType.KEY_VALUE)
        assertNull(mapping.ipPath)
        assertEquals("loc", mapping.countryCodePath)
    }

    // --- autoDetectMapping for PLAIN_TEXT ---

    @Test
    fun `autoDetect_plain_text_ip`() {
        val mapping = EndpointResponseMapper.autoDetectMapping("1.2.3.4", ResponseType.PLAIN_TEXT)
        assertEquals(ResponseType.PLAIN_TEXT, mapping.responseType)
        assertEquals("", mapping.ipPath)
    }

    // --- extractField ---

    @Test
    fun `extractField_nested_path`() {
        val raw = """{"data":{"geo":{"country":"Russia"}}}"""
        val mapping = ResponseMapping(responseType = ResponseType.JSON, countryNamePath = "$.data.geo.country")
        assertEquals("Russia", EndpointResponseMapper.extractField(raw, mapping, MappingField.COUNTRY_NAME))
    }

    @Test
    fun `extractField_missing_returns_null`() {
        val raw = """{"ip":"1.2.3.4"}"""
        val mapping = ResponseMapping(responseType = ResponseType.JSON, countryCodePath = "$.country_code")
        assertNull(EndpointResponseMapper.extractField(raw, mapping, MappingField.COUNTRY_CODE))
    }

    @Test
    fun `extractField null path returns null`() {
        val raw = """{"ip":"1.2.3.4"}"""
        val mapping = ResponseMapping(responseType = ResponseType.JSON)  // all paths null
        assertNull(EndpointResponseMapper.extractField(raw, mapping, MappingField.IP))
    }

    @Test
    fun `extractField plain text ip with empty path`() {
        val mapping = ResponseMapping(responseType = ResponseType.PLAIN_TEXT, ipPath = "")
        assertEquals("1.2.3.4", EndpointResponseMapper.extractField("  1.2.3.4  ", mapping, MappingField.IP))
    }

    @Test
    fun `extractField plain text non-ip field returns null`() {
        val mapping = ResponseMapping(responseType = ResponseType.PLAIN_TEXT, ipPath = "", countryCodePath = "US")
        // PLAIN_TEXT only handles IP with empty path; countryCodePath is not supported for plain text
        assertNull(EndpointResponseMapper.extractField("1.2.3.4", mapping, MappingField.COUNTRY_CODE))
    }

    @Test
    fun `extractField key_value`() {
        val raw = "ip=1.2.3.4\nloc=US\n"
        val mapping = ResponseMapping(responseType = ResponseType.KEY_VALUE, ipPath = "ip", countryCodePath = "loc")
        assertEquals("1.2.3.4", EndpointResponseMapper.extractField(raw, mapping, MappingField.IP))
        assertEquals("US", EndpointResponseMapper.extractField(raw, mapping, MappingField.COUNTRY_CODE))
    }

    @Test
    fun `extractField regex`() {
        val raw = "Your IP: 1.2.3.4"
        val mapping = ResponseMapping(responseType = ResponseType.REGEX, ipPath = "IP: (.+)")
        assertEquals("1.2.3.4", EndpointResponseMapper.extractField(raw, mapping, MappingField.IP))
    }

    // --- extractAll ---

    @Test
    fun `extractAll_returns_all_eight_fields`() {
        val raw = """{"ip":"1.2.3.4","country_code":"US","country":"United States","isp":"Acme","org":"AcmeOrg","asn":"AS999","is_hosting":false,"is_proxy":true}"""
        val mapping = ResponseMapping(
            responseType = ResponseType.JSON,
            ipPath = "$.ip",
            countryCodePath = "$.country_code",
            countryNamePath = "$.country",
            ispPath = "$.isp",
            orgPath = "$.org",
            asnPath = "$.asn",
            isHostingPath = "$.is_hosting",
            isProxyPath = "$.is_proxy",
        )
        val result = EndpointResponseMapper.extractAll(raw, mapping)
        assertEquals(8, result.size)
        assertEquals("1.2.3.4", result[MappingField.IP])
        assertEquals("US", result[MappingField.COUNTRY_CODE])
        assertEquals("United States", result[MappingField.COUNTRY_NAME])
        assertEquals("Acme", result[MappingField.ISP])
        assertEquals("AcmeOrg", result[MappingField.ORG])
        assertEquals("AS999", result[MappingField.ASN])
        assertEquals("false", result[MappingField.IS_HOSTING])
        assertEquals("true", result[MappingField.IS_PROXY])
    }

    @Test
    fun `extractAll with all null paths returns map with all nulls`() {
        val raw = """{"ip":"1.2.3.4"}"""
        val mapping = ResponseMapping(responseType = ResponseType.JSON)  // all paths null
        val result = EndpointResponseMapper.extractAll(raw, mapping)
        assertEquals(8, result.size)
        assertTrue(result.values.all { it == null })
    }

    // --- testEndpoint via MockWebServer ---

    @Test
    fun `testEndpoint_success_with_json_response`() {
        MockWebServer().use { server ->
            server.enqueue(
                MockResponse()
                    .setResponseCode(200)
                    .setBody("""{"ip":"1.2.3.4","country_code":"US"}""")
            )
            val url = server.url("/ip").toString()
            val result = runBlocking { EndpointResponseMapper.testEndpoint(url, timeoutMs = 3000) }
            assertTrue(result.success)
            assertEquals(200, result.statusCode)
            assertNotNull(result.rawBody)
            assertNull(result.error)
            assertEquals(ResponseType.JSON, result.detectedType)
            assertNotNull(result.suggestedMapping)
            assertEquals("$.ip", result.suggestedMapping?.ipPath)
            assertEquals("$.country_code", result.suggestedMapping?.countryCodePath)
        }
    }

    @Test
    fun `testEndpoint_timeout_returns_error`() {
        MockWebServer().use { server ->
            server.enqueue(
                MockResponse()
                    .setHeadersDelay(3000, TimeUnit.MILLISECONDS)
                    .setBody("1.2.3.4")
            )
            val url = server.url("/ip").toString()
            val result = runBlocking { EndpointResponseMapper.testEndpoint(url, timeoutMs = 500) }
            assertFalse(result.success)
            assertNotNull(result.error)
            assertNull(result.statusCode)
        }
    }

    @Test
    fun `testEndpoint_invalid_url_returns_error`() {
        val result = runBlocking { EndpointResponseMapper.testEndpoint("not-a-url", timeoutMs = 1000) }
        assertFalse(result.success)
        assertNotNull(result.error)
    }

    @Test
    fun `testEndpoint_http_error_returns_failure`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(404).setBody("Not Found"))
            val url = server.url("/ip").toString()
            val result = runBlocking { EndpointResponseMapper.testEndpoint(url, timeoutMs = 3000) }
            assertFalse(result.success)
            assertEquals(404, result.statusCode)
        }
    }
}
