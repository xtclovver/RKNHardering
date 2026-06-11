package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ClashApiClientTest {

    @Test
    fun `parses destination ips from connections json`() {
        val json = """
            {"connections":[
              {"metadata":{"destinationIP":"203.0.113.7","host":"example.com"}},
              {"metadata":{"destinationIP":"198.51.100.4","host":""}}
            ]}
        """.trimIndent()
        val ips = ClashApiClient.parseConnectionsDestinationIps(json)
        assertEquals(listOf("203.0.113.7", "198.51.100.4"), ips)
    }

    @Test
    fun `parses proxy node names from proxies json`() {
        val json = """{"proxies":{"DIRECT":{"type":"Direct"},"node-jp":{"type":"Vless"}}}"""
        val nodes = ClashApiClient.parseProxyNodes(json)
        assertTrue(nodes.contains("node-jp"))
    }

    @Test
    fun `config json is recognized as alive`() {
        assertTrue(ClashApiClient.isConfigResponseAlive("""{"port":7890,"mode":"rule"}"""))
        assertTrue(!ClashApiClient.isConfigResponseAlive("not json"))
    }
}
