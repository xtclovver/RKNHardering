package com.notcvnt.rknhardering.checker.ipconsensus

import com.notcvnt.rknhardering.model.AsnInfo
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class AsnResolverTest {

    @Test
    fun `resolveAll dedupes lookups and caches results`() = runBlocking {
        val calls = AtomicInteger(0)
        val resolver = AsnResolver(
            maxIps = 6,
            lookup = {
                calls.incrementAndGet()
                AsnInfo(asn = "AS1 Example", countryCode = "DE")
            },
        )

        val first = resolver.resolveAll(setOf("1.2.3.4", "1.2.3.4"))
        val second = resolver.resolveAll(setOf("1.2.3.4"))

        assertEquals(1, calls.get())
        assertEquals("DE", first["1.2.3.4"]?.countryCode)
        assertEquals("DE", second["1.2.3.4"]?.countryCode)
    }

    @Test
    fun `resolveAll caps the number of lookups at maxIps`() = runBlocking {
        val calls = AtomicInteger(0)
        val resolver = AsnResolver(
            maxIps = 2,
            lookup = { _ ->
                calls.incrementAndGet()
                AsnInfo(asn = "AS1", countryCode = "XX")
            },
        )

        val inputs = setOf("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")
        val result = resolver.resolveAll(inputs)

        assertEquals(2, calls.get())
        assertEquals(2, result.size)
        // The two entries that did get resolved have data; the others are absent.
    }

    @Test
    fun `resolveAll surfaces null when lookup returns null`() = runBlocking {
        val resolver = AsnResolver(maxIps = 6, lookup = { null })
        val result = resolver.resolveAll(setOf("1.2.3.4"))
        assertNull(result["1.2.3.4"])
    }
}
