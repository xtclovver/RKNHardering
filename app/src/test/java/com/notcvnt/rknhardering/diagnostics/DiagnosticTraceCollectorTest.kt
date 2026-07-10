package com.notcvnt.rknhardering.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DiagnosticTraceCollectorTest {
    @Test
    fun `records concurrently and sorts deterministically`() {
        val collector = DiagnosticTraceCollector(privacyMode = false)
        val pool = Executors.newFixedThreadPool(4)
        val start = CountDownLatch(1)
        val done = CountDownLatch(40)

        repeat(40) { index ->
            pool.execute {
                start.await()
                collector.record(
                    category = if (index % 2 == 0) "b" else "a",
                    source = "source-${40 - index}",
                    status = "ok",
                    body = "body-$index",
                )
                done.countDown()
            }
        }
        start.countDown()
        assertTrue(done.await(2, TimeUnit.SECONDS))
        pool.shutdownNow()

        val snapshot = collector.snapshot()
        assertEquals(40, snapshot.entries.size)
        assertEquals(
            snapshot.entries.sortedWith(
                compareBy<DiagnosticEntry>(
                    DiagnosticEntry::category,
                    DiagnosticEntry::source,
                    { it.target.orEmpty() },
                    DiagnosticEntry::status,
                    DiagnosticEntry::body,
                ),
            ),
            snapshot.entries,
        )
    }

    @Test
    fun `enforces utf8 entry and run limits`() {
        val collector = DiagnosticTraceCollector(
            privacyMode = false,
            entryLimitBytes = 16,
            runLimitBytes = 22,
        )
        collector.record("a", "one", status = "ok", body = "ёжикёж")
        collector.record("b", "two", status = "ok", body = "abcdef")

        val snapshot = collector.snapshot()
        assertEquals(22, snapshot.storedBytes)
        assertTrue(snapshot.truncated)
        assertEquals(18, snapshot.entries.first { it.source == "one" }.originalBytes)
        assertTrue(snapshot.entries.all { it.storedBytes <= 16 })
        assertTrue(snapshot.entries.all { it.truncated })
    }

    @Test
    fun `redacts secrets before storage`() {
        val collector = DiagnosticTraceCollector(privacyMode = false)
        collector.record(
            category = "http",
            source = "client",
            target = "https://alice:password@example.test/path?token=secret-token&safe=yes",
            status = "Authorization: Bearer abc.def",
            body = """
                Cookie: session=hidden
                password=hunter2
                {"cookie":"SID=body-secret","authorization":"Token body-auth","key":"body-key"}
                uuid=123e4567-e89b-12d3-a456-426614174000
                bssid=aa:bb:cc:dd:ee:ff
            """.trimIndent(),
        )

        val entry = collector.snapshot().entries.single()
        val stored = listOf(entry.target, entry.status, entry.body).joinToString("\n")
        listOf(
            "alice", "password@example", "secret-token", "abc.def", "hidden", "hunter2",
            "body-secret", "body-auth", "body-key", "123e4567", "aa:bb",
        ).forEach {
            assertFalse("Leaked <$it> in <$stored>", stored.contains(it, ignoreCase = true))
        }
        assertTrue(stored.contains("[REDACTED]"))
    }

    @Test
    fun `privacy mode masks public and local ip addresses in every field`() {
        val collector = DiagnosticTraceCollector(privacyMode = true)
        collector.record(
            category = "10.0.0.1",
            source = "2001:db8::1",
            target = "127.0.0.1",
            status = "from 192.0.2.10",
            body = "local=::1 public=8.8.8.8",
        )

        val entry = collector.snapshot().entries.single()
        val stored = listOf(entry.category, entry.source, entry.target, entry.status, entry.body).joinToString("\n")
        listOf("10.0.0.1", "2001:db8::1", "127.0.0.1", "192.0.2.10", "::1", "8.8.8.8").forEach {
            assertFalse(stored.contains(it))
        }
        assertTrue(stored.contains("redacted"))
    }

    @Test
    fun `clear and snapshot reject later writes`() {
        val collector = DiagnosticTraceCollector(privacyMode = false)
        collector.record("a", "before", status = "ok", body = "kept")
        collector.clear()
        collector.record("b", "after", status = "ok", body = "ignored")
        assertEquals(DiagnosticSnapshot.EMPTY, collector.snapshot())
    }

    @Test
    fun `scan truncation remains visible when a later entry cannot fit`() {
        val collector = DiagnosticTraceCollector(
            privacyMode = false,
            entryLimitBytes = 8,
            runLimitBytes = 8,
        )
        collector.record("a", "one", status = "ok", body = "ab")
        collector.record("b", "two", status = "ok", body = "c")

        val snapshot = collector.snapshot()
        assertEquals(1, snapshot.entries.size)
        assertFalse(snapshot.entries.single().truncated)
        assertTrue(snapshot.truncated)
    }
}
