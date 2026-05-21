package com.notcvnt.rknhardering.customcheck

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

@RunWith(RobolectricTestRunner::class)
class CustomCheckRepositoryTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        // Clear all saved profiles and prefs before each test
        File(context.filesDir, "custom_checks").deleteRecursively()
        context.getSharedPreferences("custom_check_prefs", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    private fun makeProfile(name: String = "Test", id: String = java.util.UUID.randomUUID().toString()): CustomCheckProfile =
        CustomCheckProfile(id = id, name = name)

    // ── getAll ────────────────────────────────────────────────────────────────

    @Test
    fun `getAll returns empty list when no profiles saved`() {
        assertTrue(CustomCheckRepository.getAll(context).isEmpty())
    }

    @Test
    fun `getAll returns all saved profiles`() {
        val p1 = makeProfile("Alpha")
        val p2 = makeProfile("Beta")
        CustomCheckRepository.save(context, p1)
        CustomCheckRepository.save(context, p2)

        val all = CustomCheckRepository.getAll(context)
        assertEquals(2, all.size)
    }

    // ── getById ───────────────────────────────────────────────────────────────

    @Test
    fun `getById returns null for missing profile`() {
        assertNull(CustomCheckRepository.getById(context, "nonexistent"))
    }

    @Test
    fun `getById returns saved profile by id`() {
        val profile = makeProfile("MyProfile", "fixed-id")
        CustomCheckRepository.save(context, profile)

        val loaded = CustomCheckRepository.getById(context, "fixed-id")
        assertNotNull(loaded)
        assertEquals("MyProfile", loaded?.name)
    }

    // ── save / update ─────────────────────────────────────────────────────────

    @Test
    fun `save overwrites existing profile`() {
        val profile = makeProfile("Original", "same-id")
        CustomCheckRepository.save(context, profile)

        val updated = profile.copy(name = "Updated")
        CustomCheckRepository.save(context, updated)

        val loaded = CustomCheckRepository.getById(context, "same-id")
        assertEquals("Updated", loaded?.name)
        assertEquals(1, CustomCheckRepository.getAll(context).size)
    }

    // ── delete ────────────────────────────────────────────────────────────────

    @Test
    fun `delete removes profile from storage`() {
        val profile = makeProfile("ToDelete", "del-id")
        CustomCheckRepository.save(context, profile)
        CustomCheckRepository.delete(context, "del-id")

        assertNull(CustomCheckRepository.getById(context, "del-id"))
        assertTrue(CustomCheckRepository.getAll(context).isEmpty())
    }

    @Test
    fun `delete clears active profile id if active profile is deleted`() {
        val profile = makeProfile("Active", "active-id")
        CustomCheckRepository.save(context, profile)
        CustomCheckRepository.setActiveProfileId(context, "active-id")

        CustomCheckRepository.delete(context, "active-id")

        assertNull(CustomCheckRepository.getActiveProfileId(context))
    }

    @Test
    fun `delete does not clear active profile id if a different profile is deleted`() {
        val p1 = makeProfile("P1", "id-1")
        val p2 = makeProfile("P2", "id-2")
        CustomCheckRepository.save(context, p1)
        CustomCheckRepository.save(context, p2)
        CustomCheckRepository.setActiveProfileId(context, "id-1")

        CustomCheckRepository.delete(context, "id-2")

        assertEquals("id-1", CustomCheckRepository.getActiveProfileId(context))
    }

    // ── active profile ────────────────────────────────────────────────────────

    @Test
    fun `getActiveProfileId returns null initially`() {
        assertNull(CustomCheckRepository.getActiveProfileId(context))
    }

    @Test
    fun `setActiveProfileId persists value`() {
        CustomCheckRepository.setActiveProfileId(context, "some-id")
        assertEquals("some-id", CustomCheckRepository.getActiveProfileId(context))
    }

    @Test
    fun `setActiveProfileId null clears value`() {
        CustomCheckRepository.setActiveProfileId(context, "some-id")
        CustomCheckRepository.setActiveProfileId(context, null)
        assertNull(CustomCheckRepository.getActiveProfileId(context))
    }

    // ── duplicate ─────────────────────────────────────────────────────────────

    @Test
    fun `duplicate creates new profile with new id`() {
        val original = makeProfile("Original", "orig-id")
        CustomCheckRepository.save(context, original)

        val copy = CustomCheckRepository.duplicate(context, "orig-id", "Copy of Original")
        assertNotEquals("orig-id", copy.id)
        assertEquals("Copy of Original", copy.name)
    }

    @Test
    fun `duplicate sets sourceProfileId to original id`() {
        val original = makeProfile("Original", "orig-id")
        CustomCheckRepository.save(context, original)

        val copy = CustomCheckRepository.duplicate(context, "orig-id", "Copy")
        assertEquals("orig-id", copy.sourceProfileId)
    }

    @Test
    fun `duplicate saves copy to storage`() {
        val original = makeProfile("Original", "orig-id")
        CustomCheckRepository.save(context, original)

        val copy = CustomCheckRepository.duplicate(context, "orig-id", "Copy")

        assertNotNull(CustomCheckRepository.getById(context, copy.id))
        assertEquals(2, CustomCheckRepository.getAll(context).size)
    }

    @Test(expected = IllegalStateException::class)
    fun `duplicate throws on missing source id`() {
        CustomCheckRepository.duplicate(context, "no-such-id", "Copy")
    }
}
