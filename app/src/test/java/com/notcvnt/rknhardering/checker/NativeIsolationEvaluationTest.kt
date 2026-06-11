package com.notcvnt.rknhardering.checker

import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class NativeIsolationEvaluationTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun primaryUserNotProfileOwnerProducesNothing() {
        val outcome = NativeSignsChecker.evaluateIsolation(
            context,
            userId = 0,
            isProfileOwner = false,
        )
        assertFalse(outcome.needsReview)
        assertTrue(outcome.evidence.isEmpty())
    }

    @Test
    fun secondaryUserRaisesNeedsReview() {
        val outcome = NativeSignsChecker.evaluateIsolation(
            context,
            userId = 10,
            isProfileOwner = false,
        )
        assertTrue(outcome.needsReview)
        assertEquals(EvidenceSource.SANDBOX_ISOLATION, outcome.evidence.first().source)
    }

    @Test
    fun cloneUserIdIsLabeled() {
        val outcome = NativeSignsChecker.evaluateIsolation(
            context,
            userId = 999,
            isProfileOwner = false,
        )
        assertTrue(outcome.needsReview)
        assertTrue(outcome.evidence.any { it.description.contains("clone") })
    }

    @Test
    fun profileOwnerRaisesNeedsReview() {
        val outcome = NativeSignsChecker.evaluateIsolation(
            context,
            userId = 0,
            isProfileOwner = true,
        )
        assertTrue(outcome.needsReview)
        assertTrue(outcome.evidence.any { it.description.contains("profile") })
    }
}
