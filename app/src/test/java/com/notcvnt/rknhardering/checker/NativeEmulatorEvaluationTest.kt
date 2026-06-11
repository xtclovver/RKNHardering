package com.notcvnt.rknhardering.checker

import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.probe.NativeEmulatorFinding
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class NativeEmulatorEvaluationTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun qemuPipeIsHighConfidenceNeedsReview() {
        val findings = listOf(NativeEmulatorFinding("qemu_pipe", "/dev/qemu_pipe"))
        val outcome = NativeSignsChecker.evaluateEmulator(context, findings, emptyList())
        assertTrue(outcome.needsReview)
        assertFalse(outcome.detected)
        val ev = outcome.evidence.single()
        assertEquals(EvidenceSource.NATIVE_EMULATOR, ev.source)
        assertEquals(EvidenceConfidence.HIGH, ev.confidence)
    }

    @Test
    fun buildOnlySignalIsMediumConfidence() {
        val outcome = NativeSignsChecker.evaluateEmulator(
            context,
            emptyList(),
            listOf("Build.FINGERPRINT=generic/sdk_gphone"),
        )
        assertTrue(outcome.needsReview)
        assertEquals(EvidenceConfidence.MEDIUM, outcome.evidence.single().confidence)
    }

    @Test
    fun emptyInputsProduceNoEvidence() {
        val outcome = NativeSignsChecker.evaluateEmulator(context, emptyList(), emptyList())
        assertFalse(outcome.needsReview)
        assertTrue(outcome.evidence.isEmpty())
    }
}
