package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SandboxIntegrityCheckerTest {
    @Test
    fun parserRejectsDuplicateCheckRowsAndDuplicateFields() {
        val duplicateRows = SandboxProbeRowParser.parse(
            arrayOf(
                "beta_v1|check=fd_identity|status=available|critical_mismatch=false",
                "beta_v1|check=fd_identity|status=available|critical_mismatch=false",
            ),
            "fd_identity",
        )
        val duplicateFields = SandboxProbeRowParser.parse(
            arrayOf("beta_v1|check=fd_identity|status=available|status=unsupported"),
            "fd_identity",
        )

        assertEquals(ProbeAvailability.MALFORMED_RESPONSE, duplicateRows.availability)
        assertEquals(ProbeAvailability.MALFORMED_RESPONSE, duplicateFields.availability)
    }

    @Test
    fun parserBoundsInputAndTreatsDenialAsAvailabilityOnly() {
        val oversized = SandboxProbeRowParser.parse(
            arrayOf("beta_v1|check=fd_identity|status=available|value=${"x".repeat(17_000)}"),
            "fd_identity",
        )
        val denied = SandboxProbeRowParser.parse(
            arrayOf("beta_v1|check=fd_identity|status=permission_denied|errno=1"),
            "fd_identity",
        )

        assertEquals(ProbeAvailability.TRUNCATED, oversized.availability)
        assertEquals(ProbeAvailability.PERMISSION_DENIED, denied.availability)
        assertEquals(
            ObservationPolarity.INCONCLUSIVE,
            SandboxIntegrityChecker.nativeObservation(
                definition = fdDefinition(),
                row = denied,
                networkEpochId = "epoch",
                observedAtElapsedMs = 1L,
            ).polarity,
        )
    }

    @Test
    fun processIdentityRequiresTwoContradictionAxes() {
        val oneMismatch = SandboxIntegrityChecker.processObservation(
            snapshot = processSnapshot(packageUid = 20002),
            nativeRow = SandboxProbeRow(
                "sandbox_identity.process",
                ProbeAvailability.AVAILABLE,
                mapOf("uid" to "10001"),
            ),
            networkEpochId = "epoch",
            observedAtElapsedMs = 1L,
        )
        val twoMismatches = SandboxIntegrityChecker.processObservation(
            snapshot = processSnapshot(packageUid = 20002, processNameExpected = false),
            nativeRow = SandboxProbeRow(
                "sandbox_identity.process",
                ProbeAvailability.AVAILABLE,
                mapOf("uid" to "10001"),
            ),
            networkEpochId = "epoch",
            observedAtElapsedMs = 1L,
        )

        assertEquals(ObservationPolarity.INCONCLUSIVE, oneMismatch.polarity)
        assertEquals(ObservationPolarity.POSITIVE, twoMismatches.polarity)
    }

    @Test
    fun successfulSelfContradictionIsPositiveButCleanCompleteProbeIsNegative() {
        val definition = fdDefinition()
        val positive = SandboxIntegrityChecker.nativeObservation(
            definition = definition,
            row = SandboxProbeRow(
                "fd_identity",
                ProbeAvailability.AVAILABLE,
                mapOf("fstat_match" to "false", "critical_mismatch" to "true"),
            ),
            networkEpochId = "epoch",
            observedAtElapsedMs = 1L,
        )
        val negative = SandboxIntegrityChecker.nativeObservation(
            definition = definition,
            row = SandboxProbeRow(
                "fd_identity",
                ProbeAvailability.AVAILABLE,
                mapOf(
                    "fstat_match" to "true",
                    "kcmp_result" to "0",
                    "critical_mismatch" to "false",
                ),
            ),
            networkEpochId = "epoch",
            observedAtElapsedMs = 1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, positive.polarity)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, negative.polarity)
    }

    @Test
    fun successfulDirectFdAndLinkerContradictionsArePositive() {
        val definitions = listOf(
            SandboxProbeDefinition(
                "direct_syscall_consistency",
                EvidenceSource.BETA_HOOK_CONSISTENCY,
                ObservationAuthority.KERNEL_QUERY,
                "hook_consistency",
                DetectionDomain.HOOK_OR_TAMPERING,
                setOf("critical_mismatch"),
            ),
            fdDefinition(),
            SandboxProbeDefinition(
                "linker_integrity",
                EvidenceSource.BETA_HOOK_CONSISTENCY,
                ObservationAuthority.LIBC_OR_PRIVATE_LIBRARY,
                "loader_integrity",
                DetectionDomain.HOOK_OR_TAMPERING,
                setOf("critical_mismatch"),
            ),
        )

        definitions.forEach { definition ->
            val observation = SandboxIntegrityChecker.nativeObservation(
                definition = definition,
                row = SandboxProbeRow(
                    definition.checkId,
                    ProbeAvailability.AVAILABLE,
                    mapOf("critical_mismatch" to "true"),
                ),
                networkEpochId = "epoch",
                observedAtElapsedMs = 1L,
            )
            assertEquals(definition.checkId, ObservationPolarity.POSITIVE, observation.polarity)
            if (definition.checkId == "direct_syscall_consistency") {
                assertTrue(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS in observation.suppressions)
            }
        }
    }

    @Test
    fun filesystemGuardsArePreservedOnObservation() {
        val suppressions = listOf(
            BetaSuppressionRuleId.SPLIT_APK_OR_UPDATE_LAYOUT,
            BetaSuppressionRuleId.ADOPTED_OR_EMULATED_STORAGE,
        )
        val observation = SandboxIntegrityChecker.nativeObservation(
            definition = SandboxProbeDefinition(
                checkId = "fscrypt_identity",
                source = EvidenceSource.BETA_SANDBOX_IDENTITY,
                authority = ObservationAuthority.KERNEL_QUERY,
                group = "filesystem_identity",
                domain = DetectionDomain.APP_VIRTUALIZATION,
                completeFields = setOf("critical_mismatch"),
            ),
            row = SandboxProbeRow(
                "fscrypt_identity",
                ProbeAvailability.AVAILABLE,
                mapOf("critical_mismatch" to "true"),
            ),
            networkEpochId = "epoch",
            observedAtElapsedMs = 1L,
            suppressions = suppressions,
        )

        assertTrue(observation.suppressions.containsAll(suppressions))
    }

    private fun processSnapshot(
        packageUid: Int? = 10001,
        processNameExpected: Boolean? = true,
    ) = ProcessIdentitySnapshot(
        uid = 10001,
        applicationUid = 10001,
        packageUid = packageUid,
        packageVisibleForUid = true,
        processNameExpected = processNameExpected,
    )

    private fun fdDefinition() = SandboxProbeDefinition(
        checkId = "fd_identity",
        source = EvidenceSource.BETA_HOOK_CONSISTENCY,
        authority = ObservationAuthority.KERNEL_QUERY,
        group = "process_fd",
        domain = DetectionDomain.HOOK_OR_TAMPERING,
        completeFields = setOf("fstat_match", "critical_mismatch"),
    )
}
