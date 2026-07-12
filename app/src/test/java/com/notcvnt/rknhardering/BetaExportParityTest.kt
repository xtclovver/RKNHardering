package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.export.CheckResultJsonExportFormatter
import com.notcvnt.rknhardering.export.CheckResultMarkdownExportFormatter
import com.notcvnt.rknhardering.export.createCompletedExportSnapshot
import com.notcvnt.rknhardering.model.BetaCheckResult
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceMaturity
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ExecutionContextFacts
import com.notcvnt.rknhardering.model.ExecutionContextKind
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.ProbeAvailability
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BetaExportParityTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `beta metadata and exact prefix reach JSON Markdown and diagnostics`() {
        val result = exportRichCheckResult().copy(betaChecks = betaResult())
        val snapshot = createCompletedExportSnapshot(result, privacyMode = false, finishedAtMillis = 0L)
        val json = CheckResultJsonExportFormatter.format(context, snapshot)
        val markdown = CheckResultMarkdownExportFormatter.format(context, snapshot)
        val debug = DebugDiagnosticsFormatter.format(result, CheckSettings(), false)

        val betaJson = JSONObject(json).getJSONObject("results").getJSONObject("betaChecks")
        val finding = betaJson.getJSONArray("findings").getJSONObject(0)
        val evidence = betaJson.getJSONArray("evidence").getJSONObject(0)
        assertEquals("β signal", finding.getString("description"))
        assertEquals("BETA", finding.getString("maturity"))
        assertEquals("beta.test", finding.getString("checkId"))
        assertEquals("AVAILABLE", finding.getString("availability"))
        assertEquals("HIGH", finding.getString("rawConfidence"))
        assertEquals("VCN_CONTEXT", finding.getJSONArray("suppressionRuleIds").getString(0))
        assertEquals("kernel_route", evidence.getString("independenceGroup"))
        assertEquals("NETWORK_PATH_DIVERGENCE", evidence.getString("detectionDomain"))
        assertTrue(markdown.contains("suppressions=VCN_CONTEXT"))
        assertTrue(debug.contains("suppressions=VCN_CONTEXT"))
        val execution = betaJson.getJSONObject("executionContext")
        assertEquals("MAIN_USER", execution.getString("kind"))
        assertEquals(true, execution.getBoolean("packageUidConsistent"))
        assertTrue(markdown.contains("### Beta execution context"))
        assertTrue(markdown.contains("β signal"))
        assertTrue(debug.contains("β signal"))
        val betaSection = markdown.substringAfter("## β Beta checks").substringBefore("## ICMP")
        assertTrue(Regex("β signal").findAll(betaSection).count() >= 2)
        assertTrue(!betaSection.contains("β β"))
    }

    private fun betaResult(): BetaCheckResult {
        val finding = Finding(
            description = "β signal",
            needsReview = true,
            source = EvidenceSource.BETA_ROUTE_LOOKUP,
            confidence = EvidenceConfidence.MEDIUM,
            maturity = EvidenceMaturity.BETA,
            checkId = "beta.test",
            availability = ProbeAvailability.AVAILABLE,
            rawConfidence = EvidenceConfidence.HIGH,
            suppressionRuleIds = listOf(BetaSuppressionRuleId.VCN_CONTEXT),
        )
        val evidence = EvidenceItem(
            source = EvidenceSource.BETA_ROUTE_LOOKUP,
            detected = true,
            confidence = EvidenceConfidence.MEDIUM,
            description = "signal",
            maturity = EvidenceMaturity.BETA,
            checkId = "beta.test",
            independenceGroup = "kernel_route",
            detectionDomain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
        )
        return BetaCheckResult(
            category = CategoryResult(
                name = "β Beta checks",
                detected = false,
                needsReview = true,
                findings = listOf(finding),
                evidence = listOf(evidence),
                maturity = EvidenceMaturity.BETA,
            ),
            availabilitySummary = mapOf(ProbeAvailability.AVAILABLE to 1),
            executionContext = ExecutionContextFacts(
                uid = 10_123,
                appId = 10_123,
                uidDerivedUserId = 0,
                packageUidConsistent = true,
                mountNamespaceId = "mnt:[123]",
                selinuxContext = "u:r:untrusted_app:s0:c1,c2",
                kind = ExecutionContextKind.MAIN_USER,
                confidence = EvidenceConfidence.LOW,
            ),
        )
    }

    @Test
    fun `privacy export omits raw process identity`() {
        val result = exportRichCheckResult().copy(betaChecks = betaResult())
        val snapshot = createCompletedExportSnapshot(result, privacyMode = true, finishedAtMillis = 0L)
        val json = JSONObject(CheckResultJsonExportFormatter.format(context, snapshot))
        val markdown = CheckResultMarkdownExportFormatter.format(context, snapshot)
        val execution = json.getJSONObject("results").getJSONObject("betaChecks").getJSONObject("executionContext")

        assertTrue(execution.isNull("uid"))
        assertTrue(execution.isNull("mountNamespaceId"))
        assertTrue(execution.isNull("selinuxContext"))
        assertTrue(!markdown.contains("mnt:[123]"))
        assertTrue(!markdown.contains("u:r:untrusted_app"))
    }
}
