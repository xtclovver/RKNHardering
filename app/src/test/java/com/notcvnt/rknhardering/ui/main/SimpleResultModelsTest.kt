package com.notcvnt.rknhardering.ui.main

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.DomainReachabilityResponse
import com.notcvnt.rknhardering.model.DomainReachabilityResult
import com.notcvnt.rknhardering.model.DomainReachabilityStepStatus
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import org.junit.Assert.assertEquals
import org.junit.Test

class SimpleResultModelsTest {
    @Test
    fun `category covers clean review detected and error`() {
        assertEquals(SimpleResultStatus.CLEAN, SimpleResultModels.category(category()).status)
        assertEquals(
            SimpleResultStatus.REVIEW,
            SimpleResultModels.category(category(needsReview = true)).status,
        )
        assertEquals(
            SimpleResultStatus.DETECTED,
            SimpleResultModels.category(category(detected = true)).status,
        )
        assertEquals(
            SimpleResultStatus.ERROR,
            SimpleResultModels.category(category(findings = listOf(Finding("failure", isError = true)))).status,
        )
    }

    @Test
    fun `specialized models map structured states without parsing text`() {
        val emptyGroup = IpCheckerGroupResult(
            title = "group",
            detected = false,
            statusLabel = "",
            summary = "",
            responses = emptyList(),
        )
        assertEquals(
            SimpleResultStatus.REVIEW,
            SimpleResultModels.ipComparison(
                IpComparisonResult(
                    detected = false,
                    needsReview = true,
                    summary = "arbitrary technical text",
                    ruGroup = emptyGroup,
                    nonRuGroup = emptyGroup,
                ),
            ).status,
        )
        assertEquals(
            SimpleResultStatus.DETECTED,
            SimpleResultModels.cdn(CdnPullingResult(detected = true, summary = "raw enum UNKNOWN")).status,
        )
        assertEquals(
            SimpleResultStatus.REVIEW,
            SimpleResultModels.bypass(bypass(needsReview = true)).status,
        )
        assertEquals(
            SimpleResultStatus.REVIEW,
            SimpleResultModels.callTransport(
                leaks = listOf(
                    CallTransportLeakResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        networkPath = CallTransportNetworkPath.ACTIVE,
                        status = CallTransportStatus.NEEDS_REVIEW,
                        summary = "ignored",
                    ),
                ),
                stunGroups = emptyList(),
            ).status,
        )
    }

    @Test
    fun `ip comparison reports the exact disagreeing group from structured state`() {
        val ruGroup = IpCheckerGroupResult(
            title = "ru",
            detected = true,
            statusLabel = "ignored",
            summary = "raw summary must not be parsed",
            responses = emptyList(),
        )
        val otherGroup = IpCheckerGroupResult(
            title = "other",
            detected = false,
            statusLabel = "ignored",
            summary = "ignored",
            canonicalIp = "203.0.113.1",
            responses = emptyList(),
        )

        val model = SimpleResultModels.ipComparison(
            IpComparisonResult(
                detected = false,
                needsReview = true,
                summary = "different wording",
                ruGroup = ruGroup,
                nonRuGroup = otherGroup,
            ),
        )

        assertEquals(listOf(SimpleResultCause.IP_RU_SERVICES_DISAGREE), model.causes)
    }

    @Test
    fun `category preserves distinct structured causes in deterministic order`() {
        val result = CategoryResult(
            name = "direct",
            detected = true,
            findings = listOf(
                Finding(
                    description = "secret path and raw error must be ignored",
                    detected = true,
                    source = EvidenceSource.ROUTING,
                ),
                Finding(
                    description = "another technical sentence",
                    detected = true,
                    source = EvidenceSource.SYSTEM_PROXY,
                ),
                Finding(
                    description = "duplicate",
                    detected = true,
                    source = EvidenceSource.ROUTING,
                ),
            ),
        )

        assertEquals(
            listOf(SimpleResultCause.SYSTEM_PROXY, SimpleResultCause.VPN_ROUTE),
            SimpleResultModels.category(result).causes,
        )
    }

    @Test
    fun `error cause describes unavailable data without claiming a detected signal`() {
        val result = category(
            findings = listOf(
                Finding(
                    description = "raw provider error must not be parsed",
                    isError = true,
                    source = EvidenceSource.GEO_IP,
                ),
            ),
        )

        assertEquals(
            listOf(SimpleResultCause.PUBLIC_DATA_UNAVAILABLE),
            SimpleResultModels.category(result).causes,
        )
    }

    @Test
    fun `domain reachability distinguishes empty clean and mismatch`() {
        assertEquals(
            SimpleResultStatus.ERROR,
            SimpleResultModels.domainReachability(DomainReachabilityResult.empty()).status,
        )
        assertEquals(
            SimpleResultStatus.CLEAN,
            SimpleResultModels.domainReachability(DomainReachabilityResult(listOf(domain(matches = true)))).status,
        )
        val mismatch = SimpleResultModels.domainReachability(
            DomainReachabilityResult(listOf(domain(matches = false))),
        )
        assertEquals(SimpleResultStatus.DETECTED, mismatch.status)
        assertEquals(listOf(SimpleResultCause.DOMAIN_TCP_MISMATCH), mismatch.causes)
    }

    @Test
    fun `disabled remains an explicit presentation state`() {
        assertEquals(SimpleResultStatus.DISABLED, SimpleCardModel(SimpleResultStatus.DISABLED).status)
    }

    @Test
    fun `installed app signal stays clean but is marked as additional information`() {
        val result = CategoryResult(
            name = "direct",
            detected = false,
            findings = emptyList(),
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.INSTALLED_APP,
                    detected = false,
                    confidence = EvidenceConfidence.LOW,
                    description = "diagnostic only",
                ),
            ),
        )

        val model = SimpleResultModels.category(result)
        assertEquals(SimpleResultStatus.CLEAN, model.status)
        assertEquals(true, model.extraInformation)
    }

    private fun category(
        detected: Boolean = false,
        needsReview: Boolean = false,
        findings: List<Finding> = emptyList(),
    ) = CategoryResult(
        name = "test",
        detected = detected,
        needsReview = needsReview,
        findings = findings,
    )

    private fun bypass(needsReview: Boolean) = BypassResult(
        proxyEndpoint = null,
        directIp = null,
        proxyIp = null,
        xrayApiScanResult = null,
        findings = emptyList(),
        detected = false,
        needsReview = needsReview,
    )

    private fun domain(matches: Boolean): DomainReachabilityResponse = DomainReachabilityResponse(
        domain = "example.test",
        label = "Example",
        dnsStatus = DomainReachabilityStepStatus.OK,
        tcpStatus = if (matches) DomainReachabilityStepStatus.OK else DomainReachabilityStepStatus.FAILED,
        tlsStatus = DomainReachabilityStepStatus.OK,
    )
}
