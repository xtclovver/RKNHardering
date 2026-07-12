package com.notcvnt.rknhardering.model

import org.junit.Assert.assertEquals
import org.junit.Test

class BetaDescriptionTest {
    @Test
    fun `beta description gets exactly one prefix`() {
        assertEquals("β check", Finding("check", maturity = EvidenceMaturity.BETA).displayDescription())
        assertEquals("β check", Finding("β check", maturity = EvidenceMaturity.BETA).displayDescription())
    }

    @Test
    fun `stable description is unchanged except legacy beta marker is normalized`() {
        assertEquals("check", Finding("check").displayDescription())
        assertEquals("check", Finding("β check").displayDescription())
    }
}
