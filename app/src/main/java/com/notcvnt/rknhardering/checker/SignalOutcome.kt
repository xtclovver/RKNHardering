package com.notcvnt.rknhardering.checker

internal data class SignalOutcome(
    val detected: Boolean = false,
    val needsReview: Boolean = false,
)
