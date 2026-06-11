package com.notcvnt.rknhardering.ui.main.render

import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.google.android.material.color.MaterialColors
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.StatusSemantic
import com.notcvnt.rknhardering.model.DomainReachabilityResult
import com.notcvnt.rknhardering.model.DomainReachabilityStepStatus

/**
 * Renders the domain-reachability card: per-domain DNS/TCP/TLS step rows
 * with expectation mismatches and error details. Moved verbatim from
 * MainActivity (which built these rows with the plain activity context, not
 * the themed one — preserved via [MainRenderEnvironment.context]).
 */
internal class DomainReachabilityRenderer(
    env: MainRenderEnvironment,
) : SectionRenderer(env) {

    fun render(result: DomainReachabilityResult, findingsContainer: LinearLayout) {
        findingsContainer.removeAllViews()
        if (result.isEmpty) return

        result.responses.forEach { response ->
            val row = LinearLayout(env.context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, 8.dp, 0, 8.dp)
            }

            // Header with match/mismatch indicator
            val matchIcon = if (response.matchesExpectation) "✅" else "⚠️"
            val header = TextView(env.context).apply {
                text = "$matchIcon ${response.label}"
                setTextColor(resolveTextColorPrimary())
                textSize = 13f
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
            row.addView(header)

            val stepsLine = TextView(env.context).apply {
                val dns = stepIcon(response.dnsStatus)
                val tcp = stepIcon(response.tcpStatus)
                val tls = stepIcon(response.tlsStatus)
                text = buildString {
                    append("DNS $dns")
                    append("  →  ")
                    append("TCP $tcp")
                    append("  →  ")
                    append("TLS $tls")
                }
                textSize = 12f
                setTextColor(resolveTextColorSecondary())
            }
            row.addView(stepsLine)

            // Show expected line when not all expected=true (custom expectations)
            val hasCustomExpectations = !response.expectedDnsAvailable || !response.expectedTcpAvailable || !response.expectedTlsAvailable
            if (hasCustomExpectations) {
                val expectedLine = TextView(env.context).apply {
                    val dn = if (response.expectedDnsAvailable) "✅" else "❌"
                    val tc = if (response.expectedTcpAvailable) "✅" else "❌"
                    val tl = if (response.expectedTlsAvailable) "✅" else "❌"
                    text = getString(R.string.domain_reachability_expected_prefix) + " DNS $dn  TCP $tc  TLS $tl"
                    textSize = 11f
                    setTextColor(resolveTextColorSecondary())
                    setPadding(0, 2.dp, 0, 0)
                }
                row.addView(expectedLine)
            }

            // Show error detail if any step failed
            val errorDetail = when {
                response.dnsStatus == DomainReachabilityStepStatus.FAILED ->
                    response.dnsError?.let { "DNS: $it" }
                response.tcpStatus == DomainReachabilityStepStatus.FAILED ->
                    response.tcpError?.let { "TCP: $it" }
                response.tlsStatus == DomainReachabilityStepStatus.FAILED ->
                    response.tlsError?.let { "TLS: $it" }
                else -> null
            }
            if (errorDetail != null) {
                val errorView = TextView(env.context).apply {
                    text = errorDetail
                    textSize = 11f
                    setTextColor(statusColor(StatusSemantic.DETECTED))
                    setPadding(0, 2.dp, 0, 0)
                }
                row.addView(errorView)
            }

            findingsContainer.addView(row)
        }
        findingsContainer.visibility = View.VISIBLE
    }

    private fun stepIcon(status: DomainReachabilityStepStatus): String = when (status) {
        DomainReachabilityStepStatus.OK -> "✅"
        DomainReachabilityStepStatus.FAILED -> "❌"
        DomainReachabilityStepStatus.SKIPPED -> "⏭"
    }

    private fun resolveTextColorPrimary(): Int {
        return MaterialColors.getColor(env.context, android.R.attr.textColorPrimary, 0xFFFFFFFF.toInt())
    }

    private fun resolveTextColorSecondary(): Int {
        return MaterialColors.getColor(env.context, android.R.attr.textColorSecondary, 0x99FFFFFF.toInt())
    }
}
