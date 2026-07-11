package com.notcvnt.rknhardering.ui.main.render

import android.graphics.Typeface
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ui.main.SimpleCardModel
import com.notcvnt.rknhardering.ui.main.SimpleResultCause
import com.notcvnt.rknhardering.ui.main.SimpleResultStatus
import com.notcvnt.rknhardering.ui.main.SimpleSignalArea
import java.util.IdentityHashMap

internal class SimpleResultRenderer(
    private val env: MainRenderEnvironment,
) {
    private data class RenderedCard(
        val root: View,
        val originalVisibility: IdentityHashMap<View, Int>,
    )

    private val renderedCards = mutableMapOf<ViewGroup, RenderedCard>()

    fun render(body: ViewGroup, whatWasChecked: String, model: SimpleCardModel) {
        clear(body)
        val originalVisibility = IdentityHashMap<View, Int>()
        repeat(body.childCount) { index ->
            body.getChildAt(index).let { child ->
                originalVisibility[child] = child.visibility
                child.visibility = View.GONE
            }
        }

        val root = LinearLayout(env.context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 10.dp, 0, 0)
            addView(label(R.string.simple_result_checked_label))
            addView(value(whatWasChecked))
            addView(label(R.string.simple_result_outcome_label, topMargin = 10.dp))
            addView(value(statusText(model.status), Typeface.BOLD))
            addView(label(R.string.simple_result_explanation_label, topMargin = 10.dp))
            addView(value(explanationText(model)))
            if (model.extraInformation) {
                addView(value(env.context.getString(R.string.simple_result_extra_information)).apply {
                    setPadding(0, 10.dp, 0, 0)
                })
            }
        }
        body.addView(root)
        renderedCards[body] = RenderedCard(root, originalVisibility)
    }

    fun clear() {
        renderedCards.keys.toList().forEach(::clear)
    }

    private fun clear(body: ViewGroup) {
        val rendered = renderedCards.remove(body) ?: return
        body.removeView(rendered.root)
        rendered.originalVisibility.forEach { (view, visibility) ->
            if (view.parent === body) view.visibility = visibility
        }
    }

    private fun label(textRes: Int, topMargin: Int = 0): TextView = TextView(env.context).apply {
        setText(textRes)
        setTextColor(env.onSurfaceVariantColor())
        textSize = 12f
        typeface = Typeface.DEFAULT_BOLD
        if (topMargin > 0) setPadding(0, topMargin, 0, 0)
    }

    private fun value(value: String, style: Int = Typeface.NORMAL): TextView = TextView(env.context).apply {
        text = value
        setTextColor(env.onSurfaceColor())
        textSize = 14f
        typeface = Typeface.create(Typeface.DEFAULT, style)
        setLineSpacing(0f, 1.08f)
    }

    private fun statusText(status: SimpleResultStatus): String = env.context.getString(
        when (status) {
            SimpleResultStatus.RUNNING -> R.string.simple_result_running
            SimpleResultStatus.CLEAN -> R.string.simple_result_clean
            SimpleResultStatus.REVIEW -> R.string.simple_result_review
            SimpleResultStatus.DETECTED -> R.string.simple_result_detected
            SimpleResultStatus.ERROR -> R.string.simple_result_error
            SimpleResultStatus.DISABLED -> R.string.simple_result_disabled
        },
    )

    private fun explanationText(model: SimpleCardModel): String {
        if (model.status == SimpleResultStatus.RUNNING) {
            return env.context.getString(R.string.simple_result_explanation_running)
        }
        if (model.status == SimpleResultStatus.CLEAN) {
            return env.context.getString(R.string.simple_result_explanation_clean)
        }
        if (model.causes.isNotEmpty()) {
            val explanations = model.causes.map { env.context.getString(causeText(it)) }
            return if (explanations.size == 1) {
                explanations.single()
            } else {
                explanations.joinToString(separator = "\n") { "\u2022 $it" }
            }
        }
        if (model.status == SimpleResultStatus.ERROR) {
            return env.context.getString(R.string.simple_result_explanation_error)
        }
        if (model.status == SimpleResultStatus.DISABLED) {
            return env.context.getString(R.string.simple_result_disabled)
        }
        return env.context.getString(
            when (model.area) {
                SimpleSignalArea.PUBLIC_ADDRESS -> R.string.simple_result_area_public_address
                SimpleSignalArea.DEVICE_NETWORK -> R.string.simple_result_area_device_network
                SimpleSignalArea.LOCAL_APP -> R.string.simple_result_area_local_app
                SimpleSignalArea.LOCAL_PROXY -> R.string.simple_result_area_local_proxy
                SimpleSignalArea.NETWORK_ROUTE -> R.string.simple_result_area_network_route
                SimpleSignalArea.CALL_ROUTE -> R.string.simple_result_area_call_route
                SimpleSignalArea.LOCATION -> R.string.simple_result_area_location
                SimpleSignalArea.REMOTE_SITE -> R.string.simple_result_area_remote_site
                SimpleSignalArea.DEVICE_ENVIRONMENT -> R.string.simple_result_area_device_environment
                SimpleSignalArea.MULTIPLE -> R.string.simple_result_area_multiple
                SimpleSignalArea.NONE -> R.string.simple_result_explanation_review
            },
        )
    }

    private fun causeText(cause: SimpleResultCause): Int = when (cause) {
        SimpleResultCause.IP_RU_SERVICES_DISAGREE -> R.string.simple_cause_ip_ru_services_disagree
        SimpleResultCause.IP_NON_RU_SERVICES_DISAGREE -> R.string.simple_cause_ip_non_ru_services_disagree
        SimpleResultCause.IP_GROUPS_DISAGREE -> R.string.simple_cause_ip_groups_disagree
        SimpleResultCause.IP_FAMILIES_DIFFER -> R.string.simple_cause_ip_families_differ
        SimpleResultCause.IP_PARTIAL_RESPONSE -> R.string.simple_cause_ip_partial_response
        SimpleResultCause.IP_UNAVAILABLE -> R.string.simple_cause_ip_unavailable
        SimpleResultCause.CDN_RESPONSES_DIFFER -> R.string.simple_cause_cdn_responses_differ
        SimpleResultCause.CDN_PARTIAL_RESPONSE -> R.string.simple_cause_cdn_partial_response
        SimpleResultCause.PUBLIC_IP_LOCATION -> R.string.simple_cause_public_ip_location
        SimpleResultCause.VPN_NETWORK_STATE -> R.string.simple_cause_vpn_network_state
        SimpleResultCause.ACTIVE_VPN_APP -> R.string.simple_cause_active_vpn_app
        SimpleResultCause.SYSTEM_PROXY -> R.string.simple_cause_system_proxy
        SimpleResultCause.LOCAL_PROXY -> R.string.simple_cause_local_proxy
        SimpleResultCause.VPN_INTERFACE -> R.string.simple_cause_vpn_interface
        SimpleResultCause.VPN_ROUTE -> R.string.simple_cause_vpn_route
        SimpleResultCause.PUBLIC_HOST_ROUTE -> R.string.simple_cause_public_host_route
        SimpleResultCause.DNS_REDIRECTION -> R.string.simple_cause_dns_redirection
        SimpleResultCause.TRAFFIC_BYPASS -> R.string.simple_cause_traffic_bypass
        SimpleResultCause.PROXY_AUTH_REQUIRED -> R.string.simple_cause_proxy_auth_required
        SimpleResultCause.LOCATION_CONFLICT -> R.string.simple_cause_location_conflict
        SimpleResultCause.ICMP_RESPONSE_MISMATCH -> R.string.simple_cause_icmp_response_mismatch
        SimpleResultCause.RTT_ROUTE_PATTERN -> R.string.simple_cause_rtt_route_pattern
        SimpleResultCause.TELEGRAM_CALL_PATH -> R.string.simple_cause_telegram_call_path
        SimpleResultCause.WHATSAPP_CALL_PATH -> R.string.simple_cause_whatsapp_call_path
        SimpleResultCause.CALL_CHECK_UNAVAILABLE -> R.string.simple_cause_call_check_unavailable
        SimpleResultCause.DOMAIN_DNS_MISMATCH -> R.string.simple_cause_domain_dns_mismatch
        SimpleResultCause.DOMAIN_TCP_MISMATCH -> R.string.simple_cause_domain_tcp_mismatch
        SimpleResultCause.DOMAIN_TLS_MISMATCH -> R.string.simple_cause_domain_tls_mismatch
        SimpleResultCause.PUBLIC_DATA_UNAVAILABLE -> R.string.simple_cause_public_data_unavailable
        SimpleResultCause.NETWORK_DATA_UNAVAILABLE -> R.string.simple_cause_network_data_unavailable
        SimpleResultCause.REMOTE_DATA_UNAVAILABLE -> R.string.simple_cause_remote_data_unavailable
        SimpleResultCause.DEVICE_DATA_UNAVAILABLE -> R.string.simple_cause_device_data_unavailable
        SimpleResultCause.DEVICE_ENVIRONMENT -> R.string.simple_cause_device_environment
    }

    private val Int.dp: Int
        get() = (this * env.context.resources.displayMetrics.density).toInt()
}
