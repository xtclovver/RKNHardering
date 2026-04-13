package com.notcvnt.rknhardering.probe

import android.content.Context
import com.notcvnt.rknhardering.model.CallTransportService
import org.json.JSONArray

object CallTransportTargetCatalog {

    data class CallTransportTarget(
        val service: CallTransportService,
        val host: String,
        val port: Int,
        val experimental: Boolean,
        val enabled: Boolean,
    )

    data class Catalog(
        val telegramTargets: List<CallTransportTarget>,
        val whatsappTargets: List<CallTransportTarget>,
    )

    fun load(context: Context, includeExperimental: Boolean): Catalog {
        val telegramTargets = readTargets(
            context = context,
            assetName = "call_transport_targets_telegram.json",
            service = CallTransportService.TELEGRAM,
            experimental = false,
        )
        val whatsappTargets = if (includeExperimental) {
            readTargets(
                context = context,
                assetName = "call_transport_targets_whatsapp_experimental.json",
                service = CallTransportService.WHATSAPP,
                experimental = true,
            )
        } else {
            emptyList()
        }

        return Catalog(
            telegramTargets = telegramTargets.filter { it.enabled },
            whatsappTargets = whatsappTargets.filter { it.enabled },
        )
    }

    private fun readTargets(
        context: Context,
        assetName: String,
        service: CallTransportService,
        experimental: Boolean,
    ): List<CallTransportTarget> {
        val raw = context.assets.open(assetName).bufferedReader(Charsets.UTF_8).use { it.readText() }
        val json = JSONArray(raw)
        return buildList(json.length()) {
            for (index in 0 until json.length()) {
                val item = json.getJSONObject(index)
                add(
                    CallTransportTarget(
                        service = service,
                        host = item.getString("host").trim(),
                        port = item.optInt("port", 3478),
                        experimental = item.optBoolean("experimental", experimental),
                        enabled = item.optBoolean("enabled", true),
                    ),
                )
            }
        }
    }
}
