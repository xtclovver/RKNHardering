package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.probe.IfconfigClient
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyScanner
import com.notcvnt.rknhardering.probe.ScanMode
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayApiScanner
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

object BypassChecker {

    data class Progress(
        val phase: String,
        val detail: String,
    )

    suspend fun check(
        onProgress: (suspend (Progress) -> Unit)? = null,
    ): BypassResult = coroutineScope {
        val findings = mutableListOf<Finding>()

        val scanner = ProxyScanner()
        val xrayScanner = XrayApiScanner()

        // Run proxy scan and xray scan in parallel
        val proxyDeferred = async {
            onProgress?.invoke(Progress("Сканирование портов", "Поиск открытых прокси на localhost..."))
            scanner.findOpenProxyEndpoint(
                mode = ScanMode.AUTO,
                manualPort = null,
                onProgress = { progress ->
                    val phaseText = when (progress.phase) {
                        com.notcvnt.rknhardering.probe.ScanPhase.POPULAR_PORTS -> "Популярные порты"
                        com.notcvnt.rknhardering.probe.ScanPhase.FULL_RANGE -> "Полное сканирование"
                    }
                    val percent = if (progress.total > 0) (progress.scanned * 100 / progress.total) else 0
                    onProgress?.invoke(
                        Progress(phaseText, "Порт ${progress.currentPort} ($percent%)")
                    )
                },
            )
        }

        val xrayDeferred = async {
            onProgress?.invoke(Progress("Xray API", "Поиск gRPC API на localhost..."))
            xrayScanner.findXrayApi { progress ->
                val percent = if (progress.total > 0) (progress.scanned * 100 / progress.total) else 0
                onProgress?.invoke(
                    Progress("Xray API", "${progress.host}:${progress.currentPort} ($percent%)")
                )
            }
        }

        val proxyEndpoint: ProxyEndpoint? = proxyDeferred.await()
        val xrayApiScanResult: XrayApiScanResult? = xrayDeferred.await()

        // Report proxy scan result
        if (proxyEndpoint != null) {
            findings.add(
                Finding(
                    "Открытый ${proxyEndpoint.type.name} прокси: ${formatHostPort(proxyEndpoint.host, proxyEndpoint.port)}",
                    true
                )
            )
        } else {
            findings.add(Finding("Открытые прокси на localhost: не обнаружены", false))
        }

        // Report xray API result
        if (xrayApiScanResult != null) {
            val ep = xrayApiScanResult.endpoint
            findings.add(Finding("Xray gRPC API: ${formatHostPort(ep.host, ep.port)}", true))
            for (outbound in xrayApiScanResult.outbounds.take(10)) {
                val detail = buildString {
                    append("  ${outbound.tag}")
                    outbound.protocolName?.let { append(" [$it]") }
                    if (outbound.address != null && outbound.port != null) {
                        append(" → ${outbound.address}:${outbound.port}")
                    }
                    outbound.sni?.let { append(", sni=$it") }
                }
                findings.add(Finding(detail, true))
            }
            if (xrayApiScanResult.outbounds.size > 10) {
                findings.add(Finding("  ...ещё ${xrayApiScanResult.outbounds.size - 10} аутбаундов", true))
            }
        } else {
            findings.add(Finding("Xray gRPC API: не обнаружен", false))
        }

        // If proxy found, fetch IPs to prove bypass
        var directIp: String? = null
        var proxyIp: String? = null

        if (proxyEndpoint != null) {
            onProgress?.invoke(Progress("Проверка IP", "Получение прямого IP и IP через прокси..."))

            val directDeferred = async { IfconfigClient.fetchDirectIp() }
            val proxyIpDeferred = async { IfconfigClient.fetchIpViaProxy(proxyEndpoint) }

            directIp = directDeferred.await().getOrNull()
            proxyIp = proxyIpDeferred.await().getOrNull()

            if (directIp != null) {
                findings.add(Finding("Прямой IP: $directIp", false))
            } else {
                findings.add(Finding("Прямой IP: не удалось получить", false))
            }

            if (proxyIp != null) {
                findings.add(Finding("IP через прокси: $proxyIp", false))
            } else {
                findings.add(Finding("IP через прокси: не удалось получить", false))
            }

            if (directIp != null && proxyIp != null) {
                if (directIp != proxyIp) {
                    findings.add(
                        Finding("Per-app split bypass: подтвержден (IP отличаются)", true)
                    )
                } else {
                    findings.add(
                        Finding("Per-app split отключен: IP совпадают", false)
                    )
                }
            }
        }

        val detected = proxyEndpoint != null || xrayApiScanResult != null

        BypassResult(
            proxyEndpoint = proxyEndpoint,
            directIp = directIp,
            proxyIp = proxyIp,
            xrayApiScanResult = xrayApiScanResult,
            findings = findings,
            detected = detected,
        )
    }

    private fun formatHostPort(host: String, port: Int): String {
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }
}
