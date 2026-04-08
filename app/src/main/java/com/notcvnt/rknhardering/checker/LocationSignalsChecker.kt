package com.notcvnt.rknhardering.checker

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.Geocoder
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoTdscdma
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.Locale
import kotlin.coroutines.resume

object LocationSignalsChecker {

    internal data class LocationSnapshot(
        val networkMcc: String?,
        val networkCountryIso: String?,
        val networkOperatorName: String?,
        val simMcc: String?,
        val simCountryIso: String?,
        val isRoaming: Boolean?,
        val cellCountryCode: String?,
        val cellLookupSummary: String?,
        val cellCandidatesCount: Int,
        val wifiAccessPointCandidatesCount: Int,
        val bssid: String?,
        val cellLookupPermissionGranted: Boolean,
        val wifiPermissionGranted: Boolean,
    )

    private const val RUSSIA_MCC = "250"
    private const val PLACEHOLDER_BSSID = "02:00:00:00:00:00"
    private const val CELL_INFO_TIMEOUT_MS = 3_000L
    private const val WIFI_SCAN_TIMEOUT_MS = 3_000L
    private const val MAX_CELL_TOWERS = 6
    private const val MAX_WIFI_ACCESS_POINTS = 12

    suspend fun check(context: Context, networkRequestsEnabled: Boolean = true): CategoryResult = withContext(Dispatchers.IO) {
        evaluate(collectSnapshot(context, networkRequestsEnabled))
    }

    private suspend fun collectSnapshot(context: Context, networkRequestsEnabled: Boolean): LocationSnapshot {
        val fineLocationGranted = hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
        val nearbyWifiGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            hasPermission(context, Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            true
        }
        val cellLookupPermissionGranted = fineLocationGranted
        val wifiPermissionGranted = fineLocationGranted && nearbyWifiGranted

        var networkMcc: String? = null
        var networkCountryIso: String? = null
        var networkOperatorName: String? = null
        var simMcc: String? = null
        var simCountryIso: String? = null
        var isRoaming: Boolean? = null
        var cellCountryCode: String? = null
        var cellLookupSummary: String? = null
        var cellCandidatesCount = 0
        var wifiAccessPointCandidatesCount = 0

        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        runCatching {
            val networkOperator = tm.networkOperator
            if (!networkOperator.isNullOrEmpty() && networkOperator.length >= 3) {
                networkMcc = networkOperator.substring(0, 3)
            }
            networkCountryIso = tm.networkCountryIso?.takeIf { it.isNotEmpty() }
            networkOperatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() }

            val simOperator = tm.simOperator
            if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                simMcc = simOperator.substring(0, 3)
            }
            simCountryIso = tm.simCountryIso?.takeIf { it.isNotEmpty() }
            isRoaming = tm.isNetworkRoaming
        }

        val cellCandidates = if (cellLookupPermissionGranted) {
            collectCellCandidates(context, tm).also { cellCandidatesCount = it.size }
        } else {
            emptyList()
        }
        val wifiCandidates = if (wifiPermissionGranted) {
            collectWifiCandidates(context).also { wifiAccessPointCandidatesCount = it.size }
        } else {
            emptyList()
        }

        if ((cellLookupPermissionGranted || wifiPermissionGranted) && networkRequestsEnabled) {
            val lookup = BeaconDbClient(countryResolver = { lat, lon ->
                reverseGeocodeCountry(context, lat, lon)
            }).lookup(cellCandidates, wifiCandidates)
            cellCountryCode = lookup.countryCode
            cellLookupSummary = buildString {
                append(lookup.summary)
                if (lookup.latitude != null && lookup.longitude != null) {
                    append(" (${lookup.latitude}, ${lookup.longitude})")
                }
            }
        }

        val bssid = if (wifiPermissionGranted) {
            runCatching { getBssid(context) }.getOrNull()
        } else {
            null
        }

        return LocationSnapshot(
            networkMcc = networkMcc,
            networkCountryIso = networkCountryIso,
            networkOperatorName = networkOperatorName,
            simMcc = simMcc,
            simCountryIso = simCountryIso,
            isRoaming = isRoaming,
            cellCountryCode = cellCountryCode,
            cellLookupSummary = cellLookupSummary,
            cellCandidatesCount = cellCandidatesCount,
            wifiAccessPointCandidatesCount = wifiAccessPointCandidatesCount,
            bssid = bssid,
            cellLookupPermissionGranted = cellLookupPermissionGranted,
            wifiPermissionGranted = wifiPermissionGranted,
        )
    }

    private fun hasPermission(context: Context, permission: String): Boolean {
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

    private suspend fun collectCellCandidates(
        context: Context,
        tm: TelephonyManager,
    ): List<CellLookupCandidate> {
        val fresh = requestFreshCellInfo(context, tm)
        val fallback = runCatching { tm.allCellInfo.orEmpty() }.getOrDefault(emptyList())
        return (fresh.ifEmpty { fallback })
            .mapNotNull(::toLookupCandidate)
            .distinctBy { listOf(it.radio, it.mcc, it.mnc, it.areaCode, it.cellId) }
            .sortedWith(
                compareByDescending<CellLookupCandidate> { it.registered }
                    .thenByDescending { it.signalStrength ?: Int.MIN_VALUE },
            )
            .take(MAX_CELL_TOWERS)
    }

    @Suppress("MissingPermission")
    private suspend fun requestFreshCellInfo(
        context: Context,
        tm: TelephonyManager,
    ): List<CellInfo> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return emptyList()
        }

        return withTimeoutOrNull(CELL_INFO_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val requested = runCatching {
                    tm.requestCellInfoUpdate(
                        context.mainExecutor,
                        object : TelephonyManager.CellInfoCallback() {
                            override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                                if (continuation.isActive) {
                                    continuation.resume(cellInfo.toList())
                                }
                            }
                        },
                    )
                }.isSuccess

                if (!requested && continuation.isActive) {
                    continuation.resume(emptyList())
                }
            }
        } ?: emptyList()
    }

    private fun toLookupCandidate(info: CellInfo): CellLookupCandidate? {
        return when (info) {
            is CellInfoGsm -> {
                val identity = info.cellIdentity
                val mcc = normalizeOperatorCode(identity.mccString) ?: return null
                val mnc = normalizeOperatorCode(identity.mncString) ?: return null
                val areaCode = normalizeCellValue(identity.lac) ?: return null
                val cellId = normalizeCellValue(identity.cid) ?: return null
                CellLookupCandidate(
                    radio = "gsm",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            is CellInfoLte -> {
                val identity = info.cellIdentity
                val mcc = normalizeOperatorCode(identity.mccString) ?: return null
                val mnc = normalizeOperatorCode(identity.mncString) ?: return null
                val areaCode = normalizeCellValue(identity.tac) ?: return null
                val cellId = normalizeCellValue(identity.ci) ?: return null
                CellLookupCandidate(
                    radio = "lte",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            is CellInfoWcdma -> {
                val identity = info.cellIdentity
                val mcc = normalizeOperatorCode(identity.mccString) ?: return null
                val mnc = normalizeOperatorCode(identity.mncString) ?: return null
                val areaCode = normalizeCellValue(identity.lac) ?: return null
                val cellId = normalizeCellValue(identity.cid) ?: return null
                CellLookupCandidate(
                    radio = "wcdma",
                    mcc = mcc,
                    mnc = mnc,
                    areaCode = areaCode,
                    cellId = cellId,
                    registered = info.isRegistered,
                    signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
                )
            }

            is CellInfoTdscdma -> null
            else -> null
        }
    }

    private suspend fun collectWifiCandidates(context: Context): List<WifiLookupCandidate> {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val cachedCandidates = currentWifiCandidates(wifiManager)
        val refreshedCandidates = requestFreshWifiScan(context, wifiManager)

        return (refreshedCandidates ?: cachedCandidates)
            .distinctBy { it.macAddress }
            .sortedByDescending { it.signalStrength ?: Int.MIN_VALUE }
            .take(MAX_WIFI_ACCESS_POINTS)
    }

    @Suppress("MissingPermission", "DEPRECATION")
    private suspend fun requestFreshWifiScan(
        context: Context,
        wifiManager: WifiManager,
    ): List<WifiLookupCandidate>? {
        val appContext = context.applicationContext
        return withTimeoutOrNull(WIFI_SCAN_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(receiverContext: Context?, intent: Intent?) {
                        if (intent?.action != WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) {
                            return
                        }
                        runCatching { appContext.unregisterReceiver(this) }
                        if (continuation.isActive) {
                            continuation.resume(currentWifiCandidates(wifiManager))
                        }
                    }
                }

                val registered = runCatching {
                    ContextCompat.registerReceiver(
                        appContext,
                        receiver,
                        IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION),
                        ContextCompat.RECEIVER_NOT_EXPORTED,
                    )
                }.isSuccess

                if (!registered) {
                    if (continuation.isActive) {
                        continuation.resume(currentWifiCandidates(wifiManager))
                    }
                    return@suspendCancellableCoroutine
                }

                continuation.invokeOnCancellation {
                    runCatching { appContext.unregisterReceiver(receiver) }
                }

                val started = runCatching { wifiManager.startScan() }.getOrDefault(false)
                if (!started) {
                    runCatching { appContext.unregisterReceiver(receiver) }
                    if (continuation.isActive) {
                        continuation.resume(currentWifiCandidates(wifiManager))
                    }
                }
            }
        }
    }

    @Suppress("MissingPermission")
    private fun currentWifiCandidates(wifiManager: WifiManager): List<WifiLookupCandidate> {
        return runCatching {
            wifiManager.scanResults
                ?.mapNotNull(::toWifiLookupCandidate)
                .orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun toWifiLookupCandidate(scanResult: ScanResult): WifiLookupCandidate? {
        val macAddress = normalizeMacAddress(scanResult.BSSID) ?: return null
        val ssid = normalizeSsid(scanResult.SSID) ?: return null
        if (ssid.endsWith("_nomap", ignoreCase = true)) return null

        return WifiLookupCandidate(
            macAddress = macAddress,
            frequency = scanResult.frequency.takeIf { it > 0 },
            signalStrength = normalizeSignalStrength(scanResult.level),
        )
    }

    private fun normalizeOperatorCode(value: String?): String? {
        return value?.takeIf { it.isNotBlank() && it.all(Char::isDigit) }
    }

    private fun normalizeCellValue(value: Int): Long? {
        return value.toLong().takeIf { it in 0 until Int.MAX_VALUE.toLong() }
    }

    private fun normalizeSignalStrength(value: Int): Int? {
        return value.takeIf { it in -150..0 }
    }

    private fun normalizeMacAddress(value: String?): String? {
        val normalized = value?.trim()?.lowercase(Locale.US) ?: return null
        if (normalized == PLACEHOLDER_BSSID) return null
        if (!MAC_ADDRESS_REGEX.matches(normalized)) return null
        return normalized
    }

    private fun normalizeSsid(value: String?): String? {
        val normalized = value?.trim().orEmpty()
        return normalized.takeIf {
            it.isNotEmpty() && !it.equals("<unknown ssid>", ignoreCase = true)
        }
    }

    @Suppress("DEPRECATION")
    private fun reverseGeocodeCountry(context: Context, latitude: Double, longitude: Double): String? {
        return runCatching {
            if (!Geocoder.isPresent()) {
                null
            } else {
                Geocoder(context, Locale.US)
                    .getFromLocation(latitude, longitude, 1)
                    ?.firstOrNull()
                    ?.countryCode
                    ?.uppercase(Locale.US)
            }
        }.getOrNull()
    }

    @Suppress("DEPRECATION")
    private fun getBssid(context: Context): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork ?: return null
            val caps = cm.getNetworkCapabilities(network) ?: return null
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null
            (caps.transportInfo as? WifiInfo)?.bssid
        } else {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wm.connectionInfo?.bssid
        }
    }

    internal fun evaluate(snapshot: LocationSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        if (snapshot.networkMcc == null) {
            findings += Finding("PLMN: network MCC is unavailable")
        } else {
            val networkCountry = snapshot.networkCountryIso?.uppercase(Locale.US) ?: "N/A"
            val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC

            findings += Finding("Network operator: ${snapshot.networkOperatorName ?: "N/A"} ($networkCountry)")
            findings += Finding("Network MCC: ${snapshot.networkMcc}")
            if (networkIsRussia) {
                findings += Finding("network_mcc_ru:true")
            }

            snapshot.simMcc?.let { simMcc ->
                val simCountry = snapshot.simCountryIso?.uppercase(Locale.US) ?: "N/A"
                findings += Finding("SIM MCC: $simMcc ($simCountry)")
            }

            when (snapshot.isRoaming) {
                true -> findings += Finding("Roaming: yes")
                false -> findings += Finding("Roaming: no")
                null -> Unit
            }

            if (!networkIsRussia) {
                val confidence = if (snapshot.isRoaming == true) {
                    EvidenceConfidence.LOW
                } else {
                    EvidenceConfidence.MEDIUM
                }
                val description = "Network MCC ${snapshot.networkMcc} ($networkCountry) is not Russia"
                findings += Finding(
                    description = description,
                    needsReview = true,
                    source = EvidenceSource.LOCATION_SIGNALS,
                    confidence = confidence,
                )
                evidence += EvidenceItem(
                    source = EvidenceSource.LOCATION_SIGNALS,
                    detected = true,
                    confidence = confidence,
                    description = description,
                )
                needsReview = true
            }
        }

        if (!snapshot.cellLookupPermissionGranted) {
            findings += Finding("Cell lookup: ACCESS_FINE_LOCATION permission is not granted")
        } else {
            findings += Finding("Cell lookup candidates: ${snapshot.cellCandidatesCount}")
            if (snapshot.cellCandidatesCount == 0) {
                findings += Finding("Cell lookup: base station identifiers are unavailable")
            }
        }

        if (!snapshot.wifiPermissionGranted) {
            findings += Finding("Wi-Fi scan: permissions are not granted")
        } else {
            findings += Finding("Wi-Fi scan candidates: ${snapshot.wifiAccessPointCandidatesCount}")
            if (snapshot.wifiAccessPointCandidatesCount == 0) {
                findings += Finding("Wi-Fi scan: access points are unavailable")
            }
        }

        snapshot.cellCountryCode?.let { countryCode ->
            findings += Finding("Cell lookup country: $countryCode")
            if (countryCode == "RU") {
                findings += Finding("cell_country_ru:true")
                findings += Finding("location_country_ru:true")
            }
        }
        snapshot.cellLookupSummary?.let { findings += Finding(it) }

        if (!snapshot.wifiPermissionGranted) {
            findings += Finding("BSSID: permission is not granted")
        } else if (snapshot.bssid == null || snapshot.bssid == PLACEHOLDER_BSSID) {
            findings += Finding("BSSID: unavailable")
        } else {
            findings += Finding("BSSID: ${snapshot.bssid}")
        }

        return CategoryResult(
            name = "Location signals",
            detected = false,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private val MAC_ADDRESS_REGEX = Regex("^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
}
