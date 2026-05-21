package com.notcvnt.rknhardering.checker

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.Geocoder
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoWcdma
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import androidx.annotation.DoNotInline
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.customcheck.LocationSignalsConfig
import com.notcvnt.rknhardering.model.LocationSignalsFacts
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import java.util.Locale

object LocationSignalsChecker {

    data class SimCardInfo(
        val slotIndex: Int,
        val subscriptionId: Int,
        val simMcc: String?,
        val simCountryIso: String?,
        val operatorName: String?,
        val isRoaming: Boolean?,
        val simMnc: String? = null,
        val isActiveDataSubscription: Boolean = false,
        val isDefaultDataSubscription: Boolean = false,
    )

    private data class DataSubscriptionIds(
        val active: Int?,
        val default: Int?,
    )

    private data class CellCollectionResult(
        val candidates: List<CellLookupCandidate> = emptyList(),
        val rawInfoCount: Int = 0,
        val rawInfoTypes: List<String> = emptyList(),
        val candidateRadios: List<String> = emptyList(),
    )

    private data class WifiCollectionResult(
        val candidates: List<WifiLookupCandidate> = emptyList(),
        val cachedScanCandidatesCount: Int = 0,
        val freshScanCandidatesCount: Int? = null,
        val connectedCandidateAvailable: Boolean = false,
    )

    private data class BssidCollectionResult(
        val bssid: String?,
        val source: String?,
        val unavailableReason: String?,
    )

    internal data class LocationSnapshot(
        val networkMcc: String?,
        val networkCountryIso: String?,
        val networkOperatorName: String?,
        val simCards: List<SimCardInfo>,
        val networkMnc: String? = null,
        val cellCountryCode: String?,
        val cellLookupSummary: String?,
        val cellCandidatesCount: Int,
        val wifiAccessPointCandidatesCount: Int,
        val bssid: String?,
        val cellLookupPermissionGranted: Boolean,
        val wifiPermissionGranted: Boolean,
        val locationServicesEnabled: Boolean = true,
        val telephonyRadioAccessAvailable: Boolean = true,
        val wifiFeatureAvailable: Boolean = true,
        val nearbyWifiPermissionGranted: Boolean = true,
        val networkRequestsEnabled: Boolean = true,
        val cellRawInfoCount: Int = 0,
        val cellRawInfoTypes: List<String> = emptyList(),
        val cellCandidateRadios: List<String> = emptyList(),
        val beaconDbCellCandidatesUsedCount: Int = 0,
        val beaconDbUnsupportedCellRadios: List<String> = emptyList(),
        val beaconDbWifiCandidatesUsedCount: Int = 0,
        val wifiCachedScanCandidatesCount: Int = 0,
        val wifiFreshScanCandidatesCount: Int? = null,
        val wifiConnectedCandidateAvailable: Boolean = false,
        val bssidSource: String? = null,
        val bssidUnavailableReason: String? = null,
    )

    private const val RUSSIA_MCC = "250"
    private const val PLACEHOLDER_BSSID = "02:00:00:00:00:00"
    private const val CELL_INFO_TIMEOUT_MS = 3_000L
    private const val WIFI_SCAN_TIMEOUT_MS = 3_000L
    private const val MAX_CELL_TOWERS = 6
    private const val MAX_WIFI_ACCESS_POINTS = 12
    private const val MAX_NR_CELL_ID = 68_719_476_735L

    suspend fun check(
        context: Context,
        networkRequestsEnabled: Boolean = true,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        config: LocationSignalsConfig = LocationSignalsConfig(),
    ): CategoryResult = withContext(Dispatchers.IO) {
        if (!config.enabled) {
            return@withContext CategoryResult(name = "Location", detected = false, findings = emptyList())
        }
        evaluate(collectSnapshot(context, networkRequestsEnabled, resolverConfig, config))
    }

    private suspend fun collectSnapshot(
        context: Context,
        networkRequestsEnabled: Boolean,
        resolverConfig: DnsResolverConfig,
        config: LocationSignalsConfig = LocationSignalsConfig(),
    ): LocationSnapshot {
        val fineLocationGranted = hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
        val nearbyWifiGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            hasPermission(context, Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            true
        }
        val cellLookupPermissionGranted = fineLocationGranted
        val wifiPermissionGranted = fineLocationGranted && nearbyWifiGranted
        val locationServicesEnabled = isLocationEnabled(context)
        val telephonyRadioAccessAvailable = hasTelephonyRadioAccess(context)
        val wifiFeatureAvailable = context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI)

        var networkMcc: String? = null
        var networkMnc: String? = null
        var networkCountryIso: String? = null
        var networkOperatorName: String? = null
        var cellCountryCode: String? = null
        var cellLookupSummary: String? = null
        var cellCandidatesCount = 0
        var wifiAccessPointCandidatesCount = 0

        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        runCatching {
            val networkOperator = tm.networkOperator
            if (!networkOperator.isNullOrEmpty() && networkOperator.length >= 3) {
                networkMcc = networkOperator.substring(0, 3)
                networkMnc = networkOperator.substring(3)
                    .takeIf { it.isNotEmpty() }
            }
            networkCountryIso = tm.networkCountryIso?.takeIf { it.isNotEmpty() }
            networkOperatorName = tm.networkOperatorName?.takeIf { it.isNotEmpty() }
        }

        val simCards = collectSimCards(context, tm)

        val cellCollection = if (config.checkCellTowers && cellLookupPermissionGranted && locationServicesEnabled && telephonyRadioAccessAvailable) {
            collectCellCandidates(context, tm, simCards).also { cellCandidatesCount = it.candidates.size }
        } else {
            CellCollectionResult()
        }
        val cellCandidates = cellCollection.candidates
        val wifiCollection = if (config.checkWifiSignals && wifiPermissionGranted && locationServicesEnabled && wifiFeatureAvailable) {
            collectWifiCandidates(context).also { wifiAccessPointCandidatesCount = it.candidates.size }
        } else {
            WifiCollectionResult()
        }
        val wifiCandidates = wifiCollection.candidates

        val beaconDbClient = BeaconDbClient(countryResolver = { lat, lon ->
            reverseGeocodeCountry(context, lat, lon)
        }, resolverConfig = resolverConfig)
        val beaconDbInput = beaconDbClient.inputDiagnostics(cellCandidates, wifiCandidates)
        val beaconDbCellCandidatesUsedCount = beaconDbInput.supportedCellCount
        val beaconDbUnsupportedCellRadios = beaconDbInput.unsupportedCellRadios
        val beaconDbWifiCandidatesUsedCount = beaconDbInput.wifiUsedCount

        if (config.checkBeacondb && (cellLookupPermissionGranted || wifiPermissionGranted) && networkRequestsEnabled) {
            val lookup = beaconDbClient.lookup(cellCandidates, wifiCandidates)
            cellCountryCode = lookup.countryCode
            cellLookupSummary = buildString {
                append(lookup.summary)
                if (lookup.latitude != null && lookup.longitude != null) {
                    append(" (${lookup.latitude}, ${lookup.longitude})")
                }
            }
        }

        val bssidResult = if (config.checkWifiSignals && wifiPermissionGranted && locationServicesEnabled && wifiFeatureAvailable) {
            collectBssid(context, wifiCandidates)
        } else {
            BssidCollectionResult(bssid = null, source = null, unavailableReason = null)
        }

        return LocationSnapshot(
            networkMcc = networkMcc,
            networkMnc = networkMnc,
            networkCountryIso = networkCountryIso,
            networkOperatorName = networkOperatorName,
            simCards = simCards,
            cellCountryCode = cellCountryCode,
            cellLookupSummary = cellLookupSummary,
            cellCandidatesCount = cellCandidatesCount,
            wifiAccessPointCandidatesCount = wifiAccessPointCandidatesCount,
            bssid = bssidResult.bssid,
            cellLookupPermissionGranted = cellLookupPermissionGranted,
            wifiPermissionGranted = wifiPermissionGranted,
            locationServicesEnabled = locationServicesEnabled,
            telephonyRadioAccessAvailable = telephonyRadioAccessAvailable,
            wifiFeatureAvailable = wifiFeatureAvailable,
            nearbyWifiPermissionGranted = nearbyWifiGranted,
            networkRequestsEnabled = networkRequestsEnabled,
            cellRawInfoCount = cellCollection.rawInfoCount,
            cellRawInfoTypes = cellCollection.rawInfoTypes,
            cellCandidateRadios = cellCollection.candidateRadios,
            beaconDbCellCandidatesUsedCount = beaconDbCellCandidatesUsedCount,
            beaconDbUnsupportedCellRadios = beaconDbUnsupportedCellRadios,
            beaconDbWifiCandidatesUsedCount = beaconDbWifiCandidatesUsedCount,
            wifiCachedScanCandidatesCount = wifiCollection.cachedScanCandidatesCount,
            wifiFreshScanCandidatesCount = wifiCollection.freshScanCandidatesCount,
            wifiConnectedCandidateAvailable = wifiCollection.connectedCandidateAvailable,
            bssidSource = bssidResult.source,
            bssidUnavailableReason = bssidResult.unavailableReason,
        )
    }

    private fun hasPermission(context: Context, permission: String): Boolean {
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun isLocationEnabled(context: Context): Boolean {
        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            ?: return true
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                locationManager.isLocationEnabled
            } else {
                @Suppress("DEPRECATION")
                locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
                    locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
            }
        }.getOrDefault(true)
    }

    private fun hasTelephonyRadioAccess(context: Context): Boolean {
        val packageManager = context.packageManager
        return packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS) ||
            packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
    }

    private fun collectSimCards(context: Context, tm: TelephonyManager): List<SimCardInfo> {
        val subscriptions = if (hasPermission(context, Manifest.permission.READ_PHONE_STATE)) {
            getActiveSubscriptions(context)
        } else {
            null
        }
        val dataSubscriptionIds = getDataSubscriptionIds()

        if (!subscriptions.isNullOrEmpty()) {
            return subscriptions.mapNotNull { info ->
                runCatching {
                    val subTm = tm.createForSubscriptionId(info.subscriptionId)
                    val simOperator = subTm.simOperator
                    val simMcc = if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                        simOperator.substring(0, 3)
                    } else null
                    val simMnc = if (!simOperator.isNullOrEmpty() && simOperator.length > 3) {
                        simOperator.substring(3)
                    } else null
                    val simCountryIso = subTm.simCountryIso?.takeIf { it.isNotEmpty() }
                        ?: info.countryIso?.takeIf { it.isNotEmpty() }
                    SimCardInfo(
                        slotIndex = info.simSlotIndex,
                        subscriptionId = info.subscriptionId,
                        simMcc = simMcc,
                        simMnc = simMnc,
                        simCountryIso = simCountryIso,
                        operatorName = info.carrierName?.toString()?.takeIf { it.isNotEmpty() }
                            ?: subTm.simOperatorName?.takeIf { it.isNotEmpty() }
                            ?: subTm.networkOperatorName?.takeIf { it.isNotEmpty() },
                        isRoaming = subTm.isNetworkRoaming,
                        isActiveDataSubscription = info.subscriptionId == dataSubscriptionIds.active,
                        isDefaultDataSubscription = info.subscriptionId == dataSubscriptionIds.default,
                    )
                }.getOrNull()
            }
        }

        // Fallback: single-SIM device or permission denied
        return runCatching {
            val simOperator = tm.simOperator
            val simMcc = if (!simOperator.isNullOrEmpty() && simOperator.length >= 3) {
                simOperator.substring(0, 3)
            } else null
            val simMnc = if (!simOperator.isNullOrEmpty() && simOperator.length > 3) {
                simOperator.substring(3)
            } else null
            listOf(
                SimCardInfo(
                    slotIndex = 0,
                    subscriptionId = -1,
                    simMcc = simMcc,
                    simMnc = simMnc,
                    simCountryIso = tm.simCountryIso?.takeIf { it.isNotEmpty() },
                    operatorName = tm.simOperatorName?.takeIf { it.isNotEmpty() }
                        ?: tm.networkOperatorName?.takeIf { it.isNotEmpty() },
                    isRoaming = tm.isNetworkRoaming,
                    isActiveDataSubscription = dataSubscriptionIds.active != null,
                    isDefaultDataSubscription = dataSubscriptionIds.default != null,
                )
            )
        }.getOrElse { emptyList() }
    }

    @Suppress("MissingPermission")
    private fun getActiveSubscriptions(context: Context): List<android.telephony.SubscriptionInfo>? {
        val subscriptionManager = context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE)
                as? SubscriptionManager
        return runCatching { subscriptionManager?.activeSubscriptionInfoList }.getOrNull()
    }

    private fun getDataSubscriptionIds(): DataSubscriptionIds {
        val defaultDataSubscriptionId = runCatching {
            normalizeSubscriptionId(SubscriptionManager.getDefaultDataSubscriptionId())
        }.getOrNull()
        val activeDataSubscriptionId = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                normalizeSubscriptionId(SubscriptionManager.getActiveDataSubscriptionId())
            } else {
                defaultDataSubscriptionId
            }
        }.getOrNull()
        return DataSubscriptionIds(
            active = activeDataSubscriptionId,
            default = defaultDataSubscriptionId,
        )
    }

    private fun normalizeSubscriptionId(subscriptionId: Int): Int? {
        return subscriptionId.takeIf {
            it != SubscriptionManager.INVALID_SUBSCRIPTION_ID &&
                it != SubscriptionManager.DEFAULT_SUBSCRIPTION_ID
        }
    }

    private suspend fun collectCellCandidates(
        context: Context,
        tm: TelephonyManager,
        simCards: List<SimCardInfo>,
    ): CellCollectionResult {
        if (!hasPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)) {
            return CellCollectionResult()
        }
        val subscriptionManagers = simCards
            .mapNotNull { it.subscriptionId.takeIf { subscriptionId -> subscriptionId >= 0 } }
            .distinct()
            .mapNotNull { subscriptionId ->
                runCatching { tm.createForSubscriptionId(subscriptionId) }.getOrNull()
            }
        val managers = (listOf(tm) + subscriptionManagers).distinct()
        val cellInfo = managers.flatMap { collectCellInfo(context, it) }
        val rawInfoTypes = cellInfo
            .map(::cellInfoTypeName)
            .distinct()
            .sorted()
        val candidates = cellInfo
            .mapNotNull(::toLookupCandidate)
            .distinctBy { listOf(it.radio, it.mcc, it.mnc, it.areaCode, it.cellId, it.newRadioCellId) }
            .sortedWith(
                compareByDescending<CellLookupCandidate> { it.registered }
                    .thenByDescending { it.signalStrength ?: Int.MIN_VALUE },
            )
            .take(MAX_CELL_TOWERS)

        if (candidates.isNotEmpty()) {
            return CellCollectionResult(
                candidates = candidates,
                rawInfoCount = cellInfo.size,
                rawInfoTypes = rawInfoTypes,
                candidateRadios = summarizeCellRadios(candidates),
            )
        }

        val legacyCandidates = managers
            .mapNotNull(::legacyGsmCellCandidate)
            .distinctBy { listOf(it.radio, it.mcc, it.mnc, it.areaCode, it.cellId, it.newRadioCellId) }
            .take(MAX_CELL_TOWERS)
        return CellCollectionResult(
            candidates = legacyCandidates,
            rawInfoCount = cellInfo.size,
            rawInfoTypes = rawInfoTypes,
            candidateRadios = summarizeCellRadios(legacyCandidates),
        )
    }

    private suspend fun collectCellInfo(
        context: Context,
        tm: TelephonyManager,
    ): List<CellInfo> {
        return (requestFreshCellInfo(context, tm) + getCachedCellInfo(tm))
            .distinctBy { it.toString() }
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
                val completed = AtomicBoolean(false)
                val requested = runCatching {
                    tm.requestCellInfoUpdate(
                        context.mainExecutor,
                        object : TelephonyManager.CellInfoCallback() {
                            override fun onCellInfo(cellInfo: MutableList<CellInfo>) {
                                resumeOnce(continuation, completed, cellInfo.toList())
                            }

                            override fun onError(errorCode: Int, detail: Throwable?) {
                                resumeOnce(continuation, completed, emptyList())
                            }
                        },
                    )
                }.isSuccess

                continuation.invokeOnCancellation {
                    completed.set(true)
                }

                if (!requested) {
                    resumeOnce(continuation, completed, emptyList())
                }
            }
        } ?: emptyList()
    }

    @Suppress("MissingPermission")
    private fun getCachedCellInfo(tm: TelephonyManager): List<CellInfo> {
        return runCatching { tm.allCellInfo.orEmpty() }.getOrDefault(emptyList())
    }

    @Suppress("DEPRECATION", "MissingPermission")
    private fun legacyGsmCellCandidate(tm: TelephonyManager): CellLookupCandidate? {
        val operator = normalizeOperatorCode(tm.networkOperator)?.takeIf { it.length >= 4 } ?: return null
        val location = runCatching {
            tm.cellLocation as? android.telephony.gsm.GsmCellLocation
        }.getOrNull() ?: return null
        val areaCode = normalizeCellValue(location.lac) ?: return null
        val cellId = normalizeCellValue(location.cid) ?: return null
        return CellLookupCandidate(
            radio = "gsm",
            mcc = operator.substring(0, 3),
            mnc = operator.substring(3),
            areaCode = areaCode,
            cellId = cellId,
            registered = true,
        )
    }

    private fun toLookupCandidate(info: CellInfo): CellLookupCandidate? {
        return when (info) {
            is CellInfoGsm -> {
                val identity = info.cellIdentity
                val mcc = gsmMcc(identity) ?: return null
                val mnc = gsmMnc(identity) ?: return null
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
                val mcc = lteMcc(identity) ?: return null
                val mnc = lteMnc(identity) ?: return null
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
                val mcc = wcdmaMcc(identity) ?: return null
                val mnc = wcdmaMnc(identity) ?: return null
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

            else -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                Api29Impl.nrCandidate(info)
            } else {
                null
            }
        }
    }

    private suspend fun collectWifiCandidates(context: Context): WifiCollectionResult {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val cachedCandidates = currentWifiCandidates(wifiManager)
        val refreshedCandidates = requestFreshWifiScan(context, wifiManager)
        val connectedCandidate = currentWifiConnectionCandidate(context, wifiManager)

        return WifiCollectionResult(
            candidates = mergeWifiCandidates(
                cached = cachedCandidates,
                refreshed = refreshedCandidates.orEmpty(),
                connected = connectedCandidate,
            ),
            cachedScanCandidatesCount = cachedCandidates.size,
            freshScanCandidatesCount = refreshedCandidates?.size,
            connectedCandidateAvailable = connectedCandidate != null,
        )
    }

    private fun summarizeCellRadios(candidates: List<CellLookupCandidate>): List<String> {
        return candidates
            .map { it.radio.lowercase(Locale.US) }
            .distinct()
            .sorted()
    }

    private fun cellInfoTypeName(info: CellInfo): String {
        return info.javaClass.simpleName
            .removePrefix("CellInfo")
            .takeIf { it.isNotBlank() }
            ?.lowercase(Locale.US)
            ?: info.javaClass.name
    }

    private fun collectBssid(
        context: Context,
        wifiCandidates: List<WifiLookupCandidate>,
    ): BssidCollectionResult {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = getWifiInfo(context, wifiManager)
        val normalizedBssid = normalizeMacAddress(wifiInfo?.bssid)
        if (normalizedBssid != null) {
            return BssidCollectionResult(
                bssid = normalizedBssid,
                source = "connected Wi-Fi info",
                unavailableReason = null,
            )
        }

        val singleScanCandidate = wifiCandidates.singleOrNull()
        if (singleScanCandidate != null) {
            val reason = when {
                wifiInfo == null -> "Wi-Fi info unavailable; using the only scan candidate"
                wifiInfo.bssid == PLACEHOLDER_BSSID -> "connected Wi-Fi info is redacted by Android; using the only scan candidate"
                else -> "connected Wi-Fi BSSID is unavailable; using the only scan candidate"
            }
            return BssidCollectionResult(
                bssid = singleScanCandidate.macAddress,
                source = "single Wi-Fi scan candidate",
                unavailableReason = reason,
            )
        }

        val reason = when {
            wifiInfo == null -> "Wi-Fi info unavailable"
            wifiInfo.bssid == PLACEHOLDER_BSSID -> "connected Wi-Fi info is redacted by Android"
            wifiInfo.bssid.isNullOrBlank() -> "connected Wi-Fi BSSID is empty"
            else -> "connected Wi-Fi BSSID is invalid"
        }
        return BssidCollectionResult(
            bssid = null,
            source = null,
            unavailableReason = reason,
        )
    }

    @Suppress("MissingPermission", "DEPRECATION")
    private suspend fun requestFreshWifiScan(
        context: Context,
        wifiManager: WifiManager,
    ): List<WifiLookupCandidate>? {
        val appContext = context.applicationContext
        return withTimeoutOrNull(WIFI_SCAN_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                val completed = AtomicBoolean(false)
                val receiver = object : BroadcastReceiver() {
                    override fun onReceive(receiverContext: Context?, intent: Intent?) {
                        if (intent?.action != WifiManager.SCAN_RESULTS_AVAILABLE_ACTION) {
                            return
                        }
                        runCatching { appContext.unregisterReceiver(this) }
                        resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
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
                    resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
                    return@suspendCancellableCoroutine
                }

                continuation.invokeOnCancellation {
                    completed.set(true)
                    runCatching { appContext.unregisterReceiver(receiver) }
                }

                val started = runCatching { wifiManager.startScan() }.getOrDefault(false)
                if (!started) {
                    runCatching { appContext.unregisterReceiver(receiver) }
                    resumeOnce(continuation, completed, currentWifiCandidates(wifiManager))
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

    private fun currentWifiConnectionCandidate(
        context: Context,
        wifiManager: WifiManager,
    ): WifiLookupCandidate? {
        val wifiInfo = getWifiInfo(context, wifiManager) ?: return null
        val macAddress = normalizeMacAddress(wifiInfo.bssid) ?: return null
        val ssid = normalizeSsid(wifiInfo.ssid)
        if (ssid?.endsWith("_nomap", ignoreCase = true) == true) return null
        return WifiLookupCandidate(
            macAddress = macAddress,
            frequency = wifiInfo.frequency.takeIf { it > 0 },
            signalStrength = normalizeSignalStrength(wifiInfo.rssi),
        )
    }

    internal fun mergeWifiCandidates(
        cached: List<WifiLookupCandidate>,
        refreshed: List<WifiLookupCandidate>,
        connected: WifiLookupCandidate?,
    ): List<WifiLookupCandidate> {
        return (cached + refreshed + listOfNotNull(connected))
            .groupBy { it.macAddress }
            .values
            .mapNotNull { candidates ->
                candidates.maxWithOrNull(
                    compareBy<WifiLookupCandidate> { it.signalStrength ?: Int.MIN_VALUE }
                        .thenBy { it.frequency ?: 0 },
                )
            }
            .sortedByDescending { it.signalStrength ?: Int.MIN_VALUE }
            .take(MAX_WIFI_ACCESS_POINTS)
    }

    private fun toWifiLookupCandidate(scanResult: ScanResult): WifiLookupCandidate? {
        val macAddress = normalizeMacAddress(scanResult.BSSID) ?: return null
        val ssid = normalizeSsid(scanResultSsid(scanResult)) ?: return null
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

    private fun normalizeOperatorCode(value: Int): String? {
        return value
            .takeIf { it in 0 until Int.MAX_VALUE }
            ?.toString()
            ?.let(::normalizeOperatorCode)
    }

    private fun scanResultSsid(scanResult: ScanResult): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Api33Impl.scanResultSsid(scanResult)
        } else {
            @Suppress("DEPRECATION")
            scanResult.SSID
        }
    }

    @Suppress("DEPRECATION")
    private fun gsmMcc(identity: android.telephony.CellIdentityGsm): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.gsmMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun gsmMnc(identity: android.telephony.CellIdentityGsm): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.gsmMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    @Suppress("DEPRECATION")
    private fun lteMcc(identity: android.telephony.CellIdentityLte): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.lteMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun lteMnc(identity: android.telephony.CellIdentityLte): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.lteMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    @Suppress("DEPRECATION")
    private fun wcdmaMcc(identity: android.telephony.CellIdentityWcdma): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.wcdmaMcc(identity)
        } else {
            normalizeOperatorCode(identity.mcc)
        }
    }

    @Suppress("DEPRECATION")
    private fun wcdmaMnc(identity: android.telephony.CellIdentityWcdma): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Api28Impl.wcdmaMnc(identity)
        } else {
            normalizeOperatorCode(identity.mnc)
        }
    }

    // Keep newer cell identity accessors isolated so older devices never resolve them.
    @RequiresApi(Build.VERSION_CODES.Q)
    private object Api29Impl {
        @DoNotInline
        fun nrCandidate(info: CellInfo): CellLookupCandidate? {
            if (info !is android.telephony.CellInfoNr) return null
            val identity = info.cellIdentity as? android.telephony.CellIdentityNr ?: return null
            val mcc = normalizeOperatorCode(identity.mccString) ?: return null
            val mnc = normalizeOperatorCode(identity.mncString) ?: return null
            val areaCode = normalizeCellValue(identity.tac) ?: return null
            val newRadioCellId = normalizeNewRadioCellValue(identity.nci) ?: return null
            return CellLookupCandidate(
                radio = "nr",
                mcc = mcc,
                mnc = mnc,
                areaCode = areaCode,
                newRadioCellId = newRadioCellId,
                registered = info.isRegistered,
                signalStrength = normalizeSignalStrength(info.cellSignalStrength.dbm),
            )
        }
    }

    // Keep API 28-only operator accessors isolated so pre-P devices never resolve them.
    @RequiresApi(Build.VERSION_CODES.P)
    private object Api28Impl {
        @DoNotInline
        fun gsmMcc(identity: android.telephony.CellIdentityGsm): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun gsmMnc(identity: android.telephony.CellIdentityGsm): String? {
            return normalizeOperatorCode(identity.mncString)
        }

        @DoNotInline
        fun lteMcc(identity: android.telephony.CellIdentityLte): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun lteMnc(identity: android.telephony.CellIdentityLte): String? {
            return normalizeOperatorCode(identity.mncString)
        }

        @DoNotInline
        fun wcdmaMcc(identity: android.telephony.CellIdentityWcdma): String? {
            return normalizeOperatorCode(identity.mccString)
        }

        @DoNotInline
        fun wcdmaMnc(identity: android.telephony.CellIdentityWcdma): String? {
            return normalizeOperatorCode(identity.mncString)
        }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private object Api33Impl {
        @DoNotInline
        fun scanResultSsid(scanResult: ScanResult): String? {
            return scanResult.wifiSsid
                ?.toString()
                ?.trim('"')
        }
    }

    private fun normalizeCellValue(value: Int): Long? {
        return value.toLong().takeIf { it in 0 until Int.MAX_VALUE.toLong() }
    }

    private fun normalizeNewRadioCellValue(value: Long): Long? {
        return value.takeIf { it in 0..MAX_NR_CELL_ID }
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

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun <T> resumeOnce(
        continuation: CancellableContinuation<T>,
        completed: AtomicBoolean,
        value: T,
    ) {
        if (!completed.compareAndSet(false, true)) {
            return
        }
        continuation.resume(value) { }
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
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return getWifiInfo(context, wifiManager)?.bssid
    }

    @Suppress("DEPRECATION")
    private fun getWifiInfo(context: Context, wifiManager: WifiManager): WifiInfo? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = cm.activeNetwork
            val caps = network?.let { cm.getNetworkCapabilities(it) }
            val transportInfo = caps
                ?.takeIf { it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }
                ?.transportInfo as? WifiInfo
            transportInfo ?: wifiManager.connectionInfo
        } else {
            wifiManager.connectionInfo
        }
    }

    internal fun evaluate(snapshot: LocationSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        val homeSim = selectHomeSim(snapshot)
        val homeSimCountryIsRussia = homeSim?.simMcc == RUSSIA_MCC
        val networkIsRussia = snapshot.networkMcc == RUSSIA_MCC
        val homeRoutedRoaming = networkIsRussia &&
            homeSim?.simMcc != null &&
            !homeSimCountryIsRussia
        val homeRoutedRoamingReason = if (homeRoutedRoaming && homeSim != null) {
            val simCountry = homeSim.simCountryIso?.uppercase(Locale.US)
                ?: countryFromMcc(homeSim.simMcc)
                ?: "?"
            "Home SIM MCC ${homeSim.simMcc} ($simCountry) on visited Russian network MCC ${snapshot.networkMcc}"
        } else {
            null
        }
        val anySimReportedRoaming = snapshot.simCards.any { it.isRoaming == true } ||
            // Telephony sometimes returns isRoaming=false for foreign SIM in RU
            // (e.g. Free Mobile in RU); fall back to MCC mismatch heuristic.
            snapshot.simCards.any {
                !it.simMcc.isNullOrBlank() &&
                    !snapshot.networkMcc.isNullOrBlank() &&
                    it.simMcc != snapshot.networkMcc
            }

        if (snapshot.networkMcc == null) {
            findings += Finding("PLMN: network MCC is unavailable")
        } else {
            val networkCountry = snapshot.networkCountryIso?.uppercase(Locale.US)
                ?: countryFromMcc(snapshot.networkMcc)
                ?: "N/A"

            findings += Finding(
                description = "Network operator: ${snapshot.networkOperatorName ?: "N/A"} ($networkCountry)",
                isInformational = true,
            )
            findings += Finding(
                description = "Network MCC: ${snapshot.networkMcc}",
                isInformational = true,
            )
            if (networkIsRussia) {
                findings += Finding("network_mcc_ru:true")
            }

            for (sim in snapshot.simCards) {
                // Prefer simCountryIso for the SIM label — historically this
                // was sourced from the network, mislabelling foreign SIMs as
                // RU when registered on a Russian visited network.
                val simCountry = sim.simCountryIso?.uppercase(Locale.US)
                    ?: countryFromMcc(sim.simMcc)
                    ?: "N/A"
                val operatorPart = sim.operatorName?.let { ", $it" } ?: ""
                findings += Finding(
                    description = "SIM[${sim.slotIndex}] MCC: ${sim.simMcc ?: "N/A"} ($simCountry)$operatorPart",
                    isInformational = true,
                )
                val effectiveRoaming: Boolean? = when {
                    sim.isRoaming == true -> true
                    !sim.simMcc.isNullOrBlank() &&
                        !snapshot.networkMcc.isNullOrBlank() &&
                        sim.simMcc != snapshot.networkMcc -> true
                    sim.isRoaming == false -> false
                    else -> null
                }
                val roamingLabel = when (effectiveRoaming) {
                    true -> "yes"
                    false -> "no"
                    null -> null
                }
                if (roamingLabel != null) {
                    findings += Finding(
                        description = "SIM[${sim.slotIndex}] Roaming: $roamingLabel",
                        isInformational = true,
                    )
                }
            }

            if (homeRoutedRoaming) {
                val description = "home_routed_roaming:true (home SIM MCC ${homeSim?.simMcc}, " +
                    "visited network MCC ${snapshot.networkMcc})"
                findings += Finding(
                    description = description,
                    source = EvidenceSource.HOME_ROUTED_ROAMING,
                    confidence = EvidenceConfidence.MEDIUM,
                    isInformational = false,
                )
                evidence += EvidenceItem(
                    source = EvidenceSource.HOME_ROUTED_ROAMING,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = homeRoutedRoamingReason
                        ?: "Foreign SIM connected via Russian visited network",
                )
            }

            if (!networkIsRussia) {
                // Foreign visited network. If this is a Russian SIM roaming
                // abroad (homeSimCountryIsRussia), the public IP is expected
                // to belong to the home (Russian) operator and bypass cannot
                // be inferred from country alone — drop confidence to LOW.
                val matchingSim = snapshot.simCards.firstOrNull { it.simMcc == snapshot.networkMcc }
                val confidence = if (matchingSim?.isRoaming == true || homeSimCountryIsRussia) {
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

        if (!snapshot.locationServicesEnabled) {
            findings += Finding("Location services: disabled")
        }

        if (!snapshot.cellLookupPermissionGranted) {
            findings += Finding("Cell lookup: ACCESS_FINE_LOCATION permission is not granted")
        } else if (!snapshot.locationServicesEnabled) {
            findings += Finding("Cell lookup: system location is disabled")
        } else if (!snapshot.telephonyRadioAccessAvailable) {
            findings += Finding("Cell lookup: telephony radio access is unavailable")
        } else {
            findings += Finding("Cell lookup candidates: ${snapshot.cellCandidatesCount}")
            if (snapshot.cellCandidatesCount == 0) {
                findings += Finding("Cell lookup: base station identifiers are unavailable")
            }
        }

        if (!snapshot.wifiPermissionGranted) {
            findings += Finding("Wi-Fi scan: permissions are not granted")
        } else if (!snapshot.locationServicesEnabled) {
            findings += Finding("Wi-Fi scan: system location is disabled")
        } else if (!snapshot.wifiFeatureAvailable) {
            findings += Finding("Wi-Fi scan: Wi-Fi feature is unavailable")
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
        } else if (!snapshot.locationServicesEnabled) {
            findings += Finding("BSSID: system location is disabled")
        } else if (!snapshot.wifiFeatureAvailable) {
            findings += Finding("BSSID: Wi-Fi feature is unavailable")
        } else if (snapshot.bssid == null || snapshot.bssid == PLACEHOLDER_BSSID) {
            findings += Finding("BSSID: unavailable")
        } else {
            findings += Finding("BSSID: ${snapshot.bssid}")
        }

        val detected = evidence.any {
            it.detected &&
                it.confidence >= EvidenceConfidence.MEDIUM &&
                it.source != EvidenceSource.HOME_ROUTED_ROAMING
        }

        val locationFacts = LocationSignalsFacts(
            networkMcc = snapshot.networkMcc,
            networkMnc = snapshot.networkMnc,
            networkCountryIso = snapshot.networkCountryIso?.uppercase(Locale.US),
            networkOperatorName = snapshot.networkOperatorName,
            networkIsRussia = networkIsRussia,
            homeSimMcc = homeSim?.simMcc,
            homeSimMnc = homeSim?.simMnc,
            homeSimCountryIso = homeSim?.simCountryIso?.uppercase(Locale.US)
                ?: countryFromMcc(homeSim?.simMcc),
            homeSimCountryIsRussia = homeSimCountryIsRussia,
            homeSimOperatorName = homeSim?.operatorName,
            anySimReportedRoaming = anySimReportedRoaming,
            homeRoutedRoaming = homeRoutedRoaming,
            homeRoutedRoamingReason = homeRoutedRoamingReason,
        )

        val result = CategoryResult(
            name = "Location signals",
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
            locationFacts = locationFacts,
        )
        return LocationSignalsDiagnosticsRegistry.attach(
            result,
            LocationSignalsDiagnostics(
                fineLocationPermissionGranted = snapshot.cellLookupPermissionGranted,
                nearbyWifiPermissionGranted = snapshot.nearbyWifiPermissionGranted,
                locationServicesEnabled = snapshot.locationServicesEnabled,
                telephonyRadioAccessAvailable = snapshot.telephonyRadioAccessAvailable,
                wifiFeatureAvailable = snapshot.wifiFeatureAvailable,
                networkRequestsEnabled = snapshot.networkRequestsEnabled,
                cellRawInfoCount = snapshot.cellRawInfoCount,
                cellRawInfoTypes = snapshot.cellRawInfoTypes,
                cellCandidateRadios = snapshot.cellCandidateRadios,
                beaconDbCellCandidatesUsedCount = snapshot.beaconDbCellCandidatesUsedCount,
                beaconDbUnsupportedCellRadios = snapshot.beaconDbUnsupportedCellRadios,
                beaconDbWifiCandidatesUsedCount = snapshot.beaconDbWifiCandidatesUsedCount,
                wifiAccessPointCandidatesCount = snapshot.wifiAccessPointCandidatesCount,
                wifiCachedScanCandidatesCount = snapshot.wifiCachedScanCandidatesCount,
                wifiFreshScanCandidatesCount = snapshot.wifiFreshScanCandidatesCount,
                wifiConnectedCandidateAvailable = snapshot.wifiConnectedCandidateAvailable,
                bssidSource = snapshot.bssidSource,
                bssidUnavailableReason = snapshot.bssidUnavailableReason,
            ),
        )
    }

    private fun selectHomeSim(snapshot: LocationSnapshot): SimCardInfo? {
        val simsWithMcc = snapshot.simCards.filter { !it.simMcc.isNullOrBlank() }
        return snapshot.simCards.firstOrNull { it.isActiveDataSubscription }
            ?: snapshot.simCards.firstOrNull { it.isDefaultDataSubscription }
            ?: simsWithMcc.firstOrNull { it.matchesRegisteredNetwork(snapshot) }
            ?: simsWithMcc.firstOrNull()
            ?: snapshot.simCards.firstOrNull()
    }

    private fun SimCardInfo.matchesRegisteredNetwork(snapshot: LocationSnapshot): Boolean {
        if (simMcc.isNullOrBlank() || snapshot.networkMcc.isNullOrBlank()) return false
        if (simMcc != snapshot.networkMcc) return false
        return snapshot.networkMnc.isNullOrBlank() ||
            simMnc.isNullOrBlank() ||
            simMnc == snapshot.networkMnc
    }

    private val MAC_ADDRESS_REGEX = Regex("^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")

    /**
     * Lightweight MCC → ISO 3166-1 alpha-2 lookup for the most common
     * countries. Used to label SIM/Network country when telephony APIs
     * return blank simCountryIso (typical when SIM-MCC and Network-MCC
     * disagree). Not exhaustive — falls back to null.
     */
    private fun countryFromMcc(mcc: String?): String? {
        if (mcc.isNullOrBlank()) return null
        return MCC_TO_ISO[mcc]
    }

    private val MCC_TO_ISO: Map<String, String> = mapOf(
        "202" to "GR", "204" to "NL", "206" to "BE", "208" to "FR",
        "212" to "MC", "213" to "AD", "214" to "ES", "216" to "HU",
        "218" to "BA", "219" to "HR", "220" to "RS", "222" to "IT",
        "226" to "RO", "228" to "CH", "230" to "CZ", "231" to "SK",
        "232" to "AT", "234" to "GB", "235" to "GB", "238" to "DK",
        "240" to "SE", "242" to "NO", "244" to "FI", "246" to "LT",
        "247" to "LV", "248" to "EE", "250" to "RU", "255" to "UA",
        "257" to "BY", "259" to "MD", "260" to "PL", "262" to "DE",
        "266" to "GI", "268" to "PT", "270" to "LU", "272" to "IE",
        "274" to "IS", "276" to "AL", "278" to "MT", "280" to "CY",
        "282" to "GE", "283" to "AM", "284" to "BG", "286" to "TR",
        "288" to "FO", "290" to "GL", "293" to "SI", "294" to "MK",
        "295" to "LI", "297" to "ME", "310" to "US", "311" to "US",
        "312" to "US", "313" to "US", "314" to "US", "315" to "US",
        "316" to "US", "330" to "PR", "334" to "MX", "338" to "JM",
        "340" to "MQ", "342" to "BB", "346" to "KY", "348" to "VG",
        "350" to "BM", "352" to "GD", "354" to "MS", "356" to "KN",
        "358" to "LC", "360" to "VC", "362" to "AN", "363" to "AW",
        "364" to "BS", "365" to "AI", "366" to "DM", "368" to "CU",
        "370" to "DO", "372" to "HT", "374" to "TT", "376" to "TC",
        "400" to "AZ", "401" to "KZ", "402" to "BT", "404" to "IN",
        "405" to "IN", "410" to "PK", "412" to "AF", "413" to "LK",
        "414" to "MM", "415" to "LB", "416" to "JO", "417" to "SY",
        "418" to "IQ", "419" to "KW", "420" to "SA", "421" to "YE",
        "422" to "OM", "424" to "AE", "425" to "IL", "426" to "BH",
        "427" to "QA", "428" to "MN", "429" to "NP", "430" to "AE",
        "431" to "AE", "432" to "IR", "434" to "UZ", "436" to "TJ",
        "437" to "KG", "438" to "TM", "440" to "JP", "441" to "JP",
        "450" to "KR", "452" to "VN", "454" to "HK", "455" to "MO",
        "456" to "KH", "457" to "LA", "460" to "CN", "461" to "CN",
        "466" to "TW", "467" to "KP", "470" to "BD", "472" to "MV",
        "502" to "MY", "505" to "AU", "510" to "ID", "514" to "TL",
        "515" to "PH", "520" to "TH", "525" to "SG", "528" to "BN",
        "530" to "NZ", "534" to "MP", "535" to "GU", "536" to "NR",
        "537" to "PG", "539" to "TO", "540" to "SB", "541" to "VU",
        "542" to "FJ", "543" to "WF", "544" to "AS", "545" to "KI",
        "546" to "NC", "547" to "PF", "548" to "CK", "549" to "WS",
        "550" to "FM", "551" to "MH", "552" to "PW", "602" to "EG",
        "603" to "DZ", "604" to "MA", "605" to "TN", "606" to "LY",
        "607" to "GM", "608" to "SN", "609" to "MR", "610" to "ML",
        "611" to "GN", "612" to "CI", "613" to "BF", "614" to "NE",
        "615" to "TG", "616" to "BJ", "617" to "MU", "618" to "LR",
        "619" to "SL", "620" to "GH", "621" to "NG", "622" to "TD",
        "623" to "CF", "624" to "CM", "625" to "CV", "626" to "ST",
        "627" to "GQ", "628" to "GA", "629" to "CG", "630" to "CD",
        "631" to "AO", "632" to "GW", "633" to "SC", "634" to "SD",
        "635" to "RW", "636" to "ET", "637" to "SO", "638" to "DJ",
        "639" to "KE", "640" to "TZ", "641" to "UG", "642" to "BI",
        "643" to "MZ", "645" to "ZM", "646" to "MG", "647" to "RE",
        "648" to "ZW", "649" to "NA", "650" to "MW", "651" to "LS",
        "652" to "BW", "653" to "SZ", "654" to "KM", "655" to "ZA",
        "657" to "ER", "659" to "SS", "702" to "BZ", "704" to "GT",
        "706" to "SV", "708" to "HN", "710" to "NI", "712" to "CR",
        "714" to "PA", "716" to "PE", "722" to "AR", "724" to "BR",
        "730" to "CL", "732" to "CO", "734" to "VE", "736" to "BO",
        "738" to "GY", "740" to "EC", "744" to "PY", "746" to "SR",
        "748" to "UY",
    )
}
