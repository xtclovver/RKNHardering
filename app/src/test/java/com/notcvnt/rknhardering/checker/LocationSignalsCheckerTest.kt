package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LocationSignalsCheckerTest {

    @Test
    fun `russian network mcc produces clean result`() {
        val result = LocationSignalsChecker.evaluate(snapshot())

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("MegaFon") })
        assertTrue(result.findings.any { it.description == "network_mcc_ru:true" })
    }

    @Test
    fun `foreign network mcc sets needs review`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simCards = listOf(sim(simMcc = "244", simCountryIso = "fi", operatorName = "Elisa", isRoaming = false)),
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `foreign network mcc with roaming lowers confidence`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simCards = listOf(sim(simMcc = "244", simCountryIso = "fi", operatorName = "Elisa", isRoaming = true)),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.LOW
            },
        )
    }

    @Test
    fun `mcc 310 non roaming network is detected as location signal`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "310",
                networkCountryIso = "us",
                networkOperatorName = "T-Mobile",
                simCards = listOf(sim(simMcc = "310", simCountryIso = "us", operatorName = "T-Mobile", isRoaming = false)),
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.findings.any { it.description == "Network MCC 310 (US) is not Russia" })
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS &&
                    it.detected &&
                    it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `plmn fields are marked as informational`() {
        val result = LocationSignalsChecker.evaluate(snapshot())

        val infoFindings = result.findings.filter { it.isInformational }
        assertEquals(4, infoFindings.size)
        assertTrue(infoFindings.any { it.description.startsWith("Network operator:") })
        assertTrue(infoFindings.any { it.description.startsWith("Network MCC:") })
        assertTrue(infoFindings.any { it.description.startsWith("SIM[0] MCC:") })
        assertTrue(infoFindings.any { it.description.startsWith("SIM[0] Roaming:") })
        assertFalse(result.findings.any { it.description.startsWith("Cell lookup") && it.isInformational })
    }

    @Test
    fun `missing network mcc produces informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = null,
                networkCountryIso = null,
                networkOperatorName = null,
                simCards = emptyList(),
            ),
        )

        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description == "PLMN: network MCC is unavailable" })
    }

    @Test
    fun `cell lookup without location permission is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(snapshot(cellLookupPermissionGranted = false))

        assertTrue(result.findings.any { it.description.contains("ACCESS_FINE_LOCATION") })
    }

    @Test
    fun `cell lookup with no candidates is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 0,
            ),
        )

        assertTrue(result.findings.any { it.description.contains("base station identifiers are unavailable") })
    }

    @Test
    fun `cell lookup diagnostics expose raw radios and beacon db eligibility`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 1,
                cellRawInfoCount = 1,
                cellRawInfoTypes = listOf("nr"),
                cellCandidateRadios = listOf("nr"),
                beaconDbCellCandidatesUsedCount = 0,
                beaconDbUnsupportedCellRadios = listOf("nr"),
            ),
        )
        val diagnostics = LocationSignalsDiagnosticsRegistry.find(result)

        assertTrue(result.findings.none { it.description.startsWith("Cell raw info:") })
        assertEquals(1, diagnostics?.cellRawInfoCount)
        assertEquals(listOf("nr"), diagnostics?.cellRawInfoTypes)
        assertEquals(listOf("nr"), diagnostics?.cellCandidateRadios)
        assertEquals(0, diagnostics?.beaconDbCellCandidatesUsedCount)
        assertEquals(listOf("nr"), diagnostics?.beaconDbUnsupportedCellRadios)
    }

    @Test
    fun `wifi permission absence is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(snapshot(wifiPermissionGranted = false))

        assertTrue(result.findings.any { it.description == "Wi-Fi scan: permissions are not granted" })
        assertTrue(result.findings.any { it.description == "BSSID: permission is not granted" })
    }

    @Test
    fun `wifi candidate count is surfaced`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                wifiAccessPointCandidatesCount = 4,
            ),
        )

        assertTrue(result.findings.any { it.description == "Wi-Fi scan candidates: 4" })
    }

    @Test
    fun `wifi diagnostics expose scan sources and beacon db minimum`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                wifiAccessPointCandidatesCount = 1,
                wifiCachedScanCandidatesCount = 1,
                wifiFreshScanCandidatesCount = null,
                wifiConnectedCandidateAvailable = false,
                beaconDbWifiCandidatesUsedCount = 0,
            ),
        )
        val diagnostics = LocationSignalsDiagnosticsRegistry.find(result)

        assertTrue(result.findings.none { it.description.startsWith("Wi-Fi scan sources:") })
        assertEquals(1, diagnostics?.wifiCachedScanCandidatesCount)
        assertEquals(null, diagnostics?.wifiFreshScanCandidatesCount)
        assertEquals(false, diagnostics?.wifiConnectedCandidateAvailable)
        assertEquals(0, diagnostics?.beaconDbWifiCandidatesUsedCount)
    }

    @Test
    fun `location services disabled is reported for radio lookups`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                wifiPermissionGranted = true,
                locationServicesEnabled = false,
            ),
        )

        assertTrue(result.findings.any { it.description == "Location services: disabled" })
        assertTrue(result.findings.any { it.description == "Cell lookup: system location is disabled" })
        assertTrue(result.findings.any { it.description == "Wi-Fi scan: system location is disabled" })
        assertTrue(result.findings.any { it.description == "BSSID: system location is disabled" })
        assertFalse(result.findings.any { it.description == "Cell lookup: base station identifiers are unavailable" })
    }

    @Test
    fun `missing telephony radio access is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                telephonyRadioAccessAvailable = false,
            ),
        )

        assertTrue(result.findings.any { it.description == "Cell lookup: telephony radio access is unavailable" })
    }

    @Test
    fun `missing wifi feature is reported explicitly`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                wifiFeatureAvailable = false,
            ),
        )

        assertTrue(result.findings.any { it.description == "Wi-Fi scan: Wi-Fi feature is unavailable" })
        assertTrue(result.findings.any { it.description == "BSSID: Wi-Fi feature is unavailable" })
    }

    @Test
    fun `ru cell lookup adds russian markers`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 1,
                cellCountryCode = "RU",
                cellLookupSummary = "BeaconDB: exact match",
            ),
        )

        assertTrue(result.findings.any { it.description == "cell_country_ru:true" })
        assertTrue(result.findings.any { it.description == "location_country_ru:true" })
        assertTrue(result.findings.any { it.description.contains("BeaconDB: exact match") })
    }

    @Test
    fun `coarse BeaconDB fallback does not add russian markers`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 1,
                cellLookupSummary = "BeaconDB: coarse cell area fallback",
            ),
        )

        assertFalse(result.findings.any { it.description == "cell_country_ru:true" })
        assertFalse(result.findings.any { it.description == "location_country_ru:true" })
    }

    @Test
    fun `valid bssid is surfaced as informational finding`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                bssid = "AA:BB:CC:DD:EE:FF",
                bssidSource = "connected Wi-Fi info",
            ),
        )

        assertTrue(result.findings.any { it.description.contains("AA:BB:CC:DD:EE:FF") })
        assertEquals("connected Wi-Fi info", LocationSignalsDiagnosticsRegistry.find(result)?.bssidSource)
    }

    @Test
    fun `placeholder bssid is treated as unavailable`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                wifiPermissionGranted = true,
                bssid = "02:00:00:00:00:00",
                bssidUnavailableReason = "connected Wi-Fi info is redacted by Android",
            ),
        )

        assertTrue(result.findings.any { it.description == "BSSID: unavailable" })
        assertEquals(
            "connected Wi-Fi info is redacted by Android",
            LocationSignalsDiagnosticsRegistry.find(result)?.bssidUnavailableReason,
        )
    }

    @Test
    fun `wifi merge keeps cached candidates when fresh scan is empty`() {
        val cached = listOf(wifi("aa:bb:cc:dd:ee:01", signalStrength = -60))

        val merged = LocationSignalsChecker.mergeWifiCandidates(
            cached = cached,
            refreshed = emptyList(),
            connected = null,
        )

        assertEquals(cached, merged)
    }

    @Test
    fun `wifi merge includes connection and keeps strongest duplicate`() {
        val merged = LocationSignalsChecker.mergeWifiCandidates(
            cached = listOf(wifi("aa:bb:cc:dd:ee:01", signalStrength = -80)),
            refreshed = listOf(wifi("aa:bb:cc:dd:ee:01", signalStrength = -55)),
            connected = wifi("aa:bb:cc:dd:ee:02", signalStrength = -50),
        )

        assertEquals(listOf("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01"), merged.map { it.macAddress })
        assertEquals(-55, merged.first { it.macAddress == "aa:bb:cc:dd:ee:01" }.signalStrength)
    }

    @Test
    fun `LocationSnapshot accepts simCards list`() {
        val sim = LocationSignalsChecker.SimCardInfo(
            slotIndex = 0,
            subscriptionId = 1,
            simMcc = "250",
            simCountryIso = "ru",
            operatorName = "MegaFon",
            isRoaming = false,
        )
        val s = LocationSignalsChecker.LocationSnapshot(
            networkMcc = "250",
            networkCountryIso = "ru",
            networkOperatorName = "MegaFon",
            simCards = listOf(sim),
            cellCountryCode = null,
            cellLookupSummary = null,
            cellCandidatesCount = 0,
            wifiAccessPointCandidatesCount = 0,
            bssid = null,
            cellLookupPermissionGranted = false,
            wifiPermissionGranted = false,
        )
        assertEquals(1, s.simCards.size)
    }

    @Test
    fun `dual sim with ru network mcc produces clean result`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MegaFon",
                simCards = listOf(
                    sim(slotIndex = 0, subscriptionId = 1, simMcc = "250", simCountryIso = "ru", operatorName = "MegaFon", isRoaming = false),
                    sim(slotIndex = 1, subscriptionId = 2, simMcc = "202", simCountryIso = "gr", operatorName = "Cosmote", isRoaming = false),
                ),
            ),
        )

        assertFalse(result.needsReview)
        assertFalse(result.detected)
        assertTrue(result.findings.any { it.description.startsWith("SIM[0] MCC:") })
        assertTrue(result.findings.any { it.description.startsWith("SIM[1] MCC:") })
    }

    @Test
    fun `dual sim non-ru network with non-roaming matching sim gives medium confidence`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "202",
                networkCountryIso = "gr",
                networkOperatorName = "Cosmote",
                simCards = listOf(
                    // Home SIM is foreign (GR) and matches the visited (GR) network — no
                    // Russian SIM means we cannot blame the geo signal on home-routed
                    // roaming, so confidence stays at MEDIUM.
                    sim(slotIndex = 0, subscriptionId = 1, simMcc = "202", simCountryIso = "gr", operatorName = "Cosmote", isRoaming = false),
                    sim(slotIndex = 1, subscriptionId = 2, simMcc = "208", simCountryIso = "fr", operatorName = "Orange", isRoaming = false),
                ),
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `dual sim non-ru network with roaming matching sim gives low confidence`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "202",
                networkCountryIso = "gr",
                networkOperatorName = "Cosmote",
                simCards = listOf(
                    sim(slotIndex = 0, subscriptionId = 1, simMcc = "250", simCountryIso = "ru", operatorName = "MegaFon", isRoaming = false),
                    sim(slotIndex = 1, subscriptionId = 2, simMcc = "202", simCountryIso = "gr", operatorName = "Cosmote", isRoaming = true),
                ),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.LOW
            },
        )
    }

    @Test
    fun `foreign sim on russian visited network is flagged as home-routed roaming`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MegaFon",
                simCards = listOf(
                    sim(
                        slotIndex = 0,
                        subscriptionId = 1,
                        simMcc = "208",
                        simCountryIso = "fr",
                        operatorName = "Free Mobile",
                        isRoaming = false,
                    ),
                ),
            ),
        )

        assertFalse(result.needsReview)
        assertFalse(result.detected)
        assertNotNull(result.locationFacts)
        assertTrue(result.locationFacts!!.homeRoutedRoaming)
        assertEquals("208", result.locationFacts!!.homeSimMcc)
        assertEquals("FR", result.locationFacts!!.homeSimCountryIso)
        assertTrue(result.findings.any { it.description.startsWith("home_routed_roaming:true") })
        assertTrue(result.evidence.any { it.source == EvidenceSource.HOME_ROUTED_ROAMING })
        // SIM-MCC mismatch flips the displayed roaming state to "yes" even when
        // telephony reported it as "no" (the bug from issue #63).
        assertTrue(result.findings.any { it.description == "SIM[0] Roaming: yes" })
    }

    @Test
    fun `active russian data sim prevents home routed roaming from inactive foreign sim`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "250",
                networkCountryIso = "ru",
                networkOperatorName = "MegaFon",
                simCards = listOf(
                    sim(
                        slotIndex = 0,
                        subscriptionId = 1,
                        simMcc = "208",
                        simCountryIso = "fr",
                        operatorName = "Free Mobile",
                        isRoaming = true,
                    ),
                    sim(
                        slotIndex = 1,
                        subscriptionId = 2,
                        simMcc = "250",
                        simMnc = "02",
                        simCountryIso = "ru",
                        operatorName = "MegaFon",
                        isRoaming = false,
                        isActiveDataSubscription = true,
                        isDefaultDataSubscription = true,
                    ),
                ),
            ),
        )

        assertFalse(result.locationFacts!!.homeRoutedRoaming)
        assertEquals("250", result.locationFacts!!.homeSimMcc)
        assertFalse(result.evidence.any { it.source == EvidenceSource.HOME_ROUTED_ROAMING })
    }

    @Test
    fun `registered network sim is preferred over first foreign sim when data id is unavailable`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "250",
                networkOperatorName = "MegaFon",
                simCards = listOf(
                    sim(
                        slotIndex = 0,
                        subscriptionId = 1,
                        simMcc = "208",
                        simCountryIso = "fr",
                        operatorName = "Free Mobile",
                        isRoaming = true,
                    ),
                    sim(
                        slotIndex = 1,
                        subscriptionId = 2,
                        simMcc = "250",
                        simCountryIso = "ru",
                        operatorName = "MegaFon",
                        isRoaming = false,
                    ),
                ),
            ),
        )

        assertFalse(result.locationFacts!!.homeRoutedRoaming)
        assertEquals("250", result.locationFacts!!.homeSimMcc)
    }

    @Test
    fun `empty sim cards list produces no sim findings and medium confidence for non-ru network`() {
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                networkMcc = "244",
                networkCountryIso = "fi",
                networkOperatorName = "Elisa",
                simCards = emptyList(),
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.needsReview)
        assertFalse(result.findings.any { it.description.startsWith("SIM[") })
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.LOCATION_SIGNALS && it.confidence == EvidenceConfidence.MEDIUM
            },
        )
    }

    @Test
    fun `when checkBeacondb=false the beacondb fetch is skipped`() {
        // When checkBeacondb is false, collectSnapshot never calls beaconDbClient.lookup,
        // so cellCountryCode remains null. Simulate this via evaluate() with a snapshot
        // that has cellCountryCode=null (the state produced when the toggle is off).
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 1,
                cellCountryCode = null,
                cellLookupSummary = null,
            ),
        )

        assertFalse(result.findings.any { it.description.startsWith("Cell lookup country:") })
        assertFalse(result.findings.any { it.description == "cell_country_ru:true" })
    }

    @Test
    fun `when checkCellTowers=false the cell tower finding is skipped`() {
        // When checkCellTowers is false, collectCellCandidates is not called,
        // so cellCandidatesCount stays 0. Simulate via snapshot with count=0.
        val result = LocationSignalsChecker.evaluate(
            snapshot(
                cellLookupPermissionGranted = true,
                cellCandidatesCount = 0,
            ),
        )

        assertTrue(result.findings.any { it.description == "Cell lookup: base station identifiers are unavailable" })
        assertFalse(result.findings.any { it.description.startsWith("Cell lookup candidates:") && it.description != "Cell lookup candidates: 0" })
    }

    private fun sim(
        slotIndex: Int = 0,
        subscriptionId: Int = 1,
        simMcc: String? = "250",
        simMnc: String? = null,
        simCountryIso: String? = "ru",
        operatorName: String? = "MegaFon",
        isRoaming: Boolean? = false,
        isActiveDataSubscription: Boolean = false,
        isDefaultDataSubscription: Boolean = false,
    ) = LocationSignalsChecker.SimCardInfo(
        slotIndex = slotIndex,
        subscriptionId = subscriptionId,
        simMcc = simMcc,
        simMnc = simMnc,
        simCountryIso = simCountryIso,
        operatorName = operatorName,
        isRoaming = isRoaming,
        isActiveDataSubscription = isActiveDataSubscription,
        isDefaultDataSubscription = isDefaultDataSubscription,
    )

    private fun snapshot(
        networkMcc: String? = "250",
        networkCountryIso: String? = "ru",
        networkOperatorName: String? = "MegaFon",
        simCards: List<LocationSignalsChecker.SimCardInfo> = listOf(sim()),
        cellCountryCode: String? = null,
        cellLookupSummary: String? = null,
        cellCandidatesCount: Int = 0,
        wifiAccessPointCandidatesCount: Int = 0,
        bssid: String? = null,
        cellLookupPermissionGranted: Boolean = false,
        wifiPermissionGranted: Boolean = false,
        locationServicesEnabled: Boolean = true,
        telephonyRadioAccessAvailable: Boolean = true,
        wifiFeatureAvailable: Boolean = true,
        nearbyWifiPermissionGranted: Boolean = true,
        networkRequestsEnabled: Boolean = true,
        cellRawInfoCount: Int = 0,
        cellRawInfoTypes: List<String> = emptyList(),
        cellCandidateRadios: List<String> = emptyList(),
        beaconDbCellCandidatesUsedCount: Int = 0,
        beaconDbUnsupportedCellRadios: List<String> = emptyList(),
        beaconDbWifiCandidatesUsedCount: Int = 0,
        wifiCachedScanCandidatesCount: Int = 0,
        wifiFreshScanCandidatesCount: Int? = null,
        wifiConnectedCandidateAvailable: Boolean = false,
        bssidSource: String? = null,
        bssidUnavailableReason: String? = null,
    ): LocationSignalsChecker.LocationSnapshot {
        return LocationSignalsChecker.LocationSnapshot(
            networkMcc = networkMcc,
            networkCountryIso = networkCountryIso,
            networkOperatorName = networkOperatorName,
            simCards = simCards,
            cellCountryCode = cellCountryCode,
            cellLookupSummary = cellLookupSummary,
            cellCandidatesCount = cellCandidatesCount,
            wifiAccessPointCandidatesCount = wifiAccessPointCandidatesCount,
            bssid = bssid,
            cellLookupPermissionGranted = cellLookupPermissionGranted,
            wifiPermissionGranted = wifiPermissionGranted,
            locationServicesEnabled = locationServicesEnabled,
            telephonyRadioAccessAvailable = telephonyRadioAccessAvailable,
            wifiFeatureAvailable = wifiFeatureAvailable,
            nearbyWifiPermissionGranted = nearbyWifiPermissionGranted,
            networkRequestsEnabled = networkRequestsEnabled,
            cellRawInfoCount = cellRawInfoCount,
            cellRawInfoTypes = cellRawInfoTypes,
            cellCandidateRadios = cellCandidateRadios,
            beaconDbCellCandidatesUsedCount = beaconDbCellCandidatesUsedCount,
            beaconDbUnsupportedCellRadios = beaconDbUnsupportedCellRadios,
            beaconDbWifiCandidatesUsedCount = beaconDbWifiCandidatesUsedCount,
            wifiCachedScanCandidatesCount = wifiCachedScanCandidatesCount,
            wifiFreshScanCandidatesCount = wifiFreshScanCandidatesCount,
            wifiConnectedCandidateAvailable = wifiConnectedCandidateAvailable,
            bssidSource = bssidSource,
            bssidUnavailableReason = bssidUnavailableReason,
        )
    }

    private fun wifi(
        mac: String,
        signalStrength: Int,
    ) = WifiLookupCandidate(
        macAddress = mac,
        frequency = 2412,
        signalStrength = signalStrength,
    )
}
