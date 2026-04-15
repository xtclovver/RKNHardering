package com.notcvnt.rknhardering

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.core.content.ContextCompat
import androidx.core.text.BidiFormatter
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isNotEmpty
import androidx.core.view.isVisible
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.notcvnt.rknhardering.checker.BypassChecker
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

fun maskIp(ip: String): String {
    val normalized = ip.trim()
    val parsed = when {
        normalized.contains('.') -> {
            val parts = normalized.split('.')
            if (parts.size != 4 || parts.any { (it.toIntOrNull() ?: -1) !in 0..255 }) {
                return "*.*.*.*"
            }
            runCatching { InetAddress.getByName(normalized) }.getOrNull()
        }
        normalized.contains(':') -> runCatching { InetAddress.getByName(normalized) }.getOrNull()
        else -> null
    } ?: return "*.*.*.*"
    return when (parsed) {
        is Inet4Address -> {
            if (parsed.isSiteLocalAddress || parsed.isLoopbackAddress || parsed.isLinkLocalAddress) {
                normalized
            } else {
                val bytes = parsed.address.map { it.toInt() and 0xff }
                "${bytes[0]}.${bytes[1]}.*.*"
            }
        }
        is Inet6Address -> {
            if (parsed.isLoopbackAddress || parsed.isLinkLocalAddress || isUniqueLocalIpv6(parsed)) {
                normalized
            } else {
                val groups = parsed.hostAddress?.substringBefore('%')?.split(':').orEmpty()
                if (groups.size < 4) {
                    "*:*:*:*"
                } else {
                    groups.take(4).joinToString(":") + ":*:*:*:*"
                }
            }
        }
        else -> "*.*.*.*"
    }
}

fun maskIpsInText(text: String): String {
    val ipv4Regex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    val maskedIpv4 = ipv4Regex.replace(text) { match ->
        maskIp(match.value)
    }
    val ipv6Regex = Regex("""(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9])""")
    return ipv6Regex.replace(maskedIpv4) { match ->
        maskIp(match.value.trim('[', ']'))
    }
}

private fun isUniqueLocalIpv6(address: Inet6Address): Boolean {
    val firstByte = address.address.firstOrNull()?.toInt()?.and(0xff) ?: return false
    return (firstByte and 0xfe) == 0xfc
}

class MainActivity : AppCompatActivity() {

    private enum class RunningStage {
        GEO_IP,
        IP_COMPARISON,
        DIRECT,
        INDIRECT,
        LOCATION,
        BYPASS,
    }

    private lateinit var btnRunCheck: MaterialButton
    private lateinit var btnStopCheck: MaterialButton
    private lateinit var cardRunCheckNotice: MaterialCardView
    private lateinit var resultsScrollView: TouchAwareScrollView
    private lateinit var textCheckStatus: TextView
    private lateinit var viewModel: CheckViewModel
    private var hasDismissedRunCheckNotice = false
    private var processedEventCount = 0
    private lateinit var cardGeoIp: MaterialCardView
    private lateinit var cardIpComparison: MaterialCardView
    private lateinit var cardDirect: MaterialCardView
    private lateinit var cardIndirect: MaterialCardView
    private lateinit var cardLocation: MaterialCardView
    private lateinit var cardVerdict: MaterialCardView
    private lateinit var iconGeoIp: ImageView
    private lateinit var iconIpComparison: ImageView
    private lateinit var iconDirect: ImageView
    private lateinit var iconIndirect: ImageView
    private lateinit var iconLocation: ImageView
    private lateinit var statusGeoIp: TextView
    private lateinit var statusIpComparison: TextView
    private lateinit var statusDirect: TextView
    private lateinit var statusIndirect: TextView
    private lateinit var statusLocation: TextView
    private lateinit var textIpComparisonSummary: TextView
    private lateinit var findingsGeoIp: LinearLayout
    private lateinit var ipComparisonGroups: LinearLayout
    private lateinit var findingsDirect: LinearLayout
    private lateinit var findingsIndirect: LinearLayout
    private lateinit var findingsLocation: LinearLayout
    private lateinit var cardBypass: MaterialCardView
    private lateinit var iconBypass: ImageView
    private lateinit var statusBypass: TextView
    private lateinit var textBypassProgress: TextView
    private lateinit var findingsBypass: LinearLayout
    private lateinit var iconVerdict: ImageView
    private lateinit var textVerdict: TextView
    private lateinit var textVerdictExplanation: TextView
    private lateinit var btnVerdictDetails: MaterialButton
    private lateinit var verdictDetailsDivider: View
    private lateinit var verdictDetailsContent: LinearLayout
    private lateinit var geoIpInfoSection: LinearLayout
    private lateinit var geoIpDivider: View
    private lateinit var locationInfoSection: LinearLayout
    private lateinit var locationDivider: View
    private lateinit var directInfoSection: LinearLayout
    private lateinit var directDivider: View
    private val bypassProgressLines = linkedMapOf<BypassChecker.ProgressLine, String>()
    private val bypassProgressOrder = listOf(
        BypassChecker.ProgressLine.BYPASS,
        BypassChecker.ProgressLine.XRAY_API,
        BypassChecker.ProgressLine.UNDERLYING_NETWORK,
    )
    private val loadingStages = linkedSetOf<RunningStage>()
    private val completedStages = mutableSetOf<RunningStage>()
    private var loadingStatusJob: Job? = null
    private var loadingAnimationFrame = 0
    private var hasUserScrolledManually = false
    private var userTouchScrollInProgress = false
    private var isAutoScrollInProgress = false
    private var activeCheckPrivacyMode = false
    private var isVerdictDetailsExpanded = false

    private val prefs by lazy { AppUiSettings.prefs(this) }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        markPermissionsRequested(result.keys)
        prefs.edit { putBoolean(PREF_RATIONALE_SHOWN, true) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        AppUiSettings.applySavedTheme(this)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setOnMenuItemClickListener { menuItem ->
            when (menuItem.itemId) {
                R.id.action_settings -> {
                    startActivity(Intent(this, SettingsActivity::class.java))
                    true
                }
                else -> false
            }
        }

        viewModel = ViewModelProvider(this)[CheckViewModel::class.java]
        bindViews()
        hasDismissedRunCheckNotice = savedInstanceState?.getBoolean(STATE_RUN_CHECK_NOTICE_HIDDEN, false) ?: false
        updateRunCheckNoticeVisibility()

        btnRunCheck.setOnClickListener { onRunCheckClicked() }
        btnStopCheck.setOnClickListener { viewModel.cancelScan() }
        observeScanEvents()

        if (intent.getBooleanExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS, false)) {
            intent.removeExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS)
            reRequestPermissions()
        } else if (!prefs.getBoolean(PREF_RATIONALE_SHOWN, false)) {
            showPermissionRationale()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS, false)) {
            reRequestPermissions()
        }
    }

    private fun bindViews() {
        resultsScrollView = findViewById(R.id.resultsScrollView)
        btnRunCheck = findViewById(R.id.btnRunCheck)
        btnStopCheck = findViewById(R.id.btnStopCheck)
        cardRunCheckNotice = findViewById(R.id.cardRunCheckNotice)
        textCheckStatus = findViewById(R.id.textCheckStatus)
        cardGeoIp = findViewById(R.id.cardGeoIp)
        cardIpComparison = findViewById(R.id.cardIpComparison)
        cardDirect = findViewById(R.id.cardDirect)
        cardIndirect = findViewById(R.id.cardIndirect)
        cardLocation = findViewById(R.id.cardLocation)
        cardVerdict = findViewById(R.id.cardVerdict)
        iconGeoIp = findViewById(R.id.iconGeoIp)
        iconIpComparison = findViewById(R.id.iconIpComparison)
        iconDirect = findViewById(R.id.iconDirect)
        iconIndirect = findViewById(R.id.iconIndirect)
        iconLocation = findViewById(R.id.iconLocation)
        statusGeoIp = findViewById(R.id.statusGeoIp)
        statusIpComparison = findViewById(R.id.statusIpComparison)
        statusDirect = findViewById(R.id.statusDirect)
        statusIndirect = findViewById(R.id.statusIndirect)
        statusLocation = findViewById(R.id.statusLocation)
        textIpComparisonSummary = findViewById(R.id.textIpComparisonSummary)
        findingsGeoIp = findViewById(R.id.findingsGeoIp)
        ipComparisonGroups = findViewById(R.id.ipComparisonGroups)
        findingsDirect = findViewById(R.id.findingsDirect)
        findingsIndirect = findViewById(R.id.findingsIndirect)
        findingsLocation = findViewById(R.id.findingsLocation)
        cardBypass = findViewById(R.id.cardBypass)
        iconBypass = findViewById(R.id.iconBypass)
        statusBypass = findViewById(R.id.statusBypass)
        textBypassProgress = findViewById(R.id.textBypassProgress)
        findingsBypass = findViewById(R.id.findingsBypass)
        iconVerdict = findViewById(R.id.iconVerdict)
        textVerdict = findViewById(R.id.textVerdict)
        textVerdictExplanation = findViewById(R.id.textVerdictExplanation)
        btnVerdictDetails = findViewById(R.id.btnVerdictDetails)
        verdictDetailsDivider = findViewById(R.id.verdictDetailsDivider)
        verdictDetailsContent = findViewById(R.id.verdictDetailsContent)
        geoIpInfoSection = findViewById(R.id.geoIpInfoSection)
        geoIpDivider = findViewById(R.id.geoIpDivider)
        locationInfoSection = findViewById(R.id.locationInfoSection)
        locationDivider = findViewById(R.id.locationDivider)
        directInfoSection = findViewById(R.id.directInfoSection)
        directDivider = findViewById(R.id.directDivider)
        btnVerdictDetails.setOnClickListener { toggleVerdictDetails() }
        setupResultsScrollTracking()
        updateCheckControls(isRunning = false)
    }

    private fun setupResultsScrollTracking() {
        resultsScrollView.onUserTouchChanged = { isTouching ->
            userTouchScrollInProgress = isTouching
        }
        resultsScrollView.setOnScrollChangeListener { _, _, _, _, _ ->
            if (userTouchScrollInProgress && !isAutoScrollInProgress) {
                hasUserScrolledManually = true
            }
        }
    }

    private fun requiredPermissions(): Array<String> {
        return buildList {
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
            if (shouldRequestPhoneStatePermission()) {
                add(Manifest.permission.READ_PHONE_STATE)
            }
        }.toTypedArray()
    }

    private fun showPermissionRationale(permissions: Array<String> = requiredPermissions()) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.main_perm_title))
            .setMessage(permissionRationaleMessage())
            .setPositiveButton(getString(R.string.main_perm_allow)) { _, _ ->
                launchPermissionRequest(permissions)
            }
            .setNegativeButton(getString(R.string.main_perm_skip)) { _, _ ->
                prefs.edit { putBoolean(PREF_RATIONALE_SHOWN, true) }
            }
            .setCancelable(false)
            .show()
    }

    private fun shouldRequestPhoneStatePermission(): Boolean {
        return packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY) ||
            packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION)
    }

    private fun permissionRationaleMessage(): String {
        val detailLines = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(getString(R.string.main_perm_rationale_wifi_13))
            } else {
                add(getString(R.string.main_perm_rationale_wifi))
            }
            if (shouldRequestPhoneStatePermission()) {
                add(getString(R.string.main_perm_rationale_phone_state))
            }
        }
        return getString(R.string.main_perm_rationale, detailLines.joinToString("\n\n"))
    }

    internal fun reRequestPermissions() {
        val missingPermissions = requiredPermissions().filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missingPermissions.isEmpty()) {
            Toast.makeText(this, getString(R.string.main_perm_all_granted), Toast.LENGTH_SHORT).show()
            return
        }

        val action = PermissionRequestPlanner.decideAction(
            missingPermissions.map { permission ->
                PermissionRequestPlanner.PermissionState(
                    permission = permission,
                    shouldShowRationale = shouldShowRequestPermissionRationale(permission),
                    wasRequestedBefore = hasPermissionBeenRequested(permission),
                )
            },
        )
        when (action) {
            PermissionRequestPlanner.Action.NONE -> Unit
            PermissionRequestPlanner.Action.SHOW_RATIONALE -> {
                showPermissionRationale(missingPermissions.toTypedArray())
            }
            PermissionRequestPlanner.Action.REQUEST -> {
                launchPermissionRequest(missingPermissions.toTypedArray())
            }
            PermissionRequestPlanner.Action.OPEN_SETTINGS -> {
                Toast.makeText(
                    this,
                    getString(R.string.main_perm_blocked),
                    Toast.LENGTH_LONG,
                ).show()
                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.fromParts("package", packageName, null)
                }
                startActivity(intent)
            }
        }
    }

    private fun launchPermissionRequest(permissions: Array<String>) {
        if (permissions.isEmpty()) return
        markPermissionsRequested(permissions.asList())
        permissionLauncher.launch(permissions)
    }

    private fun markPermissionsRequested(permissions: Collection<String>) {
        val requested = prefs.getStringSet(PREF_REQUESTED_PERMISSIONS, emptySet())
            ?.toMutableSet()
            ?: mutableSetOf()
        requested.addAll(permissions)
        prefs.edit { putStringSet(PREF_REQUESTED_PERMISSIONS, requested) }
    }

    private fun hasPermissionBeenRequested(permission: String): Boolean {
        return prefs.getStringSet(PREF_REQUESTED_PERMISSIONS, emptySet())
            ?.contains(permission) == true
    }

    private fun onRunCheckClicked() {
        if (viewModel.isRunning.value) return
        hasDismissedRunCheckNotice = true
        updateRunCheckNoticeVisibility()
        runCheck()
    }

    private fun updateRunCheckNoticeVisibility() {
        cardRunCheckNotice.visibility = if (hasDismissedRunCheckNotice) View.GONE else View.VISIBLE
    }

    private fun updateCheckControls(isRunning: Boolean) {
        val runButtonBackgroundAttr = if (isRunning) {
            com.google.android.material.R.attr.colorPrimaryContainer
        } else {
            com.google.android.material.R.attr.colorPrimary
        }
        val runButtonForegroundAttr = if (isRunning) {
            com.google.android.material.R.attr.colorOnPrimaryContainer
        } else {
            com.google.android.material.R.attr.colorOnPrimary
        }
        val runButtonBackground = MaterialColors.getColor(btnRunCheck, runButtonBackgroundAttr)
        val runButtonForeground = MaterialColors.getColor(btnRunCheck, runButtonForegroundAttr)

        btnRunCheck.isEnabled = !isRunning
        btnRunCheck.isClickable = !isRunning
        btnRunCheck.isFocusable = !isRunning
        btnRunCheck.alpha = if (isRunning) 0.72f else 1.0f
        btnRunCheck.backgroundTintList = ColorStateList.valueOf(runButtonBackground)
        btnRunCheck.setTextColor(runButtonForeground)
        btnRunCheck.iconTint = ColorStateList.valueOf(runButtonForeground)

        btnStopCheck.visibility = if (isRunning) View.VISIBLE else View.GONE
        if (isRunning) {
            updateCheckStatus(getString(R.string.main_check_running))
        } else if (textCheckStatus.text != checkStatusStopped()) {
            updateCheckStatus(null)
        }
    }

    private fun checkStatusStopped(): String = getString(R.string.main_check_stopped)

    private fun updateCheckStatus(message: String?) {
        textCheckStatus.text = message.orEmpty()
        textCheckStatus.visibility = if (message.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    private fun runCheck() {
        val splitTunnelEnabled = prefs.getBoolean(SettingsActivity.PREF_SPLIT_TUNNEL_ENABLED, true)
        val proxyScanEnabled = prefs.getBoolean(SettingsActivity.PREF_PROXY_SCAN_ENABLED, true)
        val xrayApiScanEnabled = prefs.getBoolean(SettingsActivity.PREF_XRAY_API_SCAN_ENABLED, true)
        val networkRequestsEnabled = prefs.getBoolean(SettingsActivity.PREF_NETWORK_REQUESTS_ENABLED, true)
        val callTransportProbeEnabled = prefs.getBoolean(SettingsActivity.PREF_CALL_TRANSPORT_PROBE_ENABLED, false)
        val privacyMode = prefs.getBoolean(SettingsActivity.PREF_PRIVACY_MODE, false)
        val portRange = prefs.getString(SettingsActivity.PREF_PORT_RANGE, "full") ?: "full"
        val portRangeStart = prefs.getInt(SettingsActivity.PREF_PORT_RANGE_START, 1024)
        val portRangeEnd = prefs.getInt(SettingsActivity.PREF_PORT_RANGE_END, 65535)
        val resolverConfig = DnsResolverConfig.fromPrefs(
            prefs = prefs,
            modePref = SettingsActivity.PREF_DNS_RESOLVER_MODE,
            presetPref = SettingsActivity.PREF_DNS_RESOLVER_PRESET,
            directServersPref = SettingsActivity.PREF_DNS_RESOLVER_DIRECT_SERVERS,
            dohUrlPref = SettingsActivity.PREF_DNS_RESOLVER_DOH_URL,
            dohBootstrapPref = SettingsActivity.PREF_DNS_RESOLVER_DOH_BOOTSTRAP,
        )

        val settings = CheckSettings(
            splitTunnelEnabled = splitTunnelEnabled,
            proxyScanEnabled = proxyScanEnabled,
            xrayApiScanEnabled = xrayApiScanEnabled,
            networkRequestsEnabled = networkRequestsEnabled,
            callTransportProbeEnabled = callTransportProbeEnabled,
            resolverConfig = resolverConfig,
            portRange = portRange,
            portRangeStart = portRangeStart,
            portRangeEnd = portRangeEnd,
        )

        viewModel.startScan(settings, privacyMode)
    }

    private fun observeScanEvents() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.scanEvents.collect { events ->
                    if (events.isEmpty()) return@collect

                    val firstEvent = events.first()
                    val isNewScan = firstEvent is ScanEvent.Started &&
                        (processedEventCount == 0 || events.size <= processedEventCount)
                    if (isNewScan) {
                        prepareCheckSessionUi(
                            (firstEvent as ScanEvent.Started).settings,
                            firstEvent.privacyMode,
                        )
                        processedEventCount = 1
                        events.drop(1).forEach { event ->
                            applyScanEvent(event, animate = false)
                            processedEventCount++
                        }
                    } else if (events.size > processedEventCount) {
                        events.drop(processedEventCount).forEach { event ->
                            applyScanEvent(event, animate = true)
                            processedEventCount++
                        }
                    }
                }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.isRunning.collect { running ->
                    updateCheckControls(isRunning = running)
                }
            }
        }
    }

    private fun prepareCheckSessionUi(settings: CheckSettings, privacyMode: Boolean) {
        activeCheckPrivacyMode = privacyMode
        hasUserScrolledManually = false
        userTouchScrollInProgress = false
        isAutoScrollInProgress = false
        loadingStages.clear()
        completedStages.clear()
        stopLoadingStatusAnimation()
        hideCards()
        resetBypassProgress()
        clearStageContent()
        showAllLoadingCardsNow(settings)
    }

    private fun showAllLoadingCardsNow(settings: CheckSettings) {
        enabledStages(settings).forEach { stage -> showLoadingCardForStage(stage) }
    }

    private fun applyScanEvent(event: ScanEvent, animate: Boolean) {
        when (event) {
            is ScanEvent.Started -> Unit
            is ScanEvent.Update -> {
                handleCheckUpdate(event.update, animate = animate)
            }
            is ScanEvent.Completed -> {
                ensureCardVisible(cardVerdict, shouldAutoScroll = animate)
                displayVerdict(event.result, event.privacyMode)
                if (animate) animateContentReveal(iconVerdict, textVerdict, textVerdictExplanation, btnVerdictDetails)
                stopLoadingStatusAnimation()
            }
            is ScanEvent.Cancelled -> {
                resetBypassProgress()
                statusBypass.text = getString(R.string.main_status_cancelled)
                statusBypass.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
                stopLoadingStatusAnimation()
                updateCheckStatus(getString(R.string.main_check_stopped))
                markLoadingStagesCancelled()
            }
        }
    }

    private fun clearStageContent() {
        geoIpInfoSection.removeAllViews()
        geoIpInfoSection.visibility = View.GONE
        geoIpDivider.visibility = View.GONE
        findingsGeoIp.removeAllViews()

        textIpComparisonSummary.text = ""
        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.visibility = View.GONE

        directInfoSection.removeAllViews()
        directInfoSection.visibility = View.GONE
        directDivider.visibility = View.GONE
        findingsDirect.removeAllViews()
        findingsIndirect.removeAllViews()

        locationInfoSection.removeAllViews()
        locationInfoSection.visibility = View.GONE
        locationDivider.visibility = View.GONE
        findingsLocation.removeAllViews()

        findingsBypass.removeAllViews()
        findingsBypass.visibility = View.GONE

        clearVerdictCard()
    }

    private fun enabledStages(settings: CheckSettings): List<RunningStage> {
        val stages = mutableListOf<RunningStage>()
        if (settings.networkRequestsEnabled) {
            stages += RunningStage.GEO_IP
            stages += RunningStage.IP_COMPARISON
        }
        stages += RunningStage.DIRECT
        stages += RunningStage.INDIRECT
        stages += RunningStage.LOCATION
        if (settings.splitTunnelEnabled) {
            stages += RunningStage.BYPASS
        }
        return stages
    }

    private fun handleCheckUpdate(update: CheckUpdate, animate: Boolean = true) {
        when (update) {
            is CheckUpdate.GeoIpReady -> {
                markStageCompleted(RunningStage.GEO_IP)
                ensureCardVisible(cardGeoIp, animate = false)
                displayCategory(
                    update.result,
                    cardGeoIp,
                    iconGeoIp,
                    statusGeoIp,
                    findingsGeoIp,
                    activeCheckPrivacyMode,
                )
                if (animate) animateContentReveal(findingsGeoIp, geoIpInfoSection, geoIpDivider)
            }
            is CheckUpdate.IpComparisonReady -> {
                markStageCompleted(RunningStage.IP_COMPARISON)
                ensureCardVisible(cardIpComparison, animate = false)
                displayIpComparison(update.result, activeCheckPrivacyMode)
                if (animate) animateContentReveal(textIpComparisonSummary, ipComparisonGroups)
            }
            is CheckUpdate.DirectSignsReady -> {
                markStageCompleted(RunningStage.DIRECT)
                ensureCardVisible(cardDirect, animate = false)
                displayCategory(
                    update.result,
                    cardDirect,
                    iconDirect,
                    statusDirect,
                    findingsDirect,
                    activeCheckPrivacyMode,
                )
                if (animate) animateContentReveal(findingsDirect, directInfoSection, directDivider)
            }
            is CheckUpdate.IndirectSignsReady -> {
                markStageCompleted(RunningStage.INDIRECT)
                ensureCardVisible(cardIndirect, animate = false)
                displayCategory(
                    update.result,
                    cardIndirect,
                    iconIndirect,
                    statusIndirect,
                    findingsIndirect,
                    activeCheckPrivacyMode,
                )
                if (animate) animateContentReveal(findingsIndirect)
            }
            is CheckUpdate.LocationSignalsReady -> {
                markStageCompleted(RunningStage.LOCATION)
                ensureCardVisible(cardLocation, animate = false)
                displayCategory(
                    update.result,
                    cardLocation,
                    iconLocation,
                    statusLocation,
                    findingsLocation,
                    activeCheckPrivacyMode,
                )
                if (animate) animateContentReveal(findingsLocation, locationInfoSection, locationDivider)
            }
            is CheckUpdate.BypassProgress -> {
                showLoadingCardForStage(RunningStage.BYPASS)
                updateBypassProgress(update.progress)
            }
            is CheckUpdate.BypassReady -> {
                markStageCompleted(RunningStage.BYPASS)
                ensureCardVisible(cardBypass, animate = false)
                displayBypass(update.result, activeCheckPrivacyMode)
                if (animate) animateContentReveal(findingsBypass)
            }
            is CheckUpdate.VerdictReady -> {
                Unit
            }
        }
    }

    private fun showLoadingCardForStage(stage: RunningStage) {
        if (stage in completedStages) return
        if (stage in loadingStages && cardForStage(stage).isVisible) return

        loadingStages += stage
        when (stage) {
            RunningStage.GEO_IP -> showCategoryLoading(
                stage = stage,
                card = cardGeoIp,
                icon = iconGeoIp,
                status = statusGeoIp,
                findingsContainer = findingsGeoIp,
                hint = stageLoadingMessage(stage),
                infoSection = geoIpInfoSection,
                infoDivider = geoIpDivider,
            )
            RunningStage.IP_COMPARISON -> showIpComparisonLoading(stage)
            RunningStage.DIRECT -> showCategoryLoading(
                stage = stage,
                card = cardDirect,
                icon = iconDirect,
                status = statusDirect,
                findingsContainer = findingsDirect,
                hint = stageLoadingMessage(stage),
                infoSection = directInfoSection,
                infoDivider = directDivider,
            )
            RunningStage.INDIRECT -> showCategoryLoading(
                stage = stage,
                card = cardIndirect,
                icon = iconIndirect,
                status = statusIndirect,
                findingsContainer = findingsIndirect,
                hint = stageLoadingMessage(stage),
            )
            RunningStage.LOCATION -> showCategoryLoading(
                stage = stage,
                card = cardLocation,
                icon = iconLocation,
                status = statusLocation,
                findingsContainer = findingsLocation,
                hint = stageLoadingMessage(stage),
                infoSection = locationInfoSection,
                infoDivider = locationDivider,
            )
            RunningStage.BYPASS -> showBypassLoading(stage)
        }
        syncLoadingStatusAnimation()
    }

    private fun showCategoryLoading(
        stage: RunningStage,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout,
        hint: String,
        infoSection: LinearLayout? = null,
        infoDivider: View? = null,
    ) {
        bindCardLoadingState(stage, icon, status)
        infoSection?.apply {
            removeAllViews()
            visibility = View.GONE
        }
        infoDivider?.visibility = View.GONE
        findingsContainer.removeAllViews()
        findingsContainer.addView(createLoadingHintView(hint))
        findingsContainer.visibility = View.VISIBLE
        ensureCardVisible(card)
    }

    private fun showIpComparisonLoading(stage: RunningStage) {
        bindCardLoadingState(stage, iconIpComparison, statusIpComparison)
        textIpComparisonSummary.text = stageLoadingMessage(stage)
        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.visibility = View.GONE
        ensureCardVisible(cardIpComparison)
    }

    private fun showBypassLoading(stage: RunningStage) {
        bindCardLoadingState(stage, iconBypass, statusBypass)
        findingsBypass.removeAllViews()
        findingsBypass.visibility = View.GONE
        if (bypassProgressLines.isEmpty()) {
            textBypassProgress.text = stageLoadingMessage(stage)
        }
        textBypassProgress.visibility = View.VISIBLE
        ensureCardVisible(cardBypass)
    }

    private fun markStageCompleted(stage: RunningStage) {
        completedStages += stage
        finalizeLoadingStage(stage)
    }

    private fun finalizeLoadingStage(stage: RunningStage) {
        loadingStages.remove(stage)
        syncLoadingStatusAnimation()
    }

    private fun markLoadingStagesCancelled() {
        loadingStages.toList().forEach { stage ->
            when (stage) {
                RunningStage.GEO_IP -> showCategoryStopped(
                    card = cardGeoIp,
                    icon = iconGeoIp,
                    status = statusGeoIp,
                    findingsContainer = findingsGeoIp,
                    message = stageStoppedMessage(stage),
                    infoSection = geoIpInfoSection,
                    infoDivider = geoIpDivider,
                )
                RunningStage.IP_COMPARISON -> showIpComparisonStopped(stage)
                RunningStage.DIRECT -> showCategoryStopped(
                    card = cardDirect,
                    icon = iconDirect,
                    status = statusDirect,
                    findingsContainer = findingsDirect,
                    message = stageStoppedMessage(stage),
                    infoSection = directInfoSection,
                    infoDivider = directDivider,
                )
                RunningStage.INDIRECT -> showCategoryStopped(
                    card = cardIndirect,
                    icon = iconIndirect,
                    status = statusIndirect,
                    findingsContainer = findingsIndirect,
                    message = stageStoppedMessage(stage),
                )
                RunningStage.LOCATION -> showCategoryStopped(
                    card = cardLocation,
                    icon = iconLocation,
                    status = statusLocation,
                    findingsContainer = findingsLocation,
                    message = stageStoppedMessage(stage),
                    infoSection = locationInfoSection,
                    infoDivider = locationDivider,
                )
                RunningStage.BYPASS -> showBypassStopped(stage)
            }
        }
        loadingStages.clear()
    }

    private fun showCategoryStopped(
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout,
        message: String,
        infoSection: LinearLayout? = null,
        infoDivider: View? = null,
    ) {
        icon.setImageResource(R.drawable.ic_help)
        status.text = getString(R.string.main_status_stopped)
        status.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        infoSection?.apply {
            removeAllViews()
            visibility = View.GONE
        }
        infoDivider?.visibility = View.GONE
        findingsContainer.removeAllViews()
        findingsContainer.addView(createLoadingHintView(message))
        findingsContainer.visibility = View.VISIBLE
        ensureCardVisible(card, animate = false)
    }

    private fun showIpComparisonStopped(stage: RunningStage) {
        iconIpComparison.setImageResource(R.drawable.ic_help)
        statusIpComparison.text = getString(R.string.main_status_stopped)
        statusIpComparison.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        textIpComparisonSummary.text = stageStoppedMessage(stage)
        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.visibility = View.GONE
        ensureCardVisible(cardIpComparison, animate = false)
    }

    private fun showBypassStopped(stage: RunningStage) {
        iconBypass.setImageResource(R.drawable.ic_help)
        statusBypass.text = getString(R.string.main_status_stopped)
        statusBypass.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        findingsBypass.removeAllViews()
        findingsBypass.visibility = View.GONE
        textBypassProgress.text = stageStoppedMessage(stage)
        textBypassProgress.visibility = View.VISIBLE
        ensureCardVisible(cardBypass, animate = false)
    }

    private fun bindCardLoadingState(stage: RunningStage, icon: ImageView, status: TextView) {
        icon.setImageResource(R.drawable.ic_help)
        status.text = stageLoadingStatusBase(stage)
        status.setTextColor(ContextCompat.getColor(this, R.color.md_on_surface_variant))
    }

    private fun syncLoadingStatusAnimation() {
        if (loadingStages.isEmpty()) {
            stopLoadingStatusAnimation()
            return
        }

        updateLoadingStatuses()
        if (loadingStatusJob?.isActive == true) return

        loadingStatusJob = lifecycleScope.launch {
            while (isActive && loadingStages.isNotEmpty()) {
                delay(LOADING_STATUS_FRAME_MS)
                loadingAnimationFrame = (loadingAnimationFrame + 1) % 4
                updateLoadingStatuses()
            }
        }
    }

    private fun stopLoadingStatusAnimation() {
        loadingStatusJob?.cancel()
        loadingStatusJob = null
        loadingAnimationFrame = 0
    }

    private fun updateLoadingStatuses() {
        val dots = when (loadingAnimationFrame) {
            0 -> ""
            1 -> "."
            2 -> ".."
            else -> "..."
        }
        loadingStages.forEach { stage ->
            statusViewForStage(stage).text = getString(
                R.string.main_loading_status_progress,
                stageLoadingStatusBase(stage),
                dots,
            )
        }
    }

    private fun stageLoadingStatusBase(stage: RunningStage): String {
        return when (stage) {
            RunningStage.BYPASS -> getString(R.string.main_loading_status_scanning)
            else -> getString(R.string.main_loading_status_checking)
        }
    }

    private fun stageLoadingMessage(stage: RunningStage): String {
        return when (stage) {
            RunningStage.GEO_IP -> getString(R.string.main_loading_geo_ip)
            RunningStage.IP_COMPARISON -> getString(R.string.main_loading_ip_comparison)
            RunningStage.DIRECT -> getString(R.string.main_loading_direct)
            RunningStage.INDIRECT -> getString(R.string.main_loading_indirect)
            RunningStage.LOCATION -> getString(R.string.main_loading_location)
            RunningStage.BYPASS -> getString(R.string.main_loading_bypass)
        }
    }

    private fun stageStoppedMessage(stage: RunningStage): String {
        return when (stage) {
            RunningStage.BYPASS -> getString(R.string.main_stopped_scan)
            else -> getString(R.string.main_stopped_check)
        }
    }

    private fun cardForStage(stage: RunningStage): MaterialCardView {
        return when (stage) {
            RunningStage.GEO_IP -> cardGeoIp
            RunningStage.IP_COMPARISON -> cardIpComparison
            RunningStage.DIRECT -> cardDirect
            RunningStage.INDIRECT -> cardIndirect
            RunningStage.LOCATION -> cardLocation
            RunningStage.BYPASS -> cardBypass
        }
    }

    private fun statusViewForStage(stage: RunningStage): TextView {
        return when (stage) {
            RunningStage.GEO_IP -> statusGeoIp
            RunningStage.IP_COMPARISON -> statusIpComparison
            RunningStage.DIRECT -> statusDirect
            RunningStage.INDIRECT -> statusIndirect
            RunningStage.LOCATION -> statusLocation
            RunningStage.BYPASS -> statusBypass
        }
    }

    private fun ensureCardVisible(
        card: MaterialCardView,
        animate: Boolean = true,
        shouldAutoScroll: Boolean = false,
    ) {
        val wasVisible = card.isVisible
        if (!wasVisible) {
            card.animate().cancel()
            card.visibility = View.VISIBLE
            if (animate) {
                card.alpha = 0f
                card.translationY = 12.dp.toFloat()
                card.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setDuration(220L)
                    .withEndAction {
                        if (shouldAutoScroll && !hasUserScrolledManually) {
                            scrollToCard(card)
                        }
                    }
                    .start()
            } else {
                card.alpha = 1f
                card.translationY = 0f
                if (shouldAutoScroll && !hasUserScrolledManually) {
                    scrollToCard(card)
                }
            }
            return
        }

        if (shouldAutoScroll && !hasUserScrolledManually) {
            scrollToCard(card)
        }
    }

    private fun scrollToCard(card: View) {
        isAutoScrollInProgress = true
        resultsScrollView.post {
            val targetY = (card.top - 12.dp).coerceAtLeast(0)
            resultsScrollView.smoothScrollTo(0, targetY)
            resultsScrollView.postDelayed(
                { isAutoScrollInProgress = false },
                AUTO_SCROLL_LOCK_MS,
            )
        }
    }

    private fun animateContentReveal(vararg views: View) {
        views.forEach { view ->
            if (view.visibility != View.VISIBLE) return@forEach
            view.animate().cancel()
            view.alpha = 0f
            view.translationY = 6.dp.toFloat()
            view.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(180L)
                .start()
        }
    }

    private fun createLoadingHintView(message: String): View {
        return TextView(this).apply {
            text = message
            textSize = 13f
            setLineSpacing(2.dp.toFloat(), 1f)
            setPadding(0, 8.dp, 0, 2.dp)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }
    }

    private fun hideCards() {
        listOf(
            cardGeoIp,
            cardIpComparison,
            cardDirect,
            cardIndirect,
            cardLocation,
            cardBypass,
            cardVerdict,
        ).forEach { card ->
            card.animate().cancel()
            card.alpha = 1f
            card.translationY = 0f
            card.visibility = View.GONE
        }
    }

    private fun displayCategory(
        category: CategoryResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout,
        privacyMode: Boolean = false,
    ) {
        card.visibility = View.VISIBLE
        findingsContainer.visibility = View.VISIBLE

        bindCardStatus(category.detected, category.needsReview, icon, status, hasError = category.hasError)

        val infoSection = when (card.id) {
            R.id.cardGeoIp -> geoIpInfoSection
            R.id.cardLocation -> locationInfoSection
            R.id.cardDirect -> directInfoSection
            else -> null
        }
        val infoDivider = when (card.id) {
            R.id.cardGeoIp -> geoIpDivider
            R.id.cardLocation -> locationDivider
            R.id.cardDirect -> directDivider
            else -> null
        }

        if (infoSection != null && infoDivider != null) {
            val infoFindings = category.findings.filter { it.isInformational }
            val checkFindings = category.findings.filterNot { it.isInformational }

            bindInfoSection(infoFindings, infoSection, infoDivider, checkFindings.isNotEmpty(), privacyMode)
            findingsContainer.removeAllViews()
            for (finding in checkFindings) {
                if (finding.description.startsWith("network_mcc_ru:")) continue
                findingsContainer.addView(createFindingView(finding, privacyMode))
            }
            return
        }

        findingsContainer.removeAllViews()
        for (finding in category.findings) {
            if (finding.description.startsWith("network_mcc_ru:")) continue
            findingsContainer.addView(createFindingView(finding, privacyMode))
        }
    }

    private fun bindInfoSection(
        infoFindings: List<Finding>,
        infoSection: LinearLayout,
        infoDivider: View,
        hasCheckFindings: Boolean,
        privacyMode: Boolean,
    ) {
        infoSection.removeAllViews()
        infoSection.visibility = if (infoFindings.isNotEmpty()) View.VISIBLE else View.GONE
        for (finding in infoFindings) {
            val parts = splitInfoFinding(finding.description)
            if (parts != null) {
                val value = if (privacyMode && parts.first.equals("IP", ignoreCase = true)) {
                    maskIp(parts.second)
                } else {
                    parts.second
                }
                infoSection.addView(createInfoView(parts.first, value))
            } else {
                infoSection.addView(createFindingView(finding, privacyMode))
            }
        }
        infoDivider.visibility = if (infoFindings.isNotEmpty() && hasCheckFindings) View.VISIBLE else View.GONE
    }

    private fun displayIpComparison(result: IpComparisonResult, privacyMode: Boolean = false) {
        cardIpComparison.visibility = View.VISIBLE
        bindCardStatus(result.detected, result.needsReview, iconIpComparison, statusIpComparison)
        textIpComparisonSummary.text = if (privacyMode) maskIpsInText(result.summary) else result.summary

        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.visibility = View.VISIBLE
        ipComparisonGroups.addView(
            createIpCheckerGroupView(
                group = result.ruGroup,
                expanded = result.detected || result.needsReview || result.ruGroup.needsReview,
                privacyMode = privacyMode,
            ),
        )
        ipComparisonGroups.addView(
            createIpCheckerGroupView(
                group = result.nonRuGroup,
                expanded = result.detected || result.needsReview || result.nonRuGroup.detected,
                privacyMode = privacyMode,
            ),
        )
    }

    private fun createFindingView(finding: Finding, privacyMode: Boolean = false): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val indicator = TextView(this).apply {
            text = when {
                finding.detected -> "\u26A0"
                finding.needsReview -> "?"
                else -> "\u2713"
            }
            setTextColor(
                ContextCompat.getColor(
                    this@MainActivity,
                    when {
                        finding.detected -> R.color.finding_detected
                        finding.needsReview -> R.color.verdict_yellow
                        else -> R.color.finding_ok
                    },
                ),
            )
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
        }

        val descriptionText = if (privacyMode) maskIpsInText(finding.description) else finding.description
        val description = TextView(this).apply {
            text = wrapForDisplay(descriptionText)
            textSize = 13f
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = View.TEXT_ALIGNMENT_VIEW_START
        }

        row.addView(indicator)
        row.addView(description)
        return row
    }

    private fun createInfoView(label: String, value: String): View {
        val rtl = isRtlLayout()
        val row = LinearLayout(this).apply {
            orientation = if (rtl) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
            gravity = if (rtl) Gravity.END else Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, if (rtl) 6.dp else 4.dp)
        }

        val labelView = TextView(this).apply {
            text = wrapForDisplay(label)
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = !rtl
            letterSpacing = 0.05f
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
            layoutParams = if (rtl) {
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                )
            } else {
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.38f)
            }
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = if (rtl) View.TEXT_ALIGNMENT_VIEW_END else View.TEXT_ALIGNMENT_VIEW_START
        }

        val valueView = TextView(this).apply {
            text = wrapForDisplay(value)
            textSize = 13f
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            if (tv.resourceId != 0) {
                setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            } else if (tv.type >= TypedValue.TYPE_FIRST_COLOR_INT && tv.type <= TypedValue.TYPE_LAST_COLOR_INT) {
                setTextColor(tv.data)
            }
            layoutParams = if (rtl) {
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply {
                    topMargin = 2.dp
                }
            } else {
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.62f)
            }
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = if (rtl) View.TEXT_ALIGNMENT_VIEW_END else View.TEXT_ALIGNMENT_VIEW_START
        }

        row.addView(labelView)
        row.addView(valueView)
        return row
    }

    private fun splitInfoFinding(description: String): Pair<String, String>? {
        val separatorIndex = sequenceOf(
            description.indexOf(": "),
            description.indexOf('：'),
            description.indexOf(':'),
        ).filter { it >= 0 }.minOrNull() ?: return null
        val separatorLength = when {
            description.startsWith(": ", separatorIndex) -> 2
            else -> 1
        }
        val label = description.substring(0, separatorIndex).trim()
        val value = description.substring(separatorIndex + separatorLength).trim()
        if (label.isBlank() || value.isBlank()) return null
        return label to value
    }

    private fun wrapForDisplay(text: String): String {
        return if (isRtlLayout()) {
            BidiFormatter.getInstance(true).unicodeWrap(text)
        } else {
            text
        }
    }

    private fun isRtlLayout(): Boolean = resources.configuration.layoutDirection == View.LAYOUT_DIRECTION_RTL

    private fun createIpCheckerGroupView(
        group: IpCheckerGroupResult,
        expanded: Boolean,
        privacyMode: Boolean = false,
    ): View {
        val card = MaterialCardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = 8.dp
            }
            radius = 14.dp.toFloat()
            strokeWidth = 1.dp
            strokeColor = ContextCompat.getColor(this@MainActivity, R.color.md_outline_variant)
            setCardBackgroundColor(ContextCompat.getColor(this@MainActivity, R.color.md_surface))
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(12.dp, 12.dp, 12.dp, 12.dp)
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val title = TextView(this).apply {
            text = group.title
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val status = TextView(this).apply {
            text = group.statusLabel
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(this@MainActivity, statusColorRes(group.detected, group.needsReview)))
        }

        val toggle = TextView(this).apply {
            text = if (expanded) "▼" else "▶"
            textSize = 12f
            setPadding(8.dp, 0, 0, 0)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }

        val summary = TextView(this).apply {
            text = if (privacyMode) maskIpsInText(group.summary) else group.summary
            textSize = 13f
            setPadding(0, 6.dp, 0, 0)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }

        val details = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = if (expanded) View.VISIBLE else View.GONE
            setPadding(0, 8.dp, 0, 0)
        }
        group.responses.forEach { response ->
            details.addView(createIpCheckerResponseView(response, privacyMode))
        }

        header.addView(title)
        header.addView(status)
        header.addView(toggle)

        val toggleDetails = {
            val nextExpanded = details.visibility != View.VISIBLE
            details.visibility = if (nextExpanded) View.VISIBLE else View.GONE
            toggle.text = if (nextExpanded) "▼" else "▶"
        }
        header.setOnClickListener { toggleDetails() }
        summary.setOnClickListener { toggleDetails() }

        container.addView(header)
        container.addView(summary)
        container.addView(details)
        card.addView(container)
        return card
    }

    private fun createIpCheckerResponseView(response: IpCheckerResponse, privacyMode: Boolean = false): View {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 8.dp, 0, 8.dp)
        }

        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val label = TextView(this).apply {
            text = response.label
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val displayIp = if (privacyMode && response.ip != null) maskIp(response.ip) else response.ip
        val value = TextView(this).apply {
            text = displayIp ?: getString(R.string.main_card_status_error)
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(
                ContextCompat.getColor(
                    this@MainActivity,
                    if (response.ip != null) R.color.status_green else R.color.status_amber,
                ),
            )
        }

        val url = TextView(this).apply {
            text = response.url
            textSize = 12f
            setPadding(0, 4.dp, 0, 0)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }

        topRow.addView(label)
        topRow.addView(value)
        container.addView(topRow)
        container.addView(url)

        if (!response.error.isNullOrBlank()) {
            container.addView(
                TextView(this).apply {
                    text = buildString {
                        if (response.ignoredIpv6Error) {
                            append(getString(R.string.main_ipv6_error_ignored))
                        }
                        append(response.error)
                    }.let { if (privacyMode) maskIpsInText(it) else it }
                    textSize = 12f
                    setPadding(0, 2.dp, 0, 0)
                    setTextColor(
                        ContextCompat.getColor(
                            this@MainActivity,
                            if (response.ignoredIpv6Error) R.color.md_on_surface_variant else R.color.status_amber,
                        ),
                    )
                },
            )
        }

        return container
    }

    private fun displayBypass(bypass: BypassResult, privacyMode: Boolean = false) {
        cardBypass.visibility = View.VISIBLE
        resetBypassProgress()

        bindCardStatus(bypass.detected, bypass.needsReview, iconBypass, statusBypass)

        findingsBypass.removeAllViews()
        findingsBypass.visibility = View.VISIBLE
        for (finding in bypass.findings) {
            findingsBypass.addView(createFindingView(finding, privacyMode))
        }
    }

    private fun updateBypassProgress(progress: BypassChecker.Progress) {
        bypassProgressLines[progress.line] = "${progress.phase}: ${progress.detail}"
        renderBypassProgress()
    }

    private fun resetBypassProgress() {
        bypassProgressLines.clear()
        textBypassProgress.text = ""
        textBypassProgress.visibility = View.GONE
    }

    private fun renderBypassProgress() {
        val text = bypassProgressOrder
            .mapNotNull { bypassProgressLines[it] }
            .joinToString(separator = "\n")
        textBypassProgress.text = text
        textBypassProgress.visibility = if (text.isBlank()) View.GONE else View.VISIBLE
    }

    private fun bindCardStatus(
        detected: Boolean,
        needsReview: Boolean,
        icon: ImageView,
        status: TextView,
        hasError: Boolean = false,
    ) {
        when {
            detected -> {
                icon.setImageResource(R.drawable.ic_warning)
                status.text = getString(R.string.main_card_status_detected)
            }
            hasError -> {
                icon.setImageResource(R.drawable.ic_error)
                status.text = getString(R.string.main_card_status_error)
            }
            needsReview -> {
                icon.setImageResource(R.drawable.ic_help)
                status.text = getString(R.string.main_card_status_needs_review)
            }
            else -> {
                icon.setImageResource(R.drawable.ic_check_circle)
                status.text = getString(R.string.main_card_status_clean)
            }
        }
        status.setTextColor(ContextCompat.getColor(this, statusColorRes(detected, needsReview, hasError)))
    }

    private fun statusColorRes(detected: Boolean, needsReview: Boolean, hasError: Boolean = false): Int {
        return when {
            detected -> R.color.status_red
            hasError -> R.color.status_amber
            needsReview -> R.color.status_amber
            else -> R.color.status_green
        }
    }

    private fun displayVerdict(result: CheckResult, privacyMode: Boolean) {
        cardVerdict.visibility = View.VISIBLE
        isVerdictDetailsExpanded = false

        when (result.verdict) {
            Verdict.NOT_DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_check_circle)
                textVerdict.text = getString(R.string.main_verdict_not_detected)
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_green))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_green_bg),
                )
            }
            Verdict.NEEDS_REVIEW -> {
                iconVerdict.setImageResource(R.drawable.ic_help)
                textVerdict.text = getString(R.string.main_verdict_needs_review)
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_yellow_bg),
                )
            }
            Verdict.DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_error)
                textVerdict.text = getString(R.string.main_verdict_detected)
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_red))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_red_bg),
                )
            }
        }

        bindVerdictNarrative(VerdictNarrativeBuilder.build(this, result, privacyMode))
    }

    private fun bindVerdictNarrative(narrative: VerdictNarrative) {
        textVerdictExplanation.text = narrative.explanation
        textVerdictExplanation.visibility = View.VISIBLE

        verdictDetailsContent.removeAllViews()
        addVerdictSection(
            title = getString(R.string.main_verdict_section_meaning),
            content = narrative.meaningRows.map(::createVerdictBulletView),
        )
        addVerdictSection(
            title = getString(R.string.main_verdict_section_discovered),
            content = narrative.discoveredRows.map(::createVerdictRowView),
        )
        addVerdictSection(
            title = getString(R.string.main_verdict_section_reasons),
            content = narrative.reasonRows.map(::createVerdictBulletView),
        )

        val hasDetails = verdictDetailsContent.isNotEmpty()
        verdictDetailsDivider.visibility = if (hasDetails) View.VISIBLE else View.GONE
        btnVerdictDetails.visibility = if (hasDetails) View.VISIBLE else View.GONE
        verdictDetailsContent.visibility = if (hasDetails && isVerdictDetailsExpanded) View.VISIBLE else View.GONE
        updateVerdictDetailsButton()
    }

    private fun addVerdictSection(title: String, content: List<View>) {
        if (content.isEmpty()) return

        if (verdictDetailsContent.isNotEmpty()) {
            verdictDetailsContent.addView(
                View(this).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        1.dp,
                    ).apply {
                        topMargin = 12.dp
                        bottomMargin = 12.dp
                    }
                    setBackgroundColor(ContextCompat.getColor(this@MainActivity, R.color.md_outline_variant))
                    alpha = 0.7f
                },
            )
        }

        verdictDetailsContent.addView(createVerdictSectionTitleView(title))
        content.forEach { verdictDetailsContent.addView(it) }
    }

    private fun createVerdictSectionTitleView(title: String): View {
        return TextView(this).apply {
            text = title
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = true
            letterSpacing = 0.05f
            setPadding(0, 0, 0, 6.dp)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }
    }

    private fun createVerdictBulletView(text: String): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val bullet = TextView(this).apply {
            this.text = "•"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
        }

        val body = TextView(this).apply {
            this.text = text
            textSize = 13f
            setLineSpacing(2.dp.toFloat(), 1f)
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            if (tv.resourceId != 0) {
                setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            } else if (tv.type >= TypedValue.TYPE_FIRST_COLOR_INT && tv.type <= TypedValue.TYPE_LAST_COLOR_INT) {
                setTextColor(tv.data)
            }
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        row.addView(bullet)
        row.addView(body)
        return row
    }

    private fun createVerdictRowView(row: NarrativeRow): View {
        return createInfoView(row.label, row.value)
    }

    private fun clearVerdictCard() {
        isVerdictDetailsExpanded = false
        textVerdict.text = ""
        textVerdictExplanation.text = ""
        textVerdictExplanation.visibility = View.GONE
        verdictDetailsDivider.visibility = View.GONE
        btnVerdictDetails.visibility = View.GONE
        btnVerdictDetails.text = getString(R.string.main_verdict_details)
        verdictDetailsContent.removeAllViews()
        verdictDetailsContent.visibility = View.GONE
    }

    private fun toggleVerdictDetails() {
        if (btnVerdictDetails.visibility != View.VISIBLE) return
        isVerdictDetailsExpanded = !isVerdictDetailsExpanded
        verdictDetailsContent.visibility = if (isVerdictDetailsExpanded) View.VISIBLE else View.GONE
        updateVerdictDetailsButton()
        if (isVerdictDetailsExpanded) {
            animateContentReveal(verdictDetailsContent)
        }
    }

    private fun updateVerdictDetailsButton() {
        btnVerdictDetails.text = if (isVerdictDetailsExpanded) getString(R.string.main_verdict_hide_details) else getString(R.string.main_verdict_details)
    }

    private val Int.dp: Int
        get() = (this * resources.displayMetrics.density).toInt()

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_RUN_CHECK_NOTICE_HIDDEN, hasDismissedRunCheckNotice)
    }

    companion object {
        private const val PREF_RATIONALE_SHOWN = "permissions_rationale_shown"
        private const val PREF_REQUESTED_PERMISSIONS = "requested_permissions"
        private const val STATE_RUN_CHECK_NOTICE_HIDDEN = "state_run_check_notice_hidden"
        private const val LOADING_STATUS_FRAME_MS = 420L
        private const val AUTO_SCROLL_LOCK_MS = 450L
    }
}
