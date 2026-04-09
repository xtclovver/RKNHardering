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
import android.view.MotionEvent
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.notcvnt.rknhardering.checker.BypassChecker
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.checker.VpnCheckRunner
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

fun maskIp(ip: String): String {
    val ipv4Parts = ip.split(".")
    if (ipv4Parts.size == 4 && ipv4Parts.all { it.toIntOrNull() != null }) {
        return "${ipv4Parts[0]}.${ipv4Parts[1]}.*.*"
    }
    val ipv6Parts = ip.split(":")
    if (ipv6Parts.size == 8) {
        return "${ipv6Parts[0]}:${ipv6Parts[1]}:${ipv6Parts[2]}:${ipv6Parts[3]}:*:*:*:*"
    }
    return "*.*.*.*"
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
    private lateinit var resultsScrollView: ScrollView
    private lateinit var textCheckStatus: TextView
    private var checkJob: Job? = null
    private var hasDismissedRunCheckNotice = false
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
    private var checkSessionCounter = 0
    private var activeCheckSessionId = 0
    private var activeCheckPrivacyMode = false

    private val prefs by lazy { getSharedPreferences("rknhardering_prefs", MODE_PRIVATE) }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        markPermissionsRequested(result.keys)
        prefs.edit().putBoolean(PREF_RATIONALE_SHOWN, true).apply()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        val themePrefs = getSharedPreferences("rknhardering_prefs", MODE_PRIVATE)
        SettingsActivity.applyTheme(themePrefs.getString(SettingsActivity.PREF_THEME, "system") ?: "system")
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

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

        bindViews()
        hasDismissedRunCheckNotice = savedInstanceState?.getBoolean(STATE_RUN_CHECK_NOTICE_HIDDEN, false) ?: false
        updateRunCheckNoticeVisibility()

        btnRunCheck.setOnClickListener { onRunCheckClicked() }
        btnStopCheck.setOnClickListener { checkJob?.cancel() }

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
        geoIpInfoSection = findViewById(R.id.geoIpInfoSection)
        geoIpDivider = findViewById(R.id.geoIpDivider)
        locationInfoSection = findViewById(R.id.locationInfoSection)
        locationDivider = findViewById(R.id.locationDivider)
        directInfoSection = findViewById(R.id.directInfoSection)
        directDivider = findViewById(R.id.directDivider)
        setupResultsScrollTracking()
        updateCheckControls(isRunning = false)
    }

    private fun setupResultsScrollTracking() {
        resultsScrollView.setOnTouchListener { _, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> userTouchScrollInProgress = true
                MotionEvent.ACTION_UP,
                MotionEvent.ACTION_CANCEL,
                -> userTouchScrollInProgress = false
            }
            false
        }
        resultsScrollView.setOnScrollChangeListener { _, _, _, _, _ ->
            if (userTouchScrollInProgress && !isAutoScrollInProgress) {
                hasUserScrolledManually = true
            }
        }
    }

    private fun requiredPermissions(): Array<String> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.NEARBY_WIFI_DEVICES,
            )
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    private fun showPermissionRationale(permissions: Array<String> = requiredPermissions()) {
        AlertDialog.Builder(this)
            .setTitle("\u0414\u043e\u043f\u043e\u043b\u043d\u0438\u0442\u0435\u043b\u044c\u043d\u043e\u0435 \u0440\u0430\u0437\u0440\u0435\u0448\u0435\u043d\u0438\u0435")
            .setMessage(permissionRationaleMessage())
            .setPositiveButton("Разрешить") { _, _ ->
                launchPermissionRequest(permissions)
            }
            .setNegativeButton("Пропустить") { _, _ ->
                prefs.edit().putBoolean(PREF_RATIONALE_SHOWN, true).apply()
            }
            .setCancelable(false)
            .show()
    }

    private fun permissionRationaleMessage(): String {
        val wifiPermissionLine = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            "На Android 13+ приложение также запрашивает доступ к nearby Wi-Fi devices для поиска Wi-Fi точек поблизости."
        } else {
            "Приложение также использует Wi-Fi scan для поиска точек доступа поблизости."
        }

        return "Для более точной проверки приложению нужен доступ к точной геолокации.\n\n" +
            "Он используется для чтения идентификаторов базовых станций и geolocation lookup через BeaconDB.\n\n" +
            wifiPermissionLine + "\n\n" +
            "Без этих разрешений проверка продолжит работать, но часть сигналов местоположения и Wi-Fi scan будут недоступны."
    }

    internal fun reRequestPermissions() {
        val missingPermissions = requiredPermissions().filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missingPermissions.isEmpty()) {
            Toast.makeText(this, "Все разрешения уже выданы", Toast.LENGTH_SHORT).show()
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
                "Разрешение заблокировано. Откройте настройки приложения.",
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
        prefs.edit().putStringSet(PREF_REQUESTED_PERMISSIONS, requested).apply()
    }

    private fun hasPermissionBeenRequested(permission: String): Boolean {
        return prefs.getStringSet(PREF_REQUESTED_PERMISSIONS, emptySet())
            ?.contains(permission) == true
    }

    private fun onRunCheckClicked() {
        if (checkJob?.isActive == true) return
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
            updateCheckStatus("Проверка идет. Карточки обновляются прямо по мере получения данных.")
        } else if (textCheckStatus.text != CHECK_STATUS_STOPPED) {
            updateCheckStatus(null)
        }
    }

    private fun updateCheckStatus(message: String?) {
        textCheckStatus.text = message.orEmpty()
        textCheckStatus.visibility = if (message.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    private fun runCheck() {
        val splitTunnelEnabled = prefs.getBoolean(SettingsActivity.PREF_SPLIT_TUNNEL_ENABLED, true)
        val networkRequestsEnabled = prefs.getBoolean(SettingsActivity.PREF_NETWORK_REQUESTS_ENABLED, true)
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
            networkRequestsEnabled = networkRequestsEnabled,
            resolverConfig = resolverConfig,
            portRange = portRange,
            portRangeStart = portRangeStart,
            portRangeEnd = portRangeEnd,
        )

        val sessionId = prepareCheckSession(settings, privacyMode)

        if (splitTunnelEnabled) {
            cardBypass.visibility = View.VISIBLE
            iconBypass.setImageResource(R.drawable.ic_help)
            statusBypass.text = "Сканирование..."
            statusBypass.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
            resetBypassProgress()
            updateBypassProgress(
                BypassChecker.Progress(
                    line = BypassChecker.ProgressLine.BYPASS,
                    phase = "Split tunnel bypass",
                    detail = "Подготовка...",
                ),
            )
            findingsBypass.removeAllViews()
        }

        checkJob = lifecycleScope.launch {
            try {
                showInitialLoadingCards(settings, sessionId)
                VpnCheckRunner.run(this@MainActivity, settings) { update ->
                    withContext(Dispatchers.Main) {
                        if (sessionId != activeCheckSessionId) return@withContext
                        handleCheckUpdate(update)
                    }
                }
                if (sessionId == activeCheckSessionId) {
                    stopLoadingStatusAnimation()
                    updateCheckControls(isRunning = false)
                    activeCheckSessionId = 0
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                updateCheckControls(isRunning = false)
                resetBypassProgress()
                statusBypass.text = "Отменено"
                statusBypass.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.verdict_yellow))
                if (sessionId == activeCheckSessionId) {
                    stopLoadingStatusAnimation()
                    updateCheckStatus(CHECK_STATUS_STOPPED)
                    markLoadingStagesCancelled()
                    activeCheckSessionId = 0
                }
                throw e
            } finally {
                checkJob = null
            }
        }
    }

    private fun prepareCheckSession(settings: CheckSettings, privacyMode: Boolean): Int {
        checkSessionCounter += 1
        activeCheckSessionId = checkSessionCounter
        activeCheckPrivacyMode = privacyMode
        hasUserScrolledManually = false
        userTouchScrollInProgress = false
        isAutoScrollInProgress = false
        loadingStages.clear()
        completedStages.clear()
        stopLoadingStatusAnimation()
        updateCheckControls(isRunning = true)
        hideCards()
        resetBypassProgress()
        clearStageContent()
        if (settings.splitTunnelEnabled) {
            textBypassProgress.text = stageLoadingMessage(RunningStage.BYPASS)
        }
        return activeCheckSessionId
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

        textVerdict.text = ""
    }

    private fun showInitialLoadingCards(settings: CheckSettings, sessionId: Int) {
        enabledStages(settings).forEachIndexed { index, stage ->
            resultsScrollView.postDelayed(
                {
                    if (sessionId != activeCheckSessionId) return@postDelayed
                    showLoadingCardForStage(stage)
                },
                index * INITIAL_CARD_STAGGER_MS,
            )
        }
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

    private fun handleCheckUpdate(update: CheckUpdate) {
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
                animateContentReveal(findingsGeoIp, geoIpInfoSection, geoIpDivider)
            }
            is CheckUpdate.IpComparisonReady -> {
                markStageCompleted(RunningStage.IP_COMPARISON)
                ensureCardVisible(cardIpComparison, animate = false)
                displayIpComparison(update.result, activeCheckPrivacyMode)
                animateContentReveal(textIpComparisonSummary, ipComparisonGroups)
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
                animateContentReveal(findingsDirect, directInfoSection, directDivider)
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
                animateContentReveal(findingsIndirect)
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
                animateContentReveal(findingsLocation, locationInfoSection, locationDivider)
            }
            is CheckUpdate.BypassProgress -> {
                showLoadingCardForStage(RunningStage.BYPASS)
                updateBypassProgress(update.progress)
            }
            is CheckUpdate.BypassReady -> {
                markStageCompleted(RunningStage.BYPASS)
                ensureCardVisible(cardBypass, animate = false)
                displayBypass(update.result, activeCheckPrivacyMode)
                animateContentReveal(findingsBypass)
            }
            is CheckUpdate.VerdictReady -> {
                ensureCardVisible(cardVerdict, shouldAutoScroll = true)
                displayVerdict(update.verdict)
                animateContentReveal(iconVerdict, textVerdict)
            }
        }
    }

    private fun showLoadingCardForStage(stage: RunningStage) {
        if (stage in completedStages) return
        if (stage in loadingStages && cardForStage(stage).visibility == View.VISIBLE) return

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
        status.text = "Остановлено"
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
        statusIpComparison.text = "Остановлено"
        statusIpComparison.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        textIpComparisonSummary.text = stageStoppedMessage(stage)
        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.visibility = View.GONE
        ensureCardVisible(cardIpComparison, animate = false)
    }

    private fun showBypassStopped(stage: RunningStage) {
        iconBypass.setImageResource(R.drawable.ic_help)
        statusBypass.text = "Остановлено"
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
            statusViewForStage(stage).text = stageLoadingStatusBase(stage) + dots
        }
    }

    private fun stageLoadingStatusBase(stage: RunningStage): String {
        return when (stage) {
            RunningStage.BYPASS -> "Сканирование"
            else -> "Проверяется"
        }
    }

    private fun stageLoadingMessage(stage: RunningStage): String {
        return when (stage) {
            RunningStage.GEO_IP -> "Сверяем страну, ASN и признаки хостинга."
            RunningStage.IP_COMPARISON -> "Сравниваем внешний IP через несколько независимых сервисов."
            RunningStage.DIRECT -> "Ищем прямые признаки VPN, прокси и установленных клиентов."
            RunningStage.INDIRECT -> "Проверяем интерфейсы, DNS, маршруты и локальные технические сигналы."
            RunningStage.LOCATION -> "Собираем сигналы оператора, вышек и ближайших Wi-Fi точек."
            RunningStage.BYPASS -> "Ищем локальный split tunnel bypass и доступные proxy endpoints."
        }
    }

    private fun stageStoppedMessage(stage: RunningStage): String {
        return when (stage) {
            RunningStage.BYPASS -> "Сканирование остановлено до завершения этого этапа."
            else -> "Проверка этого этапа была остановлена до завершения."
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
        val wasVisible = card.visibility == View.VISIBLE
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
            val parts = finding.description.split(": ", limit = 2)
            if (parts.size == 2) {
                val value = if (privacyMode && parts[0].trim().equals("IP", ignoreCase = true)) {
                    maskIp(parts[1].trim())
                } else {
                    parts[1]
                }
                infoSection.addView(createInfoView(parts[0], value))
            } else {
                infoSection.addView(createFindingView(finding, privacyMode))
            }
        }
        infoDivider.visibility = if (infoFindings.isNotEmpty() && hasCheckFindings) View.VISIBLE else View.GONE
    }

    private fun displayIpComparison(result: IpComparisonResult, privacyMode: Boolean = false) {
        cardIpComparison.visibility = View.VISIBLE
        bindCardStatus(result.detected, result.needsReview, iconIpComparison, statusIpComparison)
        textIpComparisonSummary.text = result.summary

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
            text = descriptionText
            textSize = 13f
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        row.addView(indicator)
        row.addView(description)
        return row
    }

    private fun maskIpsInText(text: String): String {
        val ipv4Regex = Regex("""\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b""")
        return ipv4Regex.replace(text) { match ->
            "${match.groupValues[1]}.${match.groupValues[2]}.*.*"
        }
    }

    private fun createInfoView(label: String, value: String): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val labelView = TextView(this).apply {
            text = label
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = true
            letterSpacing = 0.05f
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.md_on_surface_variant))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.38f)
        }

        val valueView = TextView(this).apply {
            text = value
            textSize = 13f
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            if (tv.resourceId != 0) {
                setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            } else if (tv.type >= TypedValue.TYPE_FIRST_COLOR_INT && tv.type <= TypedValue.TYPE_LAST_COLOR_INT) {
                setTextColor(tv.data)
            }
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.62f)
        }

        row.addView(labelView)
        row.addView(valueView)
        return row
    }

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
            text = group.summary
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
            text = displayIp ?: "Ошибка"
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
                            append("IPv6-ошибка проигнорирована: ")
                        }
                        append(response.error)
                    }
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
                status.text = "Обнаружено"
            }
            hasError -> {
                icon.setImageResource(R.drawable.ic_error)
                status.text = "Ошибка"
            }
            needsReview -> {
                icon.setImageResource(R.drawable.ic_help)
                status.text = "Требует проверки"
            }
            else -> {
                icon.setImageResource(R.drawable.ic_check_circle)
                status.text = "Чисто"
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

    private fun displayVerdict(verdict: Verdict) {
        cardVerdict.visibility = View.VISIBLE

        when (verdict) {
            Verdict.NOT_DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_check_circle)
                textVerdict.text = "Обход не выявлен"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_green))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_green_bg),
                )
            }
            Verdict.NEEDS_REVIEW -> {
                iconVerdict.setImageResource(R.drawable.ic_help)
                textVerdict.text = "Требуется дополнительная проверка"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_yellow_bg),
                )
            }
            Verdict.DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_error)
                textVerdict.text = "Обход выявлен"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_red))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_red_bg),
                )
            }
        }
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
        private const val CHECK_STATUS_STOPPED = "Проверка остановлена"
        private const val INITIAL_CARD_STAGGER_MS = 70L
        private const val LOADING_STATUS_FRAME_MS = 420L
        private const val AUTO_SCROLL_LOCK_MS = 450L
    }
}
