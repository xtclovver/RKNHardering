package com.notcvnt.rknhardering

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.AttrRes
import androidx.annotation.ColorRes
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isNotEmpty
import androidx.core.view.isVisible
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.transition.AutoTransition
import androidx.transition.TransitionManager
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.notcvnt.rknhardering.checker.BypassChecker
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.DomainReachabilityResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.ObservedIp
import com.notcvnt.rknhardering.model.StunProbeGroupResult
import com.notcvnt.rknhardering.export.CompletedExportSnapshot
import com.notcvnt.rknhardering.export.createCompletedExportSnapshot
import com.notcvnt.rknhardering.model.ExposureStatus
import com.notcvnt.rknhardering.model.NarrativeRow
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VerdictNarrative
import com.notcvnt.rknhardering.model.VerdictNarrativeBuilder
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.ui.main.CategoryTiles
import com.notcvnt.rknhardering.ui.main.MainExportController
import com.notcvnt.rknhardering.ui.main.TileSpec
import com.notcvnt.rknhardering.ui.main.render.BypassRenderer
import com.notcvnt.rknhardering.ui.main.render.CallTransportRenderer
import com.notcvnt.rknhardering.ui.main.render.CategoryCardRenderer
import com.notcvnt.rknhardering.ui.main.render.CdnPullingRenderer
import com.notcvnt.rknhardering.ui.main.render.DomainReachabilityRenderer
import com.notcvnt.rknhardering.ui.main.render.FindingViewFactory
import com.notcvnt.rknhardering.ui.main.render.IpChannelsRenderer
import com.notcvnt.rknhardering.ui.main.render.IpComparisonRenderer
import com.notcvnt.rknhardering.ui.main.render.MainRenderEnvironment
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

internal fun retainCompletedDiagnosticsSnapshot(
    result: CheckResult,
    settings: CheckSettings?,
): RetainedDiagnosticsSnapshot? {
    val retainedSettings = settings?.takeIf { it.tunProbeDebugEnabled } ?: return null
    return RetainedDiagnosticsSnapshot(
        result = result,
        settings = retainedSettings,
    )
}

internal data class RetainedDiagnosticsSnapshot(
    val result: CheckResult,
    val settings: CheckSettings,
)

class MainActivity : AppCompatActivity() {

    private enum class RunningStage {
        GEO_IP,
        IP_COMPARISON,
        CDN_PULLING,
        DIRECT,
        INDIRECT,
        NATIVE_SIGNS,
        ICMP,
        RTT_TRIANGULATION,
        LOCATION,
        IP_CONSENSUS,
        BYPASS,
        DOMAIN_REACHABILITY,
    }

    private lateinit var btnRunCheck: MaterialButton
    private lateinit var btnCopyDiagnostics: ImageButton
    private lateinit var btnExport: ImageButton
    private lateinit var resultsScrollView: TouchAwareScrollView
    private lateinit var textCheckStatus: TextView
    private lateinit var viewModel: CheckViewModel
    private var processedEventCount = 0
    private var processedEventScanId: Long? = null
    private lateinit var cardGeoIp: MaterialCardView
    private lateinit var cardIpComparison: MaterialCardView
    private lateinit var cardCdnPulling: MaterialCardView
    private lateinit var cardDirect: MaterialCardView
    private lateinit var cardIndirect: MaterialCardView
    private lateinit var cardLocation: MaterialCardView
    private lateinit var cardCallTransport: MaterialCardView
    private lateinit var iconCallTransport: ImageView
    private lateinit var statusCallTransport: TextView
    private lateinit var textCallTransportSummary: TextView
    private lateinit var stunGroupsContainer: LinearLayout
    private lateinit var findingsCallTransport: LinearLayout
    private lateinit var cardIcmpSpoofing: MaterialCardView
    private lateinit var iconIcmpSpoofing: ImageView
    private lateinit var statusIcmpSpoofing: TextView
    private lateinit var findingsIcmpSpoofing: LinearLayout
    private lateinit var cardRttTriangulation: MaterialCardView
    private lateinit var iconRttTriangulation: ImageView
    private lateinit var statusRttTriangulation: TextView
    private lateinit var findingsRttTriangulation: LinearLayout
    private lateinit var cardNativeSigns: MaterialCardView
    private lateinit var iconNativeSigns: ImageView
    private lateinit var statusNativeSigns: TextView
    private lateinit var textNativeSignsSummary: TextView
    private lateinit var findingsNativeSigns: LinearLayout
    private lateinit var cardIpChannels: MaterialCardView
    private lateinit var ipChannelsContainer: LinearLayout
    private lateinit var cardVerdict: MaterialCardView
    private lateinit var iconGeoIp: ImageView
    private lateinit var iconIpComparison: ImageView
    private lateinit var iconCdnPulling: ImageView
    private lateinit var iconDirect: ImageView
    private lateinit var iconIndirect: ImageView
    private lateinit var iconLocation: ImageView
    private lateinit var statusGeoIp: TextView
    private lateinit var statusIpComparison: TextView
    private lateinit var statusCdnPulling: TextView
    private lateinit var statusDirect: TextView
    private lateinit var statusIndirect: TextView
    private lateinit var statusLocation: TextView
    private lateinit var textIpComparisonSummary: TextView
    private lateinit var textCdnPullingSummary: TextView
    private lateinit var findingsGeoIp: LinearLayout
    private lateinit var ipComparisonGroups: LinearLayout
    private lateinit var cdnPullingResponses: LinearLayout
    private lateinit var findingsDirect: LinearLayout
    private lateinit var findingsIndirect: LinearLayout
    private lateinit var findingsLocation: LinearLayout
    private lateinit var cardDomainReachability: MaterialCardView
    private lateinit var findingsDomainReachability: LinearLayout
    private lateinit var cardBypass: MaterialCardView
    private lateinit var iconBypass: ImageView
    private lateinit var statusBypass: TextView
    private lateinit var textBypassProgress: TextView
    private lateinit var findingsBypass: LinearLayout
    private lateinit var iconVerdict: ImageView
    private lateinit var textVerdict: TextView
    private lateinit var textVerdictExplanation: TextView
    private lateinit var textVerdictHomeRoutedRoamingNote: TextView
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
    private var activeCheckSettings: CheckSettings? = null
    private var retainedDiagnosticsSnapshot: RetainedDiagnosticsSnapshot? = null
    private var completedExportSnapshot: CompletedExportSnapshot? = null
    private var isVerdictDetailsExpanded = false

    // Redesign
    private lateinit var mainContentRoot: LinearLayout
    private lateinit var categoryContainer: LinearLayout
    private lateinit var verdictHero: MaterialCardView
    private lateinit var verdictAvatar: View
    private lateinit var verdictAvatarIcon: ImageView
    private lateinit var verdictLabel: TextView
    private lateinit var verdictTitle: TextView
    private lateinit var verdictSubtitle: TextView
    private lateinit var verdictHomeRoutedRoamingNote: TextView
    private lateinit var whitelistWarningBanner: View
    private lateinit var hiddenLegacyCardsHost: LinearLayout
    private lateinit var btnPrivacyInfo: MaterialButton
    private val tiles = mutableMapOf<String, TileHolder>()
    private val expandedCategoryIds = linkedSetOf<String>()
    private var lastCompletedResult: CheckResult? = null

    private data class TileHolder(
        val id: String,
        val card: MaterialCardView,
        val header: View,
        val statusDot: View,
        val title: TextView,
        val hint: TextView,
        val chevron: ImageView,
        val body: View,
    )

    private val prefs by lazy { AppUiSettings.prefs(this) }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        markPermissionsRequested(result.keys)
        prefs.edit { putBoolean(PREF_RATIONALE_SHOWN, true) }
    }

    // Field initializer: the controller registers its CreateDocument launchers
    // here, preserving the pre-STARTED registration timing.
    private val exportController = MainExportController(
        activity = this,
        snapshot = { completedExportSnapshot },
        debugClipboardEnabled = { isDebugClipboardExportEnabled() },
    )

    // Lazy: the render environment anchors on resultsScrollView, which is
    // bound in bindViews() before the first render call.
    private val renderEnv by lazy {
        MainRenderEnvironment(
            context = this,
            anchorView = resultsScrollView,
            statusVisual = ::statusVisual,
            colorVisionMode = ::colorVisionMode,
        )
    }
    private val findingViews by lazy { FindingViewFactory(renderEnv) }
    private val categoryCards by lazy { CategoryCardRenderer(renderEnv, findingViews) }
    private val ipComparisonRenderer by lazy { IpComparisonRenderer(renderEnv) }
    private val cdnPullingRenderer by lazy { CdnPullingRenderer(renderEnv, findingViews) }
    private val callTransportRenderer by lazy { CallTransportRenderer(renderEnv, findingViews) }
    private val bypassRenderer by lazy { BypassRenderer(renderEnv, findingViews) }
    private val ipChannelsRenderer by lazy { IpChannelsRenderer(renderEnv) }
    private val domainReachabilityRenderer by lazy { DomainReachabilityRenderer(renderEnv) }

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

        btnRunCheck.setOnClickListener {
            if (viewModel.isRunning.value) {
                viewModel.cancelScan()
            } else {
                onRunCheckClicked()
            }
        }
        btnCopyDiagnostics.setOnClickListener { copyTunProbeDiagnostics() }
        btnExport.setOnClickListener { exportController.showFormatDialog() }
        observeScanEvents()

        handleRkncheckImportIntent()

        if (showAutoUpdateOnboardingIfNeeded()) return
        continueStartupFlow()
    }

    private fun handleRkncheckImportIntent() {
        val data = intent?.data ?: return
        val uriStr = data.toString()
        if (intent?.action == Intent.ACTION_VIEW && (uriStr.endsWith(".rkncheck", ignoreCase = true) || uriStr.contains(".rkncheck"))) {
            val settingsIntent = Intent(this, SettingsActivity::class.java).apply {
                putExtra(SettingsActivity.EXTRA_IMPORT_RKNCHECK_URI, uriStr)
            }
            startActivity(settingsIntent)
            intent.data = null
        }
    }

    private fun continueStartupFlow() {
        handleInitialPermissionFlow()
        checkForAppUpdates()
    }

    private fun handleInitialPermissionFlow() {
        if (intent.getBooleanExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS, false)) {
            intent.removeExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS)
            reRequestPermissions()
        } else if (!prefs.getBoolean(PREF_RATIONALE_SHOWN, false)) {
            showPermissionRationale()
        }
    }

    private fun showAutoUpdateOnboardingIfNeeded(): Boolean {
        if (AppUpdateChecker.isAutoUpdateChoiceMade(this)) return false
        if (!prefs.getBoolean(SettingsActivity.PREF_NETWORK_REQUESTS_ENABLED, true)) return false

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.auto_update_onboarding_title)
            .setMessage(R.string.auto_update_onboarding_message)
            .setPositiveButton(R.string.auto_update_onboarding_enable) { _, _ ->
                AppUpdateChecker.setAutoUpdateEnabled(this, true)
                checkForAppUpdates {
                    handleInitialPermissionFlow()
                }
            }
            .setNegativeButton(R.string.auto_update_onboarding_disable) { _, _ ->
                AppUpdateChecker.setAutoUpdateEnabled(this, false)
                handleInitialPermissionFlow()
            }
            .setCancelable(false)
            .show()
        return true
    }

    private fun checkForAppUpdates(onComplete: (() -> Unit)? = null) {
        if (!AppUpdateChecker.canCheckForUpdates(this)) {
            onComplete?.invoke()
            return
        }
        lifecycleScope.launch {
            val updateInfo = AppUpdateChecker.fetchLatestRelease()
            if (updateInfo == null) {
                onComplete?.invoke()
                return@launch
            }
            val currentVersion = BuildConfig.VERSION_NAME
            if (!AppUpdateChecker.isNewerVersion(currentVersion, updateInfo.latestVersion)) {
                onComplete?.invoke()
                return@launch
            }
            if (AppUpdateChecker.isVersionSkipped(this@MainActivity, updateInfo.latestVersion)) {
                onComplete?.invoke()
                return@launch
            }
            AppUpdateChecker.showUpdateDialog(
                this@MainActivity,
                currentVersion,
                updateInfo,
                onDismiss = onComplete,
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS, false)) {
            reRequestPermissions()
        }
    }

    override fun onResume() {
        super.onResume()
        updateResultActionButtonsVisibility()
    }

    private fun bindViews() {
        resultsScrollView = findViewById(R.id.resultsScrollView)
        btnRunCheck = findViewById(R.id.btnRunCheck)
        btnCopyDiagnostics = findViewById(R.id.btnCopyDiagnostics)
        btnExport = findViewById(R.id.btnExport)
        textCheckStatus = findViewById(R.id.textCheckStatus)
        cardGeoIp = findViewById(R.id.cardGeoIp)
        cardIpComparison = findViewById(R.id.cardIpComparison)
        cardCdnPulling = findViewById(R.id.cardCdnPulling)
        cardDirect = findViewById(R.id.cardDirect)
        cardIndirect = findViewById(R.id.cardIndirect)
        cardLocation = findViewById(R.id.cardLocation)
        cardCallTransport = findViewById(R.id.cardCallTransport)
        iconCallTransport = findViewById(R.id.iconCallTransport)
        statusCallTransport = findViewById(R.id.statusCallTransport)
        textCallTransportSummary = findViewById(R.id.textCallTransportSummary)
        stunGroupsContainer = findViewById(R.id.stunGroupsContainer)
        findingsCallTransport = findViewById(R.id.findingsCallTransport)
        cardIcmpSpoofing = findViewById(R.id.cardIcmpSpoofing)
        iconIcmpSpoofing = findViewById(R.id.iconIcmpSpoofing)
        statusIcmpSpoofing = findViewById(R.id.statusIcmpSpoofing)
        findingsIcmpSpoofing = findViewById(R.id.findingsIcmpSpoofing)
        cardRttTriangulation = findViewById(R.id.cardRttTriangulation)
        iconRttTriangulation = findViewById(R.id.iconRttTriangulation)
        statusRttTriangulation = findViewById(R.id.statusRttTriangulation)
        findingsRttTriangulation = findViewById(R.id.findingsRttTriangulation)
        cardNativeSigns = findViewById(R.id.cardNativeSigns)
        iconNativeSigns = findViewById(R.id.iconNativeSigns)
        statusNativeSigns = findViewById(R.id.statusNativeSigns)
        textNativeSignsSummary = findViewById(R.id.textNativeSignsSummary)
        findingsNativeSigns = findViewById(R.id.findingsNativeSigns)
        cardIpChannels = findViewById(R.id.cardIpChannels)
        ipChannelsContainer = findViewById(R.id.ipChannelsContainer)
        cardVerdict = findViewById(R.id.cardVerdict)
        iconGeoIp = findViewById(R.id.iconGeoIp)
        iconIpComparison = findViewById(R.id.iconIpComparison)
        iconCdnPulling = findViewById(R.id.iconCdnPulling)
        iconDirect = findViewById(R.id.iconDirect)
        iconIndirect = findViewById(R.id.iconIndirect)
        iconLocation = findViewById(R.id.iconLocation)
        statusGeoIp = findViewById(R.id.statusGeoIp)
        statusIpComparison = findViewById(R.id.statusIpComparison)
        statusCdnPulling = findViewById(R.id.statusCdnPulling)
        statusDirect = findViewById(R.id.statusDirect)
        statusIndirect = findViewById(R.id.statusIndirect)
        statusLocation = findViewById(R.id.statusLocation)
        textIpComparisonSummary = findViewById(R.id.textIpComparisonSummary)
        textCdnPullingSummary = findViewById(R.id.textCdnPullingSummary)
        findingsGeoIp = findViewById(R.id.findingsGeoIp)
        ipComparisonGroups = findViewById(R.id.ipComparisonGroups)
        cdnPullingResponses = findViewById(R.id.cdnPullingResponses)
        findingsDirect = findViewById(R.id.findingsDirect)
        findingsIndirect = findViewById(R.id.findingsIndirect)
        findingsLocation = findViewById(R.id.findingsLocation)
        cardDomainReachability = findViewById(R.id.cardDomainReachability)
        findingsDomainReachability = findViewById(R.id.findingsDomainReachability)
        cardBypass = findViewById(R.id.cardBypass)
        iconBypass = findViewById(R.id.iconBypass)
        statusBypass = findViewById(R.id.statusBypass)
        textBypassProgress = findViewById(R.id.textBypassProgress)
        findingsBypass = findViewById(R.id.findingsBypass)
        iconVerdict = findViewById(R.id.iconVerdict)
        textVerdict = findViewById(R.id.textVerdict)
        textVerdictExplanation = findViewById(R.id.textVerdictExplanation)
        textVerdictHomeRoutedRoamingNote = findViewById(R.id.textVerdictHomeRoutedRoamingNote)
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

        // Redesign bindings
        mainContentRoot = findViewById(R.id.mainContentRoot)
        categoryContainer = findViewById(R.id.categoryContainer)
        verdictHero = findViewById(R.id.verdictHero)
        verdictAvatar = findViewById(R.id.verdictAvatar)
        verdictAvatarIcon = findViewById(R.id.verdictAvatarIcon)
        verdictLabel = findViewById(R.id.verdictLabel)
        verdictTitle = findViewById(R.id.verdictTitle)
        verdictSubtitle = findViewById(R.id.verdictSubtitle)
        verdictHomeRoutedRoamingNote = findViewById(R.id.verdictHomeRoutedRoamingNote)
        whitelistWarningBanner = findViewById(R.id.whitelistWarningBanner)
        hiddenLegacyCardsHost = findViewById(R.id.hiddenLegacyCardsHost)
        btnPrivacyInfo = findViewById(R.id.btnPrivacyInfo)
        btnPrivacyInfo.setOnClickListener { showPrivacyFooterDialog() }

        setupCategoryAccordion()
        bindVerdictHeroIdle()
        setupResultsScrollTracking()
        updateCheckControls(isRunning = false)
        updateResultActionButtonsVisibility()
    }

    private fun setupCategoryAccordion() {
        tiles.clear()
        expandedCategoryIds.clear()
        CategoryTiles.ALL.forEach { spec ->
            val id = spec.id
            val holder = createTileHolder(spec)
            holder.title.text = getString(spec.titleRes)
            findViewById<ImageView>(spec.views.icon).setImageResource(spec.iconRes)
            holder.hint.text = getString(R.string.tile_hint_placeholder)
            holder.body.visibility = View.GONE
            holder.chevron.rotation = 0f
            holder.header.setBackgroundResource(R.drawable.bg_category_header_collapsed)
            holder.header.setOnClickListener { onTileClicked(id) }
            tiles[id] = holder
            setTileStatus(id, TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_placeholder))
        }
    }

    private fun createTileHolder(spec: TileSpec): TileHolder {
        return TileHolder(
            id = spec.id,
            card = findViewById(spec.views.card),
            header = findViewById(spec.views.header),
            statusDot = findViewById(spec.views.dot),
            title = findViewById(spec.views.title),
            hint = findViewById(spec.views.hint),
            chevron = findViewById(spec.views.chevron),
            body = findViewById(spec.views.body),
        )
    }

    private fun showPrivacyFooterDialog() {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.privacy_footer_text))
            .setMessage(getString(R.string.run_check_notice))
            .setPositiveButton(android.R.string.ok, null)
            .show()
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
            (
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION)
                )
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
        runCheck()
    }

    private fun isDebugClipboardExportEnabled(): Boolean {
        return prefs.getBoolean(SettingsActivity.PREF_TUN_PROBE_DEBUG_ENABLED, false)
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

        btnRunCheck.isEnabled = true
        btnRunCheck.isClickable = true
        btnRunCheck.isFocusable = true
        btnRunCheck.alpha = 1.0f
        btnRunCheck.backgroundTintList = ColorStateList.valueOf(runButtonBackground)
        btnRunCheck.setTextColor(runButtonForeground)
        btnRunCheck.iconTint = ColorStateList.valueOf(runButtonForeground)
        btnRunCheck.text = getString(
            if (isRunning) {
                R.string.main_stop_check
            } else if (lastCompletedResult != null || processedEventCount > 0) {
                R.string.main_run_check_again
            } else {
                R.string.main_run_check
            },
        )
        btnRunCheck.setIconResource(
            if (isRunning) {
                R.drawable.ic_stop_circle
            } else {
                R.drawable.ic_refresh
            },
        )
        if (isRunning) {
            updateCheckStatus(getString(R.string.main_check_running))
        } else if (textCheckStatus.text != checkStatusStopped()) {
            updateCheckStatus(null)
        }
    }

    private fun checkStatusStopped(): String = getString(R.string.main_check_stopped)

    private fun themedContext(): android.content.Context = resultsScrollView.context

    private fun themeColor(@AttrRes attrRes: Int, @ColorRes fallbackColorRes: Int): Int {
        return MaterialColors.getColor(
            resultsScrollView,
            attrRes,
            ContextCompat.getColor(themedContext(), fallbackColorRes),
        )
    }

    private fun surfaceColor(): Int =
        themeColor(com.google.android.material.R.attr.colorSurface, R.color.md_surface)

    private fun onSurfaceColor(): Int =
        themeColor(com.google.android.material.R.attr.colorOnSurface, R.color.md_on_surface)

    private fun onSurfaceVariantColor(): Int =
        themeColor(
            com.google.android.material.R.attr.colorOnSurfaceVariant,
            R.color.md_on_surface_variant,
        )

    private fun outlineVariantColor(): Int =
        themeColor(com.google.android.material.R.attr.colorOutlineVariant, R.color.md_outline_variant)

    private fun updateCheckStatus(message: String?) {
        textCheckStatus.text = message.orEmpty()
        textCheckStatus.visibility = if (message.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    private fun updateCopyDiagnosticsVisibility() {
        val debugEnabled = prefs.getBoolean(SettingsActivity.PREF_TUN_PROBE_DEBUG_ENABLED, false)
        val canShow = retainedDiagnosticsSnapshot != null &&
            debugEnabled
        btnCopyDiagnostics.isEnabled = canShow
        btnCopyDiagnostics.alpha = if (canShow) 1.0f else 0.42f
    }

    private fun updateExportVisibility() {
        val canShow = completedExportSnapshot != null
        btnExport.isEnabled = canShow
        btnExport.alpha = if (canShow) 1.0f else 0.42f
    }

    private fun updateResultActionButtonsVisibility() {
        updateCopyDiagnosticsVisibility()
        updateExportVisibility()
    }

    private fun copyTunProbeDiagnostics() {
        val snapshot = retainedDiagnosticsSnapshot ?: return
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val text = DebugDiagnosticsFormatter.format(
            result = snapshot.result,
            settings = snapshot.settings,
            privacyMode = activeCheckPrivacyMode,
        )
        clipboard.setPrimaryClip(
            ClipData.newPlainText(
                getString(R.string.main_copy_diagnostics),
                text,
            ),
        )
        viewModel.markCompletedDiagnosticsConsumed()
        retainedDiagnosticsSnapshot = null
        updateResultActionButtonsVisibility()
        Toast.makeText(this, R.string.main_diagnostics_copied, Toast.LENGTH_SHORT).show()
    }

    private fun runCheck() {
        val splitTunnelEnabled = prefs.getBoolean(SettingsActivity.PREF_SPLIT_TUNNEL_ENABLED, true)
        val proxyScanEnabled = prefs.getBoolean(SettingsActivity.PREF_PROXY_SCAN_ENABLED, true)
        val xrayApiScanEnabled = prefs.getBoolean(SettingsActivity.PREF_XRAY_API_SCAN_ENABLED, true)
        val networkRequestsEnabled = prefs.getBoolean(SettingsActivity.PREF_NETWORK_REQUESTS_ENABLED, true)
        val callTransportProbeEnabled = prefs.getBoolean(SettingsActivity.PREF_CALL_TRANSPORT_PROBE_ENABLED, false)
        val cdnPullingEnabled = prefs.getBoolean(SettingsActivity.PREF_CDN_PULLING_ENABLED, false)
        val cdnPullingMeduzaEnabled = prefs.getBoolean(SettingsActivity.PREF_CDN_PULLING_MEDUZA_ENABLED, true)
        val rttTriangulationEnabled = prefs.getBoolean(SettingsActivity.PREF_RTT_TRIANGULATION_ENABLED, false)
        val tunProbeDebugEnabled = prefs.getBoolean(SettingsActivity.PREF_TUN_PROBE_DEBUG_ENABLED, false)
        val tunProbeModeOverride = com.notcvnt.rknhardering.probe.TunProbeModeOverride.fromPref(
            prefs.getString(
                SettingsActivity.PREF_TUN_PROBE_MODE_OVERRIDE,
                com.notcvnt.rknhardering.probe.TunProbeModeOverride.AUTO.prefValue,
            ),
        )
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

        val baseSettings = CheckSettings(
            splitTunnelEnabled = splitTunnelEnabled,
            proxyScanEnabled = proxyScanEnabled,
            xrayApiScanEnabled = xrayApiScanEnabled,
            networkRequestsEnabled = networkRequestsEnabled,
            callTransportProbeEnabled = callTransportProbeEnabled,
            cdnPullingEnabled = cdnPullingEnabled,
            cdnPullingMeduzaEnabled = cdnPullingMeduzaEnabled,
            rttTriangulationEnabled = rttTriangulationEnabled,
            tunProbeDebugEnabled = tunProbeDebugEnabled,
            tunProbeModeOverride = tunProbeModeOverride,
            resolverConfig = resolverConfig,
            portRange = portRange,
            portRangeStart = portRangeStart,
            portRangeEnd = portRangeEnd,
        )

        val customEnabled = prefs.getBoolean(SettingsActivity.PREF_CUSTOM_CHECKS_ENABLED, false)
        val activeProfile = if (customEnabled) com.notcvnt.rknhardering.customcheck.CustomCheckRunner.getActiveProfile(this) else null
        val effectiveSettings = activeProfile?.let { com.notcvnt.rknhardering.customcheck.CustomCheckRunner.toCheckSettings(it, baseSettings) } ?: baseSettings

        viewModel.startScan(effectiveSettings, privacyMode)
    }

    private fun observeScanEvents() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.scanEvents.collect { timeline ->
                    val events = timeline.events
                    if (events.isEmpty()) return@collect

                    val isNewScan = timeline.scanId != processedEventScanId
                    if (isNewScan) {
                        processedEventScanId = timeline.scanId
                        processedEventCount = 0
                    }
                    if (processedEventCount >= events.size) return@collect

                    if (processedEventCount == 0) {
                        val firstEvent = events.firstOrNull() as? ScanEvent.Started ?: return@collect
                        prepareCheckSessionUi(
                            firstEvent.settings,
                            firstEvent.privacyMode,
                        )
                        processedEventCount = 1
                        while (processedEventCount < events.size) {
                            applyScanEvent(events[processedEventCount], animate = false)
                            processedEventCount += 1
                        }
                    } else {
                        while (processedEventCount < events.size) {
                            applyScanEvent(events[processedEventCount], animate = true)
                            processedEventCount += 1
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
        activeCheckSettings = settings
        retainedDiagnosticsSnapshot = null
        completedExportSnapshot = null
        hasUserScrolledManually = false
        userTouchScrollInProgress = false
        isAutoScrollInProgress = false
        loadingStages.clear()
        completedStages.clear()
        stopLoadingStatusAnimation()
        hideCards()
        resetBypassProgress()
        clearStageContent()
        resetAllTiles()
        applyTileVisibilityFromSettings(settings)
        if (settings.callTransportProbeEnabled) {
            setTileStatus(CATEGORY_STN, TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_loading))
        }
        bindVerdictHeroRunning()
        showAllLoadingCardsNow(settings)
        updateResultActionButtonsVisibility()
    }

    private fun showAllLoadingCardsNow(settings: CheckSettings) {
        enabledStages(settings).forEach { stage -> showLoadingCardForStage(stage) }
    }

    private fun applyTileVisibilityFromSettings(settings: CheckSettings) {
        val enabledTileIds = enabledStages(settings).map { tileIdForStage(it) }.toMutableSet()
        if (settings.callTransportProbeEnabled) {
            enabledTileIds += CATEGORY_STN
        }
        tiles.forEach { (id, holder) ->
            holder.card.visibility = if (id in enabledTileIds) View.VISIBLE else View.GONE
        }
    }

    private fun applyScanEvent(event: ScanEvent, animate: Boolean) {
        when (event) {
            is ScanEvent.Started -> Unit
            is ScanEvent.Update -> {
                handleCheckUpdate(event.update, animate = animate)
            }
            is ScanEvent.Completed -> {
                retainedDiagnosticsSnapshot = if (viewModel.canRetainCompletedDiagnostics()) {
                    retainCompletedDiagnosticsSnapshot(
                        result = event.result,
                        settings = activeCheckSettings,
                    )
                } else {
                    null
                }
                completedExportSnapshot = createCompletedExportSnapshot(
                    result = event.result,
                    privacyMode = event.privacyMode,
                )
                activeCheckSettings = null
                lastCompletedResult = event.result
                refreshCompletedCategoryViews(event.result, event.privacyMode)
                displayVerdict(event.result, event.privacyMode)
                bindVerdictHero(event.result)
                if (animate) animateContentReveal(verdictHero)
                stopLoadingStatusAnimation()
                updateResultActionButtonsVisibility()
            }
            is ScanEvent.Cancelled -> {
                activeCheckSettings = null
                resetBypassProgress()
                statusBypass.text = getString(R.string.main_status_cancelled)
                statusBypass.setTextColor(statusColor(StatusSemantic.REVIEW))
                stopLoadingStatusAnimation()
                updateCheckStatus(getString(R.string.main_check_stopped))
                markLoadingStagesCancelled()
                loadingStages.toList().forEach { stage ->
                    setTileStatus(
                        tileIdForStage(stage),
                        TILE_STATUS_REVIEW,
                        getString(R.string.tile_hint_stopped),
                    )
                }
                if (isCallTransportTileLoading()) {
                    setTileStatus(CATEGORY_STN, TILE_STATUS_REVIEW, getString(R.string.tile_hint_stopped))
                }
                bindVerdictHeroIdle()
                verdictSubtitle.text = getString(R.string.main_check_stopped)
                updateResultActionButtonsVisibility()
            }
        }
    }

    private fun refreshCompletedCategoryViews(result: CheckResult, privacyMode: Boolean) {
        if (cardCdnPulling.isVisible || result.cdnPulling != CdnPullingResult.empty()) {
            displayCdnPulling(result.cdnPulling, privacyMode)
            updateTileFromCdn(result.cdnPulling)
        }

        val icmpHasContent = result.icmpSpoofing.findings.isNotEmpty() ||
            result.icmpSpoofing.evidence.isNotEmpty() ||
            result.icmpSpoofing.detected ||
            result.icmpSpoofing.needsReview ||
            result.icmpSpoofing.hasError
        if (cardIcmpSpoofing.isVisible || icmpHasContent) {
            displayCategory(
                result.icmpSpoofing,
                cardIcmpSpoofing,
                iconIcmpSpoofing,
                statusIcmpSpoofing,
                findingsIcmpSpoofing,
                privacyMode,
            )
            updateTileFromCategory(CATEGORY_ICM, result.icmpSpoofing)
        }

        if (cardDomainReachability.isVisible || !result.domainReachability.isEmpty) {
            displayDomainReachability(result.domainReachability)
            updateTileFromDomainReachability(result.domainReachability)
        }
    }

    private fun displayDomainReachability(result: DomainReachabilityResult) {
        domainReachabilityRenderer.render(result, findingsDomainReachability)
    }

    private fun updateTileFromDomainReachability(result: DomainReachabilityResult) {
        if (result.isEmpty) return
        val mismatchCount = result.responses.count { !it.matchesExpectation }
        val status = when {
            mismatchCount > 0 -> TILE_STATUS_DETECTED
            else -> TILE_STATUS_CLEAN
        }
        val hint = if (mismatchCount > 0) {
            getString(R.string.domain_reachability_hint_mismatch, mismatchCount, result.totalCount)
        } else {
            getString(R.string.domain_reachability_hint_all_match, result.responses.size, result.totalCount)
        }
        setTileStatus(CATEGORY_REA, status, hint)
    }

    private fun showDomainReachabilityLoading(stage: RunningStage) {
        findingsDomainReachability.removeAllViews()
        findingsDomainReachability.addView(findingViews.createLoadingHintView(stageLoadingMessage(stage)))
        findingsDomainReachability.visibility = View.VISIBLE
        ensureCardVisible(cardDomainReachability)
    }

    private fun clearStageContent() {
        geoIpInfoSection.removeAllViews()
        geoIpInfoSection.visibility = View.GONE
        geoIpDivider.visibility = View.GONE
        findingsGeoIp.removeAllViews()

        textIpComparisonSummary.text = ""
        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.visibility = View.GONE

        textCdnPullingSummary.text = ""
        cdnPullingResponses.removeAllViews()
        cdnPullingResponses.visibility = View.GONE

        directInfoSection.removeAllViews()
        directInfoSection.visibility = View.GONE
        directDivider.visibility = View.GONE
        findingsDirect.removeAllViews()
        findingsIndirect.removeAllViews()

        locationInfoSection.removeAllViews()
        locationInfoSection.visibility = View.GONE
        locationDivider.visibility = View.GONE
        findingsLocation.removeAllViews()

        textCallTransportSummary.text = ""
        textCallTransportSummary.visibility = View.GONE
        stunGroupsContainer.removeAllViews()
        stunGroupsContainer.visibility = View.GONE
        findingsCallTransport.removeAllViews()
        findingsCallTransport.visibility = View.GONE

        findingsIcmpSpoofing.removeAllViews()
        findingsIcmpSpoofing.visibility = View.GONE

        findingsRttTriangulation.removeAllViews()
        findingsRttTriangulation.visibility = View.GONE

        textNativeSignsSummary.text = ""
        textNativeSignsSummary.visibility = View.GONE
        findingsNativeSigns.removeAllViews()
        findingsNativeSigns.visibility = View.GONE

        findingsBypass.removeAllViews()
        findingsBypass.visibility = View.GONE

        findingsDomainReachability.removeAllViews()
        findingsDomainReachability.visibility = View.GONE

        ipChannelsContainer.removeAllViews()
        cardIpChannels.visibility = View.GONE

        clearVerdictCard()
    }

    private fun enabledStages(settings: CheckSettings): List<RunningStage> {
        val stages = mutableListOf<RunningStage>()
        if (settings.networkRequestsEnabled) {
            if (settings.geoIp.enabled) stages += RunningStage.GEO_IP
            if (settings.ipComparison.enabled) stages += RunningStage.IP_COMPARISON
            if (settings.cdnPullingEnabled) {
                stages += RunningStage.CDN_PULLING
            }
            if (settings.icmpSpoofingEnabled) {
                stages += RunningStage.ICMP
            }
            if (settings.rttTriangulationEnabled) {
                stages += RunningStage.RTT_TRIANGULATION
            }
        }
        if (settings.directSigns.enabled) stages += RunningStage.DIRECT
        if (settings.indirectSigns.enabled) stages += RunningStage.INDIRECT
        if (settings.nativeSignsEnabled) stages += RunningStage.NATIVE_SIGNS
        if (settings.locationSignals.enabled) stages += RunningStage.LOCATION
        if (settings.networkRequestsEnabled || settings.splitTunnelEnabled) {
            stages += RunningStage.IP_CONSENSUS
        }
        if (settings.splitTunnelEnabled) {
            stages += RunningStage.BYPASS
        }
        if (settings.domainReachabilityEnabled && settings.reachabilityDomains.isNotEmpty()) {
            stages += RunningStage.DOMAIN_REACHABILITY
        }
        return stages
    }

    private fun handleCheckUpdate(update: CheckUpdate, animate: Boolean = true) {
        when (update) {
            is CheckUpdate.GeoIpReady -> {
                markStageCompleted(RunningStage.GEO_IP)
                ensureCardVisible(cardGeoIp)
                displayCategory(
                    update.result,
                    cardGeoIp,
                    iconGeoIp,
                    statusGeoIp,
                    findingsGeoIp,
                    activeCheckPrivacyMode,
                )
                updateTileFromCategory(CATEGORY_GEO, update.result)
                if (animate) animateContentReveal(findingsGeoIp, geoIpInfoSection, geoIpDivider)
            }
            is CheckUpdate.IpComparisonReady -> {
                markStageCompleted(RunningStage.IP_COMPARISON)
                ensureCardVisible(cardIpComparison)
                displayIpComparison(update.result, activeCheckPrivacyMode)
                updateTileFromIpComparison(update.result)
                if (animate) animateContentReveal(textIpComparisonSummary, ipComparisonGroups)
            }
            is CheckUpdate.CdnPullingReady -> {
                markStageCompleted(RunningStage.CDN_PULLING)
                ensureCardVisible(cardCdnPulling)
                displayCdnPulling(update.result, activeCheckPrivacyMode)
                updateTileFromCdn(update.result)
                if (animate) animateContentReveal(textCdnPullingSummary, cdnPullingResponses)
            }
            is CheckUpdate.IcmpSpoofingReady -> {
                markStageCompleted(RunningStage.ICMP)
                ensureCardVisible(cardIcmpSpoofing)
                displayCategory(
                    update.result,
                    cardIcmpSpoofing,
                    iconIcmpSpoofing,
                    statusIcmpSpoofing,
                    findingsIcmpSpoofing,
                    activeCheckPrivacyMode,
                )
                updateTileFromCategory(CATEGORY_ICM, update.result)
                if (animate) animateContentReveal(findingsIcmpSpoofing)
            }
            is CheckUpdate.RttTriangulationReady -> {
                markStageCompleted(RunningStage.RTT_TRIANGULATION)
                ensureCardVisible(cardRttTriangulation)
                displayCategory(
                    update.result,
                    cardRttTriangulation,
                    iconRttTriangulation,
                    statusRttTriangulation,
                    findingsRttTriangulation,
                    activeCheckPrivacyMode,
                )
                updateTileFromCategory(CATEGORY_RTT, update.result)
                if (animate) animateContentReveal(findingsRttTriangulation)
            }
            is CheckUpdate.DirectSignsReady -> {
                markStageCompleted(RunningStage.DIRECT)
                ensureCardVisible(cardDirect)
                displayCategory(
                    update.result,
                    cardDirect,
                    iconDirect,
                    statusDirect,
                    findingsDirect,
                    activeCheckPrivacyMode,
                )
                updateTileFromCategory(CATEGORY_DIR, update.result)
                if (animate) animateContentReveal(findingsDirect, directInfoSection, directDivider)
            }
            is CheckUpdate.IndirectSignsReady -> {
                markStageCompleted(RunningStage.INDIRECT)
                ensureCardVisible(cardIndirect)
                displayCategory(
                    update.result,
                    cardIndirect,
                    iconIndirect,
                    statusIndirect,
                    findingsIndirect,
                    activeCheckPrivacyMode,
                )
                updateTileFromCategory(CATEGORY_IND, update.result)
                if (animate) animateContentReveal(findingsIndirect)

                val callTransportEnabled = prefs.getBoolean(
                    SettingsActivity.PREF_CALL_TRANSPORT_PROBE_ENABLED, false,
                )
                if (callTransportEnabled) {
                    displayCallTransport(update.result.callTransportLeaks, update.result.stunProbeGroups, activeCheckPrivacyMode)
                    updateTileFromCallTransport(update.result.callTransportLeaks, update.result.stunProbeGroups)
                    if (animate) animateContentReveal(findingsCallTransport, stunGroupsContainer)
                }
            }
            is CheckUpdate.LocationSignalsReady -> {
                markStageCompleted(RunningStage.LOCATION)
                ensureCardVisible(cardLocation)
                displayCategory(
                    update.result,
                    cardLocation,
                    iconLocation,
                    statusLocation,
                    findingsLocation,
                    activeCheckPrivacyMode,
                )
                updateTileFromCategory(CATEGORY_LOC, update.result)
                if (animate) animateContentReveal(findingsLocation, locationInfoSection, locationDivider)
            }
            is CheckUpdate.NativeSignsReady -> {
                markStageCompleted(RunningStage.NATIVE_SIGNS)
                displayNativeSigns(update.result, activeCheckPrivacyMode)
                updateTileFromCategory(CATEGORY_NAT, update.result)
                if (animate) animateContentReveal(findingsNativeSigns, textNativeSignsSummary)
            }
            is CheckUpdate.BypassProgress -> {
                showLoadingCardForStage(RunningStage.BYPASS)
                updateBypassProgress(update.progress)
            }
            is CheckUpdate.BypassReady -> {
                markStageCompleted(RunningStage.BYPASS)
                ensureCardVisible(cardBypass)
                displayBypass(update.result, activeCheckPrivacyMode)
                updateTileFromBypass(update.result)
                if (animate) animateContentReveal(findingsBypass)
            }
            is CheckUpdate.IpConsensusReady -> {
                markStageCompleted(RunningStage.IP_CONSENSUS)
            }
            is CheckUpdate.DomainReachabilityReady -> {
                markStageCompleted(RunningStage.DOMAIN_REACHABILITY)
                ensureCardVisible(cardDomainReachability)
                displayDomainReachability(update.result)
                updateTileFromDomainReachability(update.result)
                if (animate) animateContentReveal(findingsDomainReachability)
            }
            is CheckUpdate.VerdictReady -> {
                Unit
            }
        }
    }

    private fun tileIdForStage(stage: RunningStage): String = when (stage) {
        RunningStage.GEO_IP -> CATEGORY_GEO
        RunningStage.IP_COMPARISON -> CATEGORY_IPC
        RunningStage.CDN_PULLING -> CATEGORY_CDN
        RunningStage.DIRECT -> CATEGORY_DIR
        RunningStage.INDIRECT -> CATEGORY_IND
        RunningStage.NATIVE_SIGNS -> CATEGORY_NAT
        RunningStage.ICMP -> CATEGORY_ICM
        RunningStage.RTT_TRIANGULATION -> CATEGORY_RTT
        RunningStage.LOCATION -> CATEGORY_LOC
        RunningStage.IP_CONSENSUS -> CATEGORY_IPS
        RunningStage.BYPASS -> CATEGORY_BYP
        RunningStage.DOMAIN_REACHABILITY -> CATEGORY_REA
    }

    // View bundle for the "plain category card" stages handled by
    // showCategoryLoading/showCategoryStopped. Stages with specialized
    // loading/stopped handlers (IP comparison, CDN, bypass, reachability,
    // consensus) return null.
    private data class StageCategoryViews(
        val card: MaterialCardView,
        val icon: ImageView,
        val status: TextView,
        val findingsContainer: LinearLayout,
        val infoSection: LinearLayout? = null,
        val infoDivider: View? = null,
    )

    private fun categoryViewsForStage(stage: RunningStage): StageCategoryViews? = when (stage) {
        RunningStage.GEO_IP -> StageCategoryViews(cardGeoIp, iconGeoIp, statusGeoIp, findingsGeoIp, geoIpInfoSection, geoIpDivider)
        RunningStage.ICMP -> StageCategoryViews(cardIcmpSpoofing, iconIcmpSpoofing, statusIcmpSpoofing, findingsIcmpSpoofing)
        RunningStage.RTT_TRIANGULATION -> StageCategoryViews(cardRttTriangulation, iconRttTriangulation, statusRttTriangulation, findingsRttTriangulation)
        RunningStage.DIRECT -> StageCategoryViews(cardDirect, iconDirect, statusDirect, findingsDirect, directInfoSection, directDivider)
        RunningStage.INDIRECT -> StageCategoryViews(cardIndirect, iconIndirect, statusIndirect, findingsIndirect)
        RunningStage.NATIVE_SIGNS -> StageCategoryViews(cardNativeSigns, iconNativeSigns, statusNativeSigns, findingsNativeSigns)
        RunningStage.LOCATION -> StageCategoryViews(cardLocation, iconLocation, statusLocation, findingsLocation, locationInfoSection, locationDivider)
        else -> null
    }

    private fun showLoadingCardForStage(stage: RunningStage) {
        if (stage == RunningStage.IP_CONSENSUS) return
        if (stage in completedStages) return
        if (stage in loadingStages && cardForStage(stage).isVisible) return

        setTileStatus(tileIdForStage(stage), TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_loading))
        loadingStages += stage
        when (stage) {
            RunningStage.IP_COMPARISON -> showIpComparisonLoading(stage)
            RunningStage.CDN_PULLING -> showCdnPullingLoading(stage)
            RunningStage.BYPASS -> showBypassLoading(stage)
            RunningStage.DOMAIN_REACHABILITY -> showDomainReachabilityLoading(stage)
            RunningStage.IP_CONSENSUS -> Unit
            else -> categoryViewsForStage(stage)?.let { v ->
                showCategoryLoading(
                    stage = stage,
                    card = v.card,
                    icon = v.icon,
                    status = v.status,
                    findingsContainer = v.findingsContainer,
                    hint = stageLoadingMessage(stage),
                    infoSection = v.infoSection,
                    infoDivider = v.infoDivider,
                )
            }
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
        findingsContainer.addView(findingViews.createLoadingHintView(hint))
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

    private fun showCdnPullingLoading(stage: RunningStage) {
        bindCardLoadingState(stage, iconCdnPulling, statusCdnPulling)
        textCdnPullingSummary.text = stageLoadingMessage(stage)
        cdnPullingResponses.removeAllViews()
        cdnPullingResponses.visibility = View.GONE
        ensureCardVisible(cardCdnPulling)
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
                RunningStage.IP_COMPARISON -> showIpComparisonStopped(stage)
                RunningStage.CDN_PULLING -> showCdnPullingStopped(stage)
                RunningStage.BYPASS -> showBypassStopped(stage)
                RunningStage.DOMAIN_REACHABILITY -> {
                    findingsDomainReachability.removeAllViews()
                    findingsDomainReachability.addView(findingViews.createLoadingHintView(stageStoppedMessage(stage)))
                    findingsDomainReachability.visibility = View.VISIBLE
                }
                RunningStage.IP_CONSENSUS -> Unit
                else -> categoryViewsForStage(stage)?.let { v ->
                    showCategoryStopped(
                        card = v.card,
                        icon = v.icon,
                        status = v.status,
                        findingsContainer = v.findingsContainer,
                        message = stageStoppedMessage(stage),
                        infoSection = v.infoSection,
                        infoDivider = v.infoDivider,
                    )
                }
            }
        }
        loadingStages.clear()
    }

    private fun bindCardStoppedState(icon: ImageView, status: TextView) {
        val visual = statusVisual(StatusSemantic.REVIEW)
        icon.setImageResource(visual.iconRes)
        icon.imageTintList = ColorStateList.valueOf(visual.accentColor)
        status.text = getString(R.string.main_status_stopped)
        status.setTextColor(visual.accentColor)
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
        bindCardStoppedState(icon, status)
        infoSection?.apply {
            removeAllViews()
            visibility = View.GONE
        }
        infoDivider?.visibility = View.GONE
        findingsContainer.removeAllViews()
        findingsContainer.addView(findingViews.createLoadingHintView(message))
        findingsContainer.visibility = View.VISIBLE
        ensureCardVisible(card)
    }

    private fun showIpComparisonStopped(stage: RunningStage) {
        bindCardStoppedState(iconIpComparison, statusIpComparison)
        textIpComparisonSummary.text = stageStoppedMessage(stage)
        ipComparisonGroups.removeAllViews()
        ipComparisonGroups.visibility = View.GONE
        ensureCardVisible(cardIpComparison)
    }

    private fun showCdnPullingStopped(stage: RunningStage) {
        bindCardStoppedState(iconCdnPulling, statusCdnPulling)
        textCdnPullingSummary.text = stageStoppedMessage(stage)
        cdnPullingResponses.removeAllViews()
        cdnPullingResponses.visibility = View.GONE
        ensureCardVisible(cardCdnPulling)
    }

    private fun showBypassStopped(stage: RunningStage) {
        bindCardStoppedState(iconBypass, statusBypass)
        findingsBypass.removeAllViews()
        findingsBypass.visibility = View.GONE
        textBypassProgress.text = stageStoppedMessage(stage)
        textBypassProgress.visibility = View.VISIBLE
        ensureCardVisible(cardBypass)
    }

    private fun bindCardLoadingState(stage: RunningStage, icon: ImageView, status: TextView) {
        val visual = statusVisual(StatusSemantic.NEUTRAL)
        icon.setImageResource(visual.iconRes)
        icon.imageTintList = ColorStateList.valueOf(visual.accentColor)
        status.text = stageLoadingStatusBase(stage)
        status.setTextColor(visual.accentColor)
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
            RunningStage.CDN_PULLING -> getString(R.string.main_loading_cdn_pulling)
            RunningStage.ICMP -> getString(R.string.main_loading_icmp)
            RunningStage.RTT_TRIANGULATION -> getString(R.string.main_loading_rtt_triangulation)
            RunningStage.DIRECT -> getString(R.string.main_loading_direct)
            RunningStage.INDIRECT -> getString(R.string.main_loading_indirect)
            RunningStage.NATIVE_SIGNS -> getString(R.string.main_loading_native_signs)
            RunningStage.LOCATION -> getString(R.string.main_loading_location)
            RunningStage.IP_CONSENSUS -> getString(R.string.main_loading_ip_comparison)
            RunningStage.BYPASS -> getString(R.string.main_loading_bypass)
            RunningStage.DOMAIN_REACHABILITY -> getString(R.string.main_loading_domain_reachability)
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
            RunningStage.CDN_PULLING -> cardCdnPulling
            RunningStage.ICMP -> cardIcmpSpoofing
            RunningStage.RTT_TRIANGULATION -> cardRttTriangulation
            RunningStage.DIRECT -> cardDirect
            RunningStage.INDIRECT -> cardIndirect
            RunningStage.NATIVE_SIGNS -> cardNativeSigns
            RunningStage.LOCATION -> cardLocation
            RunningStage.IP_CONSENSUS -> cardIpChannels
            RunningStage.BYPASS -> cardBypass
            RunningStage.DOMAIN_REACHABILITY -> cardDomainReachability
        }
    }

    private fun statusViewForStage(stage: RunningStage): TextView {
        return when (stage) {
            RunningStage.GEO_IP -> statusGeoIp
            RunningStage.IP_COMPARISON -> statusIpComparison
            RunningStage.CDN_PULLING -> statusCdnPulling
            RunningStage.ICMP -> statusIcmpSpoofing
            RunningStage.RTT_TRIANGULATION -> statusRttTriangulation
            RunningStage.DIRECT -> statusDirect
            RunningStage.INDIRECT -> statusIndirect
            RunningStage.NATIVE_SIGNS -> statusNativeSigns
            RunningStage.LOCATION -> statusLocation
            RunningStage.IP_CONSENSUS -> statusGeoIp
            RunningStage.BYPASS -> statusBypass
            RunningStage.DOMAIN_REACHABILITY -> statusGeoIp // No dedicated status view; reuse placeholder
        }
    }

    private fun ensureCardVisible(
        card: MaterialCardView,
        shouldAutoScroll: Boolean = false,
    ) {
        val inHiddenHost = card.parent === hiddenLegacyCardsHost
        if (!card.isVisible) {
            card.animate().cancel()
            card.visibility = View.VISIBLE
            card.alpha = 1f
            card.translationY = 0f
        }
        if (!inHiddenHost && shouldAutoScroll && !hasUserScrolledManually) {
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

    private fun hideCards() {
        collapseExpanded()
        cardIpChannels.visibility = View.GONE
        cardVerdict.visibility = View.GONE
    }

    // Reflected by MainActivityUiRenderingTest (name + arity). Resolves the
    // optional info-section views for the card before delegating.
    private fun displayCategory(
        category: CategoryResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout,
        privacyMode: Boolean = false,
    ) {
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
        categoryCards.render(category, card, icon, status, findingsContainer, infoSection, infoDivider, privacyMode)
    }

    // Reflected by MainActivityUiRenderingTest (name + arity).
    private fun displayIpComparison(result: IpComparisonResult, privacyMode: Boolean = false) {
        ipComparisonRenderer.render(
            result,
            cardIpComparison,
            iconIpComparison,
            statusIpComparison,
            textIpComparisonSummary,
            ipComparisonGroups,
            privacyMode,
        )
    }

    // Reflected by MainActivityUiRenderingTest (name + arity).
    private fun displayCdnPulling(result: CdnPullingResult, privacyMode: Boolean = false) {
        cdnPullingRenderer.render(
            result,
            cardCdnPulling,
            iconCdnPulling,
            statusCdnPulling,
            textCdnPullingSummary,
            cdnPullingResponses,
            privacyMode,
        )
    }

    // Reflected by MainActivityUiRenderingTest (name + arity) — keep this
    // delegator even without production call sites.
    private fun createFindingView(finding: Finding, privacyMode: Boolean = false): View =
        findingViews.createFindingView(finding, privacyMode)

    private fun createInfoView(label: String, value: String): View =
        findingViews.createInfoView(label, value)

    // Reflected by MainActivityUiRenderingTest (name + arity) — keep this
    // delegator even without production call sites.
    private fun createIpCheckerResponseView(response: IpCheckerResponse, privacyMode: Boolean = false): View =
        ipComparisonRenderer.createIpCheckerResponseView(response, privacyMode)

    // Reflected by MainActivityUiRenderingTest (name + arity) — keep this
    // delegator even without production call sites.
    private fun createCdnPullingResponseView(response: CdnPullingResponse, privacyMode: Boolean = false): View =
        cdnPullingRenderer.createCdnPullingResponseView(response, privacyMode)

    // Reflected by MainActivityUiRenderingTest (name + arity) — keep this
    // delegator even without production call sites (the IP-channels card is
    // currently not rendered from MainActivity; see IpChannelsRenderer).
    private fun createIpChannelRow(ip: ObservedIp, privacyMode: Boolean): View =
        ipChannelsRenderer.createIpChannelRow(ip, privacyMode)

    // Reflected by MainActivityUiRenderingTest (name + arity). Card
    // visibility and the progress reset stay here — they touch activity
    // state shared with the loading flow.
    private fun displayBypass(bypass: BypassResult, privacyMode: Boolean = false) {
        cardBypass.visibility = View.VISIBLE
        resetBypassProgress()
        bypassRenderer.render(bypass, iconBypass, statusBypass, findingsBypass, privacyMode)
    }

    // Reflected by MainActivityUiRenderingTest (name + arity).
    private fun displayCallTransport(
        leaks: List<CallTransportLeakResult>,
        stunGroups: List<StunProbeGroupResult>,
        privacyMode: Boolean,
    ) {
        callTransportRenderer.render(
            leaks,
            stunGroups,
            cardCallTransport,
            iconCallTransport,
            statusCallTransport,
            textCallTransportSummary,
            stunGroupsContainer,
            findingsCallTransport,
            privacyMode,
        )
    }

    private fun displayNativeSigns(result: CategoryResult, privacyMode: Boolean) {
        categoryCards.renderNativeSigns(
            result,
            cardNativeSigns,
            iconNativeSigns,
            statusNativeSigns,
            textNativeSignsSummary,
            findingsNativeSigns,
            privacyMode,
        )
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

    private fun statusVisual(status: StatusSemantic): StatusVisual {
        return StatusVisualResolver.resolve(this, status, colorVisionMode())
    }

    private fun statusColor(status: StatusSemantic): Int = statusVisual(status).accentColor

    private fun statusLabel(status: StatusSemantic): String = getString(statusVisual(status).labelRes)

    private fun colorVisionMode(): ColorVisionMode {
        return ColorVisionMode.fromPref(
            prefs.getString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.OFF.prefValue),
        )
    }

    private fun displayVerdict(result: CheckResult, privacyMode: Boolean) {
        cardVerdict.visibility = View.VISIBLE
        isVerdictDetailsExpanded = false

        when (result.verdict) {
            Verdict.NOT_DETECTED -> {
                val visual = statusVisual(StatusSemantic.CLEAN)
                iconVerdict.setImageResource(visual.iconRes)
                iconVerdict.imageTintList = ColorStateList.valueOf(visual.accentColor)
                textVerdict.text = getString(R.string.main_verdict_not_detected)
                textVerdict.setTextColor(visual.accentColor)
                cardVerdict.setCardBackgroundColor(visual.containerColor)
            }
            Verdict.NEEDS_REVIEW -> {
                val visual = statusVisual(StatusSemantic.REVIEW)
                iconVerdict.setImageResource(visual.iconRes)
                iconVerdict.imageTintList = ColorStateList.valueOf(visual.accentColor)
                textVerdict.text = getString(R.string.main_verdict_needs_review)
                textVerdict.setTextColor(visual.accentColor)
                cardVerdict.setCardBackgroundColor(visual.containerColor)
            }
            Verdict.DETECTED -> {
                val visual = statusVisual(StatusSemantic.DETECTED)
                iconVerdict.setImageResource(visual.iconRes)
                iconVerdict.imageTintList = ColorStateList.valueOf(visual.accentColor)
                textVerdict.text = getString(R.string.main_verdict_detected)
                textVerdict.setTextColor(visual.accentColor)
                cardVerdict.setCardBackgroundColor(visual.containerColor)
            }
        }

        bindVerdictNarrative(VerdictNarrativeBuilder.build(this, result, privacyMode))
        bindWhitelistWarningBanner(result.operatorWhitelistProbe?.whitelistDetected == true)
    }

    private fun bindWhitelistWarningBanner(show: Boolean) {
        whitelistWarningBanner.visibility = if (show) View.VISIBLE else View.GONE
    }

    private fun bindVerdictNarrative(narrative: VerdictNarrative) {
        textVerdictExplanation.text = narrative.explanation
        textVerdictExplanation.visibility = View.VISIBLE

        bindHomeRoutedRoamingNote(narrative.homeRoutedRoamingNote)

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

    private fun bindHomeRoutedRoamingNote(note: String?) {
        if (note != null) {
            textVerdictHomeRoutedRoamingNote.text = note
            textVerdictHomeRoutedRoamingNote.visibility = View.VISIBLE
            textVerdictHomeRoutedRoamingNote.setTextColor(onSurfaceColor())
            textVerdictHomeRoutedRoamingNote.setBackgroundResource(
                R.drawable.bg_verdict_home_routed_roaming_note,
            )
            verdictHomeRoutedRoamingNote.text = note
            verdictHomeRoutedRoamingNote.visibility = View.VISIBLE
        } else {
            textVerdictHomeRoutedRoamingNote.text = ""
            textVerdictHomeRoutedRoamingNote.visibility = View.GONE
            verdictHomeRoutedRoamingNote.text = ""
            verdictHomeRoutedRoamingNote.visibility = View.GONE
        }
    }

    private fun addVerdictSection(title: String, content: List<View>) {
        if (content.isEmpty()) return

        if (verdictDetailsContent.isNotEmpty()) {
            verdictDetailsContent.addView(
                View(themedContext()).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        1.dp,
                    ).apply {
                        topMargin = 12.dp
                        bottomMargin = 12.dp
                    }
                    setBackgroundColor(outlineVariantColor())
                    alpha = 0.7f
                },
            )
        }

        verdictDetailsContent.addView(createVerdictSectionTitleView(title))
        content.forEach { verdictDetailsContent.addView(it) }
    }

    private fun createVerdictSectionTitleView(title: String): View {
        return TextView(themedContext()).apply {
            text = title
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = true
            letterSpacing = 0.05f
            setPadding(0, 0, 0, 6.dp)
            setTextColor(onSurfaceVariantColor())
        }
    }

    private fun createVerdictBulletView(text: String): View {
        val row = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val bullet = TextView(themedContext()).apply {
            this.text = "•"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val body = TextView(themedContext()).apply {
            this.text = text
            textSize = 13f
            setLineSpacing(2.dp.toFloat(), 1f)
            setTextColor(onSurfaceColor())
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
        bindHomeRoutedRoamingNote(null)
        bindWhitelistWarningBanner(false)
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

    companion object {
        private const val PREF_RATIONALE_SHOWN = "permissions_rationale_shown"
        private const val PREF_REQUESTED_PERMISSIONS = "requested_permissions"
        private const val LOADING_STATUS_FRAME_MS = 420L
        private const val AUTO_SCROLL_LOCK_MS = 450L

        private const val CATEGORY_GEO = CategoryTiles.GEO
        private const val CATEGORY_IPC = CategoryTiles.IPC
        private const val CATEGORY_CDN = CategoryTiles.CDN
        private const val CATEGORY_IPS = CategoryTiles.IPS
        private const val CATEGORY_DIR = CategoryTiles.DIR
        private const val CATEGORY_IND = CategoryTiles.IND
        private const val CATEGORY_STN = CategoryTiles.STN
        private const val CATEGORY_ICM = CategoryTiles.ICM
        private const val CATEGORY_RTT = CategoryTiles.RTT
        private const val CATEGORY_LOC = CategoryTiles.LOC
        private const val CATEGORY_BYP = CategoryTiles.BYP
        private const val CATEGORY_NAT = CategoryTiles.NAT
        private const val CATEGORY_REA = CategoryTiles.REA

        private const val TILE_STATUS_NEUTRAL = 0
        private const val TILE_STATUS_CLEAN = 1
        private const val TILE_STATUS_REVIEW = 2
        private const val TILE_STATUS_DETECTED = 3
        private const val TILE_STATUS_ERROR = 4
    }

    private fun onTileClicked(id: String) {
        if (expandedCategoryIds.contains(id)) {
            collapseCategory(id)
        } else {
            expandCategory(id)
        }
    }

    private fun beginCategoryTransition() {
        TransitionManager.beginDelayedTransition(categoryContainer, AutoTransition().apply {
            duration = 200L
        })
    }

    private fun collapseCategory(id: String) {
        if (!expandedCategoryIds.contains(id)) return
        val holder = tiles[id] ?: return
        beginCategoryTransition()
        setTileExpanded(holder, expanded = false)
        expandedCategoryIds.remove(id)
    }

    private fun collapseExpanded() {
        if (expandedCategoryIds.isEmpty()) return
        beginCategoryTransition()
        expandedCategoryIds.toList().forEach { currentId ->
            tiles[currentId]?.let { holder ->
                setTileExpanded(holder, expanded = false)
            }
        }
        expandedCategoryIds.clear()
    }

    private fun expandCategory(id: String) {
        if (expandedCategoryIds.contains(id)) return
        val holder = tiles[id] ?: return
        beginCategoryTransition()
        setTileExpanded(holder, expanded = true)
        expandedCategoryIds.add(id)
    }

    private fun setTileExpanded(holder: TileHolder, expanded: Boolean) {
        holder.body.visibility = if (expanded) View.VISIBLE else View.GONE
        holder.header.setBackgroundResource(
            if (expanded) {
                R.drawable.bg_category_header_expanded
            } else {
                R.drawable.bg_category_header_collapsed
            },
        )
        holder.chevron.animate()
            .rotation(if (expanded) 90f else 0f)
            .setDuration(200L)
            .start()
        if (expanded) {
            syncExpandedCategoryHint(holder.id)
        }
    }

    private fun setTileStatus(id: String, status: Int, hint: String?) {
        val holder = tiles[id] ?: return
        val previousStatus = holder.statusDot.tag as? Int
        val semantic = semanticForTileStatus(status)
        holder.statusDot.background = StatusVisualResolver.indicatorDrawable(this, semantic, colorVisionMode())
        holder.statusDot.tag = status
        if (hint != null) {
            holder.hint.text = hint
        }
        holder.statusDot.contentDescription = statusLabel(semantic)
        holder.header.contentDescription = buildString {
            append(holder.title.text)
            append(". ")
            append(statusLabel(semantic))
            holder.hint.text?.takeIf { it.isNotBlank() }?.let { currentHint ->
                append(". ")
                append(currentHint)
            }
        }
        if (
            (status == TILE_STATUS_REVIEW || status == TILE_STATUS_DETECTED || status == TILE_STATUS_ERROR) &&
            previousStatus != status
        ) {
            expandCategory(id)
        }
    }

    private fun semanticForTileStatus(status: Int): StatusSemantic {
        return when (status) {
            TILE_STATUS_CLEAN -> StatusSemantic.CLEAN
            TILE_STATUS_REVIEW -> StatusSemantic.REVIEW
            TILE_STATUS_DETECTED -> StatusSemantic.DETECTED
            TILE_STATUS_ERROR -> StatusSemantic.ERROR
            else -> StatusSemantic.NEUTRAL
        }
    }

    private fun resetAllTiles() {
        tiles.keys.forEach { id ->
            setTileStatus(id, TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_placeholder))
        }
        if (expandedCategoryIds.isNotEmpty()) {
            collapseExpanded()
        }
    }

    private fun statusFromCategory(detected: Boolean, needsReview: Boolean, hasError: Boolean): Int {
        return when {
            hasError -> TILE_STATUS_ERROR
            detected -> TILE_STATUS_DETECTED
            needsReview -> TILE_STATUS_REVIEW
            else -> TILE_STATUS_CLEAN
        }
    }

    private fun updateTileFromCategory(id: String, category: CategoryResult) {
        val status = statusFromCategory(category.detected, category.needsReview, category.hasError)
        val hint = buildTileHintForCategory(category)
        setTileStatus(id, status, hint)
    }

    private fun updateTileFromIpComparison(result: IpComparisonResult) {
        val status = statusFromCategory(result.detected, result.needsReview, result.hasError)
        val ru = result.ruGroup.responses.size
        val nonRu = result.nonRuGroup.responses.size
        val total = ru + nonRu
        val hint = when {
            result.hasError -> getString(R.string.tile_hint_error)
            result.detected -> getString(R.string.tile_hint_review)
            result.needsReview -> getString(R.string.tile_hint_review)
            total > 0 -> getString(R.string.tile_hint_clean_count, total)
            else -> null
        }
        setTileStatus(CATEGORY_IPC, status, hint)
    }

    private fun updateTileFromCdn(result: CdnPullingResult) {
        val status = statusFromCategory(result.detected, result.needsReview, result.hasError)
        val total = result.responses.size
        val hint = when {
            result.hasError -> getString(R.string.tile_hint_error)
            result.detected -> getString(R.string.tile_hint_review)
            result.needsReview -> getString(R.string.tile_hint_review)
            total > 0 -> getString(R.string.tile_hint_clean_count, total)
            else -> null
        }
        setTileStatus(CATEGORY_CDN, status, hint)
    }

    private fun updateTileFromBypass(result: BypassResult) {
        val status = statusFromCategory(result.detected, result.needsReview, result.hasError)
        val hint = when {
            result.hasError -> getString(R.string.tile_hint_error)
            result.detected -> getString(R.string.tile_hint_review)
            result.needsReview -> getString(R.string.tile_hint_review)
            else -> getString(R.string.tile_hint_clean)
        }
        setTileStatus(CATEGORY_BYP, status, hint)
    }

    private fun updateTileFromIpConsensus(result: IpConsensusResult) {
        val hasDetectedSignal = result.crossChannelMismatch ||
            result.warpLikeIndicator ||
            result.probeTargetDivergence ||
            result.probeTargetDirectDivergence ||
            result.geoCountryMismatch ||
            result.foreignIps.isNotEmpty()
        val hasReviewSignal = result.channelConflict.isNotEmpty() || result.needsReview
        val observedCount = result.observedIps.size
        val status = when {
            hasDetectedSignal -> TILE_STATUS_DETECTED
            hasReviewSignal -> TILE_STATUS_REVIEW
            observedCount > 0 -> TILE_STATUS_CLEAN
            else -> TILE_STATUS_NEUTRAL
        }
        val hint = when {
            hasDetectedSignal || hasReviewSignal -> getString(R.string.tile_hint_review)
            observedCount > 0 -> getString(R.string.tile_hint_clean_count, observedCount)
            else -> getString(R.string.tile_hint_placeholder)
        }
        setTileStatus(CATEGORY_IPS, status, hint)
    }

    private fun updateTileFromCallTransport(leaks: List<CallTransportLeakResult>, stunGroups: List<StunProbeGroupResult>) {
        val respondedCount = stunGroups.sumOf { it.respondedCount }
        val totalCount = stunGroups.sumOf { it.totalCount }
        val hasNeedsReview = leaks.any { it.status == CallTransportStatus.NEEDS_REVIEW }
        val hasError = leaks.any { it.status == CallTransportStatus.ERROR }
        if (leaks.isEmpty() && totalCount == 0) {
            setTileStatus(CATEGORY_STN, TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_placeholder))
            return
        }
        val status = when {
            hasError -> TILE_STATUS_ERROR
            hasNeedsReview -> TILE_STATUS_REVIEW
            else -> TILE_STATUS_CLEAN
        }
        val hint = when {
            hasError -> getString(R.string.tile_hint_error)
            totalCount > 0 -> getString(R.string.main_card_call_transport_stun_responded, respondedCount, totalCount)
            else -> getString(R.string.tile_hint_clean_count, leaks.size)
        }
        setTileStatus(CATEGORY_STN, status, hint)
    }

    private fun isCallTransportTileLoading(): Boolean {
        val holder = tiles[CATEGORY_STN] ?: return false
        return holder.statusDot.tag == TILE_STATUS_NEUTRAL &&
            holder.hint.text?.toString() == getString(R.string.tile_hint_loading)
    }

    private fun syncExpandedCategoryHint(id: String) {
        when (id) {
            CATEGORY_GEO -> {
                if (geoIpInfoSection.childCount > 0 || findingsGeoIp.childCount > 0) return
                syncHintOnlyContainer(findingsGeoIp, previewMessageForCategory(id))
            }
            CATEGORY_IPC -> {
                if (textIpComparisonSummary.text?.isNotBlank() == true || ipComparisonGroups.childCount > 0) return
                textIpComparisonSummary.text = previewMessageForCategory(id)
                textIpComparisonSummary.visibility = View.VISIBLE
            }
            CATEGORY_CDN -> {
                if (textCdnPullingSummary.text?.isNotBlank() == true || cdnPullingResponses.childCount > 0) return
                textCdnPullingSummary.text = previewMessageForCategory(id)
                textCdnPullingSummary.visibility = View.VISIBLE
            }
            CATEGORY_DIR -> {
                if (directInfoSection.childCount > 0 || findingsDirect.childCount > 0) return
                syncHintOnlyContainer(findingsDirect, previewMessageForCategory(id))
            }
            CATEGORY_IND -> {
                if (findingsIndirect.childCount > 0) return
                syncHintOnlyContainer(findingsIndirect, previewMessageForCategory(id))
            }
            CATEGORY_NAT -> {
                if ((textNativeSignsSummary.text?.isNotBlank() == true && textNativeSignsSummary.visibility == View.VISIBLE) || findingsNativeSigns.childCount > 0) return
                syncHintOnlyContainer(findingsNativeSigns, previewMessageForCategory(id))
            }
            CATEGORY_STN -> {
                val hasSummary = textCallTransportSummary.visibility == View.VISIBLE &&
                    textCallTransportSummary.text?.isNotBlank() == true
                if (hasSummary || stunGroupsContainer.childCount > 0 || findingsCallTransport.childCount > 0) return
                syncHintOnlyContainer(
                    findingsCallTransport,
                    if (isCallTransportTileLoading()) {
                        getString(R.string.main_loading_call_transport)
                    } else {
                        previewMessageForCategory(id)
                    },
                )
            }
            CATEGORY_ICM -> {
                if (findingsIcmpSpoofing.childCount > 0) return
                syncHintOnlyContainer(findingsIcmpSpoofing, previewMessageForCategory(id))
            }
            CATEGORY_RTT -> {
                if (findingsRttTriangulation.childCount > 0) return
                syncHintOnlyContainer(findingsRttTriangulation, previewMessageForCategory(id))
            }
            CATEGORY_LOC -> {
                if (locationInfoSection.childCount > 0 || findingsLocation.childCount > 0) return
                syncHintOnlyContainer(findingsLocation, previewMessageForCategory(id))
            }
            CATEGORY_BYP -> {
                if ((textBypassProgress.text?.isNotBlank() == true && textBypassProgress.visibility == View.VISIBLE) || findingsBypass.childCount > 0) return
                textBypassProgress.text = previewMessageForCategory(id)
                textBypassProgress.visibility = View.VISIBLE
            }
            CATEGORY_REA -> {
                if (findingsDomainReachability.childCount > 0) return
                syncHintOnlyContainer(findingsDomainReachability, previewMessageForCategory(id))
            }
        }
    }

    private fun previewMessageForCategory(id: String): String {
        return when (id) {
            CATEGORY_GEO -> getString(R.string.main_preview_geo_ip)
            CATEGORY_IPC -> getString(R.string.main_preview_ip_comparison)
            CATEGORY_CDN -> getString(R.string.main_preview_cdn_pulling)
            CATEGORY_DIR -> getString(R.string.main_preview_direct)
            CATEGORY_IND -> getString(R.string.main_preview_indirect)
            CATEGORY_NAT -> getString(R.string.main_preview_native_signs)
            CATEGORY_STN -> getString(R.string.main_preview_call_transport)
            CATEGORY_ICM -> getString(R.string.main_preview_icmp)
            CATEGORY_RTT -> getString(R.string.main_preview_rtt_triangulation)
            CATEGORY_LOC -> getString(R.string.main_preview_location)
            CATEGORY_BYP -> getString(R.string.main_preview_bypass)
            CATEGORY_REA -> getString(R.string.main_preview_domain_reachability)
            else -> getString(R.string.tile_hint_placeholder)
        }
    }

    private fun syncHintOnlyContainer(container: LinearLayout, message: String) {
        if (container.childCount > 0) return
        container.removeAllViews()
        container.addView(findingViews.createLoadingHintView(message))
        container.visibility = View.VISIBLE
    }

    private fun buildTileHintForCategory(category: CategoryResult): String {
        val nonInfo = category.findings.filterNot { it.isInformational || it.isError }
        val detected = nonInfo.count { it.detected }
        val total = nonInfo.size
        return when {
            category.hasError -> getString(R.string.tile_hint_error)
            category.detected && total > 0 -> getString(R.string.tile_hint_detected_count, detected, total)
            category.detected -> getString(R.string.tile_hint_review)
            category.needsReview -> getString(R.string.tile_hint_review)
            total > 0 -> getString(R.string.tile_hint_clean_count, total)
            else -> getString(R.string.tile_hint_clean)
        }
    }

    private fun bindVerdictHeroIdle() {
        val visual = statusVisual(StatusSemantic.NEUTRAL)
        applyVerdictHeroColors(visual)
        verdictAvatarIcon.setImageResource(visual.iconRes)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(R.string.verdict_title_idle)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_idle)
        bindHomeRoutedRoamingNote(null)
        bindWhitelistWarningBanner(false)
    }

    private fun bindVerdictHeroRunning() {
        val visual = statusVisual(StatusSemantic.NEUTRAL)
        applyVerdictHeroColors(visual)
        verdictAvatarIcon.setImageResource(visual.iconRes)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(R.string.verdict_title_idle)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_running)
        bindHomeRoutedRoamingNote(null)
        bindWhitelistWarningBanner(false)
    }

    private fun bindVerdictHero(result: CheckResult) {
        val (semantic, titleRes) = when (result.verdict) {
            Verdict.NOT_DETECTED -> StatusSemantic.CLEAN to R.string.verdict_title_clean
            Verdict.NEEDS_REVIEW -> StatusSemantic.REVIEW to R.string.verdict_title_review
            Verdict.DETECTED -> StatusSemantic.DETECTED to R.string.verdict_title_detected
        }
        val visual = statusVisual(semantic)
        applyVerdictHeroColors(visual)
        verdictAvatarIcon.setImageResource(visual.iconRes)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(titleRes)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_done, tiles.size)
        bindWhitelistWarningBanner(result.operatorWhitelistProbe?.whitelistDetected == true)
    }

    private fun applyVerdictHeroColors(visual: StatusVisual) {
        verdictHero.setCardBackgroundColor(visual.containerColor)
        verdictTitle.setTextColor(visual.accentColor)
        verdictLabel.setTextColor(visual.accentColor)
        val avatarBg = android.graphics.drawable.GradientDrawable().apply {
            shape = android.graphics.drawable.GradientDrawable.OVAL
            setColor(visual.accentColor)
        }
        verdictAvatar.background = avatarBg
    }
}
