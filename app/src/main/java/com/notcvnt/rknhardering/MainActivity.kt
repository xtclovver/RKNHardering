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
import android.view.Gravity
import android.view.View
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
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.notcvnt.rknhardering.checker.BypassChecker
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpFamily
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.ObservedIp
import com.notcvnt.rknhardering.model.StunProbeGroupResult
import com.notcvnt.rknhardering.model.StunScope
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException
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

internal fun maskInfoValue(value: String, privacyMode: Boolean): String {
    return if (privacyMode) maskIpsInText(value) else value
}

private const val CALL_TRANSPORT_NO_STUN_RESPONSE_MARKER = "did not receive a STUN response"
private const val CALL_TRANSPORT_TELEGRAM_DC_UNREACHABLE_MARKER = "did not expose a reachable Telegram DC"

internal fun formatCallTransportReason(
    context: android.content.Context,
    leak: CallTransportLeakResult,
    privacyMode: Boolean,
): String? {
    val summary = leak.summary.trim()
    return when {
        leak.status == CallTransportStatus.BASELINE || leak.status == CallTransportStatus.NEEDS_REVIEW -> null
        summary.contains(CALL_TRANSPORT_NO_STUN_RESPONSE_MARKER, ignoreCase = true) ->
            buildCallTransportReason(
                base = context.getString(R.string.main_card_call_transport_reason_no_response),
                detail = summaryDetailAfterMarker(summary, CALL_TRANSPORT_NO_STUN_RESPONSE_MARKER),
                privacyMode = privacyMode,
            )
        summary.contains(CALL_TRANSPORT_TELEGRAM_DC_UNREACHABLE_MARKER, ignoreCase = true) ->
            buildCallTransportReason(
                base = context.getString(R.string.main_card_call_transport_reason_telegram_dc_unreachable),
                detail = summaryDetailAfterMarker(summary, CALL_TRANSPORT_TELEGRAM_DC_UNREACHABLE_MARKER),
                privacyMode = privacyMode,
            )
        summary.contains("targets are unavailable", ignoreCase = true) ||
            summary.contains("target catalog is unavailable", ignoreCase = true) ->
            context.getString(R.string.main_card_call_transport_reason_targets_unavailable)
        else -> maskInfoValue(summary, privacyMode)
    }
}

private fun buildCallTransportReason(base: String, detail: String?, privacyMode: Boolean): String {
    val maskedDetail = detail
        ?.takeIf { it.isNotBlank() }
        ?.let { maskInfoValue(it, privacyMode) }
    return if (maskedDetail.isNullOrBlank()) base else "$base: $maskedDetail"
}

private fun summaryDetailAfterMarker(summary: String, marker: String): String? {
    val tail = summary.substringAfter(marker, missingDelimiterValue = "").trim()
    return tail.removePrefix(":").trim().takeIf { it.isNotBlank() }
}

private fun isUniqueLocalIpv6(address: Inet6Address): Boolean {
    val firstByte = address.address.firstOrNull()?.toInt()?.and(0xff) ?: return false
    return (firstByte and 0xfe) == 0xfc
}

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
        LOCATION,
        IP_CONSENSUS,
        BYPASS,
    }

    private lateinit var btnRunCheck: MaterialButton
    private lateinit var btnStopCheck: MaterialButton
    private lateinit var btnCopyDiagnostics: MaterialButton
    private lateinit var btnExport: MaterialButton
    private lateinit var resultActionsContainer: LinearLayout
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
    private var activeCheckSettings: CheckSettings? = null
    private var retainedDiagnosticsSnapshot: RetainedDiagnosticsSnapshot? = null
    private var completedExportSnapshot: CompletedExportSnapshot? = null
    private var isVerdictDetailsExpanded = false

    // Redesign
    private lateinit var mainContentRoot: LinearLayout
    private lateinit var categoryGrid: android.widget.GridLayout
    private lateinit var verdictHero: MaterialCardView
    private lateinit var verdictAvatar: View
    private lateinit var verdictAvatarIcon: ImageView
    private lateinit var verdictLabel: TextView
    private lateinit var verdictTitle: TextView
    private lateinit var verdictSubtitle: TextView
    private lateinit var expandedDetail: MaterialCardView
    private lateinit var detailIcon: ImageView
    private lateinit var detailTitle: TextView
    private lateinit var detailStatusChip: TextView
    private lateinit var detailContentSlot: android.widget.FrameLayout
    private lateinit var hiddenLegacyCardsHost: LinearLayout
    private lateinit var btnPrivacyInfo: MaterialButton
    private val tiles = mutableMapOf<String, TileHolder>()
    private var expandedCategoryId: String? = null
    private var lastCompletedResult: CheckResult? = null

    private data class TileHolder(
        val id: String,
        val card: MaterialCardView,
        val icon: ImageView,
        val statusDot: View,
        val title: TextView,
        val hint: TextView,
    )

    private val prefs by lazy { AppUiSettings.prefs(this) }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        markPermissionsRequested(result.keys)
        prefs.edit { putBoolean(PREF_RATIONALE_SHOWN, true) }
    }

    private val exportMarkdownLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument(ExportFormat.MARKDOWN.mimeType),
    ) { uri ->
        writeExportDocument(uri, ExportFormat.MARKDOWN)
    }

    private val exportJsonLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument(ExportFormat.JSON.mimeType),
    ) { uri ->
        writeExportDocument(uri, ExportFormat.JSON)
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

        btnRunCheck.setOnClickListener { onRunCheckClicked() }
        btnStopCheck.setOnClickListener { viewModel.cancelScan() }
        btnCopyDiagnostics.setOnClickListener { copyTunProbeDiagnostics() }
        btnExport.setOnClickListener { showExportFormatDialog() }
        observeScanEvents()

        if (intent.getBooleanExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS, false)) {
            intent.removeExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS)
            reRequestPermissions()
        } else if (!prefs.getBoolean(PREF_RATIONALE_SHOWN, false)) {
            showPermissionRationale()
        }

        checkForAppUpdates()
    }

    private fun checkForAppUpdates() {
        lifecycleScope.launch {
            val updateInfo = AppUpdateChecker.fetchLatestRelease() ?: return@launch
            val currentVersion = BuildConfig.VERSION_NAME
            if (!AppUpdateChecker.isNewerVersion(currentVersion, updateInfo.latestVersion)) return@launch
            if (AppUpdateChecker.isVersionSkipped(this@MainActivity, updateInfo.latestVersion)) return@launch
            AppUpdateChecker.showUpdateDialog(this@MainActivity, currentVersion, updateInfo)
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
        btnStopCheck = findViewById(R.id.btnStopCheck)
        btnCopyDiagnostics = findViewById(R.id.btnCopyDiagnostics)
        btnExport = findViewById(R.id.btnExport)
        resultActionsContainer = findViewById(R.id.resultActionsContainer)
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

        // Redesign bindings
        mainContentRoot = findViewById(R.id.mainContentRoot)
        categoryGrid = findViewById(R.id.categoryGrid)
        verdictHero = findViewById(R.id.verdictHero)
        verdictAvatar = findViewById(R.id.verdictAvatar)
        verdictAvatarIcon = findViewById(R.id.verdictAvatarIcon)
        verdictLabel = findViewById(R.id.verdictLabel)
        verdictTitle = findViewById(R.id.verdictTitle)
        verdictSubtitle = findViewById(R.id.verdictSubtitle)
        expandedDetail = findViewById(R.id.expandedDetail)
        detailIcon = findViewById(R.id.detailIcon)
        detailTitle = findViewById(R.id.detailTitle)
        detailStatusChip = findViewById(R.id.detailStatusChip)
        detailContentSlot = findViewById(R.id.detailContentSlot)
        hiddenLegacyCardsHost = findViewById(R.id.hiddenLegacyCardsHost)
        btnPrivacyInfo = findViewById(R.id.btnPrivacyInfo)
        btnPrivacyInfo.setOnClickListener { showPrivacyFooterDialog() }

        setupCategoryGrid()
        bindVerdictHeroIdle()
        setupResultsScrollTracking()
        updateCheckControls(isRunning = false)
        updateResultActionButtonsVisibility()
    }

    private fun setupCategoryGrid() {
        categoryGrid.removeAllViews()
        tiles.clear()
        val inflater = layoutInflater
        val columnCount = 2
        val gap = 8.dp
        data class Spec(val id: String, val title: String, val iconRes: Int)
        val specs = listOf(
            Spec(CATEGORY_GEO, getString(R.string.main_card_geo_ip), R.drawable.ic_globe),
            Spec(CATEGORY_IPC, getString(R.string.main_card_ip_comparison), R.drawable.ic_compare),
            Spec(CATEGORY_CDN, getString(R.string.main_card_cdn_pulling), R.drawable.ic_cloud),
            Spec(CATEGORY_IPS, getString(R.string.ip_channels_title), R.drawable.ic_compare),
            Spec(CATEGORY_DIR, getString(R.string.main_card_direct_signs), R.drawable.ic_shield),
            Spec(CATEGORY_IND, getString(R.string.main_card_indirect_signs), R.drawable.ic_network),
            Spec(CATEGORY_STN, getString(R.string.main_card_call_transport), R.drawable.ic_phone),
            Spec(CATEGORY_LOC, getString(R.string.main_card_location_signals), R.drawable.ic_pin),
            Spec(CATEGORY_BYP, getString(R.string.settings_split_tunnel), R.drawable.ic_split),
            Spec(CATEGORY_NAT, getString(R.string.checker_native_card_title), R.drawable.ic_shield),
        )
        specs.forEachIndexed { index, spec ->
            val tile = inflater.inflate(R.layout.view_category_tile, categoryGrid, false) as MaterialCardView
            val row = index / columnCount
            val col = index % columnCount
            val lp = android.widget.GridLayout.LayoutParams().apply {
                width = 0
                height = android.widget.GridLayout.LayoutParams.WRAP_CONTENT
                columnSpec = android.widget.GridLayout.spec(col, 1, 1f)
                rowSpec = android.widget.GridLayout.spec(row)
                setMargins(
                    if (col == 0) 0 else gap / 2,
                    if (row == 0) 0 else gap,
                    if (col == columnCount - 1) 0 else gap / 2,
                    0,
                )
            }
            tile.layoutParams = lp
            val tileIcon = tile.findViewById<ImageView>(R.id.tileIcon)
            val tileStatusDot = tile.findViewById<View>(R.id.tileStatusDot)
            val tileTitle = tile.findViewById<TextView>(R.id.tileTitle)
            val tileHint = tile.findViewById<TextView>(R.id.tileHint)
            tileIcon.setImageResource(spec.iconRes)
            tileTitle.text = spec.title
            tileHint.text = getString(R.string.tile_hint_placeholder)
            val holder = TileHolder(spec.id, tile, tileIcon, tileStatusDot, tileTitle, tileHint)
            tiles[spec.id] = holder
            tile.setOnClickListener { onTileClicked(spec.id) }
            categoryGrid.addView(tile)
        }
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

    private fun showExportFormatDialog() {
        if (completedExportSnapshot == null) return
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.main_export_title)
            .setPositiveButton(R.string.main_export_markdown) { _, _ ->
                onExportFormatSelected(ExportFormat.MARKDOWN)
            }
            .setNegativeButton(R.string.main_export_json) { _, _ ->
                onExportFormatSelected(ExportFormat.JSON)
            }
            .setNeutralButton(android.R.string.cancel, null)
            .show()
    }

    private fun onExportFormatSelected(format: ExportFormat) {
        if (isDebugClipboardExportEnabled()) {
            showExportActionDialog(format)
        } else {
            launchExport(format)
        }
    }

    private fun showExportActionDialog(format: ExportFormat) {
        MaterialAlertDialogBuilder(this)
            .setTitle(
                when (format) {
                    ExportFormat.MARKDOWN -> R.string.main_export_markdown
                    ExportFormat.JSON -> R.string.main_export_json
                },
            )
            .setPositiveButton(R.string.main_export_save_file) { _, _ ->
                launchExport(format)
            }
            .setNegativeButton(R.string.main_export_copy_to_clipboard) { _, _ ->
                copyExportToClipboard(format)
            }
            .setNeutralButton(android.R.string.cancel, null)
            .show()
    }

    private fun launchExport(format: ExportFormat) {
        val snapshot = completedExportSnapshot ?: return
        val defaultFileName = buildDefaultExportFileName(format, snapshot.finishedAtMillis)
        when (format) {
            ExportFormat.MARKDOWN -> exportMarkdownLauncher.launch(defaultFileName)
            ExportFormat.JSON -> exportJsonLauncher.launch(defaultFileName)
        }
    }

    private fun copyExportToClipboard(format: ExportFormat) {
        val snapshot = completedExportSnapshot ?: return
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val labelResId = when (format) {
            ExportFormat.MARKDOWN -> R.string.main_export_markdown
            ExportFormat.JSON -> R.string.main_export_json
        }
        clipboard.setPrimaryClip(
            ClipData.newPlainText(
                getString(labelResId),
                buildExportContent(snapshot, format),
            ),
        )
        Toast.makeText(this, R.string.main_export_copied, Toast.LENGTH_SHORT).show()
    }

    private fun writeExportDocument(uri: Uri?, format: ExportFormat) {
        val targetUri = uri ?: return
        val snapshot = completedExportSnapshot ?: return
        val content = buildExportContent(snapshot, format)
        val exportResult = runCatching {
            contentResolver.openOutputStream(targetUri)?.use { outputStream ->
                outputStream.writer(Charsets.UTF_8).use { writer ->
                    writer.write(content)
                }
            } ?: throw IOException("Unable to open export destination")
        }
        if (exportResult.isSuccess) {
            Toast.makeText(this, R.string.main_export_saved, Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, R.string.main_export_failed, Toast.LENGTH_SHORT).show()
        }
    }

    private fun buildExportContent(
        snapshot: CompletedExportSnapshot,
        format: ExportFormat,
    ): String {
        return when (format) {
            ExportFormat.MARKDOWN -> CheckResultMarkdownExportFormatter.format(this, snapshot)
            ExportFormat.JSON -> CheckResultJsonExportFormatter.format(this, snapshot)
        }
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
        btnCopyDiagnostics.visibility = if (canShow) View.VISIBLE else View.GONE
    }

    private fun updateExportVisibility() {
        btnExport.visibility = if (completedExportSnapshot != null) View.VISIBLE else View.GONE
    }

    private fun updateResultActionButtonsVisibility() {
        updateCopyDiagnosticsVisibility()
        updateExportVisibility()
        resultActionsContainer.visibility = if (
            btnCopyDiagnostics.visibility == View.VISIBLE || btnExport.visibility == View.VISIBLE
        ) {
            View.VISIBLE
        } else {
            View.GONE
        }
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

        val settings = CheckSettings(
            splitTunnelEnabled = splitTunnelEnabled,
            proxyScanEnabled = proxyScanEnabled,
            xrayApiScanEnabled = xrayApiScanEnabled,
            networkRequestsEnabled = networkRequestsEnabled,
            callTransportProbeEnabled = callTransportProbeEnabled,
            cdnPullingEnabled = cdnPullingEnabled,
            cdnPullingMeduzaEnabled = cdnPullingMeduzaEnabled,
            tunProbeDebugEnabled = tunProbeDebugEnabled,
            tunProbeModeOverride = tunProbeModeOverride,
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
                statusBypass.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
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

        findingsBypass.removeAllViews()
        findingsBypass.visibility = View.GONE

        ipChannelsContainer.removeAllViews()
        cardIpChannels.visibility = View.GONE

        clearVerdictCard()
    }

    private fun enabledStages(settings: CheckSettings): List<RunningStage> {
        val stages = mutableListOf<RunningStage>()
        if (settings.networkRequestsEnabled) {
            stages += RunningStage.GEO_IP
            stages += RunningStage.IP_COMPARISON
            if (settings.cdnPullingEnabled) {
                stages += RunningStage.CDN_PULLING
            }
        }
        stages += RunningStage.DIRECT
        stages += RunningStage.INDIRECT
        stages += RunningStage.LOCATION
        if (settings.networkRequestsEnabled || settings.splitTunnelEnabled) {
            stages += RunningStage.IP_CONSENSUS
        }
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
                updateTileFromCategory(CATEGORY_GEO, update.result)
                if (animate) animateContentReveal(findingsGeoIp, geoIpInfoSection, geoIpDivider)
            }
            is CheckUpdate.IpComparisonReady -> {
                markStageCompleted(RunningStage.IP_COMPARISON)
                ensureCardVisible(cardIpComparison, animate = false)
                displayIpComparison(update.result, activeCheckPrivacyMode)
                updateTileFromIpComparison(update.result)
                if (animate) animateContentReveal(textIpComparisonSummary, ipComparisonGroups)
            }
            is CheckUpdate.CdnPullingReady -> {
                markStageCompleted(RunningStage.CDN_PULLING)
                ensureCardVisible(cardCdnPulling, animate = false)
                displayCdnPulling(update.result, activeCheckPrivacyMode)
                updateTileFromCdn(update.result)
                if (animate) animateContentReveal(textCdnPullingSummary, cdnPullingResponses)
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
                updateTileFromCategory(CATEGORY_DIR, update.result)
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
                ensureCardVisible(cardLocation, animate = false)
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
                ensureCardVisible(cardBypass, animate = false)
                displayBypass(update.result, activeCheckPrivacyMode)
                updateTileFromBypass(update.result)
                if (animate) animateContentReveal(findingsBypass)
            }
            is CheckUpdate.IpConsensusReady -> {
                markStageCompleted(RunningStage.IP_CONSENSUS)
                ensureCardVisible(cardIpChannels, animate = false)
                displayIpChannels(update.result, activeCheckPrivacyMode)
                updateTileFromIpConsensus(update.result)
                if (animate) animateContentReveal(ipChannelsContainer)
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
        RunningStage.LOCATION -> CATEGORY_LOC
        RunningStage.IP_CONSENSUS -> CATEGORY_IPS
        RunningStage.BYPASS -> CATEGORY_BYP
    }

    private fun showLoadingCardForStage(stage: RunningStage) {
        if (stage in completedStages) return
        if (stage in loadingStages && cardForStage(stage).isVisible) return

        setTileStatus(tileIdForStage(stage), TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_loading))
        if (stage != RunningStage.IP_CONSENSUS) {
            loadingStages += stage
        }
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
            RunningStage.CDN_PULLING -> showCdnPullingLoading(stage)
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
            RunningStage.IP_CONSENSUS -> {
                ensureCardVisible(cardIpChannels, animate = false)
                setTileStatus(tileIdForStage(stage), TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_loading))
            }
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
                RunningStage.CDN_PULLING -> showCdnPullingStopped(stage)
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
                RunningStage.IP_CONSENSUS -> cardIpChannels.visibility = View.GONE
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

    private fun showCdnPullingStopped(stage: RunningStage) {
        iconCdnPulling.setImageResource(R.drawable.ic_help)
        statusCdnPulling.text = getString(R.string.main_status_stopped)
        statusCdnPulling.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        textCdnPullingSummary.text = stageStoppedMessage(stage)
        cdnPullingResponses.removeAllViews()
        cdnPullingResponses.visibility = View.GONE
        ensureCardVisible(cardCdnPulling, animate = false)
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
        status.setTextColor(onSurfaceVariantColor())
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
            RunningStage.DIRECT -> getString(R.string.main_loading_direct)
            RunningStage.INDIRECT -> getString(R.string.main_loading_indirect)
            RunningStage.LOCATION -> getString(R.string.main_loading_location)
            RunningStage.IP_CONSENSUS -> getString(R.string.main_loading_ip_comparison)
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
            RunningStage.CDN_PULLING -> cardCdnPulling
            RunningStage.DIRECT -> cardDirect
            RunningStage.INDIRECT -> cardIndirect
            RunningStage.LOCATION -> cardLocation
            RunningStage.IP_CONSENSUS -> cardIpChannels
            RunningStage.BYPASS -> cardBypass
        }
    }

    private fun statusViewForStage(stage: RunningStage): TextView {
        return when (stage) {
            RunningStage.GEO_IP -> statusGeoIp
            RunningStage.IP_COMPARISON -> statusIpComparison
            RunningStage.CDN_PULLING -> statusCdnPulling
            RunningStage.DIRECT -> statusDirect
            RunningStage.INDIRECT -> statusIndirect
            RunningStage.LOCATION -> statusLocation
            RunningStage.IP_CONSENSUS -> statusGeoIp
            RunningStage.BYPASS -> statusBypass
        }
    }

    private fun ensureCardVisible(
        card: MaterialCardView,
        animate: Boolean = true,
        shouldAutoScroll: Boolean = false,
    ) {
        // В редизайне все старые карточки лежат в hiddenLegacyCardsHost и никогда
        // не показываются напрямую — их контент переносится в expandedDetail
        // по тапу плитки. Auto-scroll на них тоже не имеет смысла.
        val inHiddenHost = card.parent === hiddenLegacyCardsHost
        val wasVisible = card.isVisible
        if (!wasVisible) {
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

    private fun createLoadingHintView(message: String): View {
        return TextView(themedContext()).apply {
            text = message
            textSize = 13f
            setLineSpacing(2.dp.toFloat(), 1f)
            setPadding(0, 8.dp, 0, 2.dp)
            setTextColor(onSurfaceVariantColor())
        }
    }

    private fun hideCards() {
        listOf(
            cardGeoIp,
            cardIpComparison,
            cardCdnPulling,
            cardIpChannels,
            cardDirect,
            cardIndirect,
            cardCallTransport,
            cardNativeSigns,
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
            val checkFindings = category.findings.filterNot { it.isInformational || it.isError }

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
            if (finding.isError) continue
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
                val value = maskInfoValue(parts.second, privacyMode)
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

    private fun displayCdnPulling(result: CdnPullingResult, privacyMode: Boolean = false) {
        cardCdnPulling.visibility = View.VISIBLE
        bindCardStatus(result.detected, result.needsReview, iconCdnPulling, statusCdnPulling, hasError = result.hasError)
        textCdnPullingSummary.text = if (privacyMode) maskIpsInText(result.summary) else result.summary

        cdnPullingResponses.removeAllViews()
        cdnPullingResponses.visibility = if (result.responses.isEmpty()) View.GONE else View.VISIBLE
        result.responses.forEach { response ->
            cdnPullingResponses.addView(createCdnPullingResponseView(response, privacyMode))
        }
    }

    private fun createFindingView(finding: Finding, privacyMode: Boolean = false): View {
        val row = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val indicator = TextView(themedContext()).apply {
            text = when {
                finding.detected -> "\u26A0"
                finding.needsReview -> "?"
                else -> "\u2713"
            }
            setTextColor(
                ContextCompat.getColor(
                    themedContext(),
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
        val description = TextView(themedContext()).apply {
            text = wrapForDisplay(descriptionText)
            textSize = 13f
            setTextColor(onSurfaceColor())
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
        val row = LinearLayout(themedContext()).apply {
            orientation = if (rtl) LinearLayout.VERTICAL else LinearLayout.HORIZONTAL
            gravity = if (rtl) Gravity.END else Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, if (rtl) 6.dp else 4.dp)
        }

        val labelView = TextView(themedContext()).apply {
            text = wrapForDisplay(label)
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            isAllCaps = !rtl
            letterSpacing = 0.05f
            setTextColor(onSurfaceVariantColor())
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

        val valueView = TextView(themedContext()).apply {
            text = wrapForDisplay(value)
            textSize = 13f
            setTextColor(onSurfaceColor())
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
        val card = MaterialCardView(themedContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = 8.dp
            }
            radius = 14.dp.toFloat()
            strokeWidth = 1.dp
            strokeColor = outlineVariantColor()
            setCardBackgroundColor(surfaceColor())
        }

        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(12.dp, 12.dp, 12.dp, 12.dp)
        }

        val header = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val title = TextView(themedContext()).apply {
            text = group.title
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val status = TextView(themedContext()).apply {
            text = group.statusLabel
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(ContextCompat.getColor(themedContext(), statusColorRes(group.detected, group.needsReview)))
        }

        val toggle = TextView(themedContext()).apply {
            text = if (expanded) "▼" else "▶"
            textSize = 12f
            setPadding(8.dp, 0, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val summary = TextView(themedContext()).apply {
            text = if (privacyMode) maskIpsInText(group.summary) else group.summary
            textSize = 13f
            setPadding(0, 6.dp, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val details = LinearLayout(themedContext()).apply {
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
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 8.dp, 0, 8.dp)
        }

        val topRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val label = TextView(themedContext()).apply {
            text = response.label
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val displayIp = if (privacyMode && response.ip != null) maskIp(response.ip) else response.ip
        val value = TextView(themedContext()).apply {
            text = displayIp ?: getString(R.string.main_card_status_error)
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(
                ContextCompat.getColor(
                    themedContext(),
                    if (response.ip != null) R.color.status_green else R.color.status_amber,
                ),
            )
        }

        val url = TextView(themedContext()).apply {
            text = response.url
            textSize = 12f
            setPadding(0, 4.dp, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        topRow.addView(label)
        topRow.addView(value)
        container.addView(topRow)
        container.addView(url)

        return container
    }

    private fun createCdnPullingResponseView(response: CdnPullingResponse, privacyMode: Boolean = false): View {
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 8.dp, 0, 8.dp)
        }

        val topRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val label = TextView(themedContext()).apply {
            text = response.targetLabel
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val hasDualStack = response.ipv4 != null && response.ipv6 != null
        val hasIpv6Only = response.ipv6 != null && response.ipv4 == null
        val primaryDisplayIp = response.ip

        val valueText = when {
            hasDualStack -> if (privacyMode) maskIp(response.ipv4!!) else response.ipv4!!
            hasIpv6Only && response.ipv4Unavailable -> if (privacyMode) maskIp(response.ipv6!!) else response.ipv6!!
            primaryDisplayIp != null -> if (privacyMode) maskIp(primaryDisplayIp) else primaryDisplayIp
            response.importantFields.isNotEmpty() -> getString(R.string.main_card_status_detected)
            response.error != null -> getString(R.string.main_card_status_error)
            else -> getString(R.string.main_card_status_clean)
        }
        val value = TextView(themedContext()).apply {
            text = valueText
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(
                ContextCompat.getColor(
                    themedContext(),
                    when {
                        primaryDisplayIp != null -> R.color.status_red
                        response.error != null -> R.color.status_amber
                        else -> R.color.status_green
                    },
                ),
            )
        }

        val url = TextView(themedContext()).apply {
            text = response.url
            textSize = 12f
            setPadding(0, 4.dp, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        topRow.addView(label)
        topRow.addView(value)
        container.addView(topRow)

        if (hasDualStack) {
            container.addView(
                TextView(themedContext()).apply {
                    text = if (privacyMode) maskIp(response.ipv6!!) else response.ipv6!!
                    textSize = 13f
                    typeface = Typeface.MONOSPACE
                    setPadding(0, 2.dp, 0, 0)
                    setTextColor(ContextCompat.getColor(themedContext(), R.color.status_red))
                },
            )
        } else if (response.ipv4Unavailable && response.ipv6 != null) {
            container.addView(
                TextView(themedContext()).apply {
                    text = getString(R.string.main_ip_comparison_ipv4_unavailable)
                    textSize = 12f
                    typeface = Typeface.MONOSPACE
                    setPadding(0, 2.dp, 0, 0)
                    setTextColor(onSurfaceVariantColor())
                },
            )
            response.ipv4Error?.takeIf { it.isNotBlank() }?.let { reason ->
                container.addView(
                    TextView(themedContext()).apply {
                        text = reason
                        textSize = 11f
                        typeface = Typeface.MONOSPACE
                        setPadding(0, 0, 0, 0)
                        setTextColor(onSurfaceVariantColor())
                    },
                )
            }
        }

        container.addView(url)

        response.importantFields.forEach { (fieldLabel, fieldValue) ->
            if (response.ip != null && fieldLabel.equals("IP", ignoreCase = true)) return@forEach
            container.addView(
                createInfoView(
                    fieldLabel,
                    maskInfoValue(fieldValue, privacyMode),
                ),
            )
        }

        return container
    }

    private fun displayIpChannels(consensus: IpConsensusResult, privacyMode: Boolean = false) {
        if (consensus.observedIps.isEmpty()) {
            cardIpChannels.visibility = View.GONE
            return
        }
        cardIpChannels.visibility = View.VISIBLE
        ipChannelsContainer.removeAllViews()

        consensus.observedIps.forEach { ip ->
            ipChannelsContainer.addView(createIpChannelRow(ip, privacyMode))
        }

        val hasWarning = consensus.crossChannelMismatch || consensus.warpLikeIndicator ||
                consensus.geoCountryMismatch || consensus.probeTargetDivergence ||
                consensus.probeTargetDirectDivergence || consensus.channelConflict.isNotEmpty() ||
                consensus.needsReview

        if (hasWarning) {
            val flagsContainer = LinearLayout(themedContext()).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = 8.dp }
            }

            val warningColor = ContextCompat.getColor(themedContext(), R.color.finding_detected)
            val warningBackground = TextView(themedContext()).apply {
                text = buildIpConsensusWarningText(consensus)
                textSize = 12f
                setTextColor(warningColor)
                setPadding(8.dp, 8.dp, 8.dp, 8.dp)
            }

            flagsContainer.addView(warningBackground)
            ipChannelsContainer.addView(flagsContainer)
        }
    }

    private fun createIpChannelRow(ip: ObservedIp, privacyMode: Boolean): View {
        val row = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val channelChip = TextView(themedContext()).apply {
            text = ipChannelLabel(ip.channel)
            textSize = 11f
            setTextColor(onSurfaceColor())
            typeface = Typeface.DEFAULT_BOLD
            val padding = 6.dp
            setPadding(padding, padding / 2, padding, padding / 2)
            setBackgroundColor(MaterialColors.getColor(themedContext(), com.google.android.material.R.attr.colorSurfaceVariant, 0))
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                .apply { marginEnd = 8.dp }
        }

        val targetChip = if (ip.targetGroup != null) {
            TextView(themedContext()).apply {
                text = ipTargetGroupLabel(ip.targetGroup)
                textSize = 11f
                setTextColor(onSurfaceColor())
                typeface = Typeface.DEFAULT_BOLD
                val padding = 6.dp
                setPadding(padding, padding / 2, padding, padding / 2)
                setBackgroundColor(ContextCompat.getColor(themedContext(), R.color.verdict_yellow))
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                    .apply { marginEnd = 8.dp }
            }
        } else null

        val infoText = buildString {
            val maskedIp = maskInfoValue(ip.value, privacyMode)
            append(maskedIp)
            if (ip.countryCode != null) append(" (${ip.countryCode})")
            if (ip.asn != null) append(" ${ip.asn}")
            append(" • ${ipFamilyLabel(ip.family)}")
        }

        val infoView = TextView(themedContext()).apply {
            text = infoText
            textSize = 13f
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            textDirection = View.TEXT_DIRECTION_LOCALE
            textAlignment = View.TEXT_ALIGNMENT_VIEW_START
        }

        row.addView(channelChip)
        if (targetChip != null) row.addView(targetChip)
        row.addView(infoView)

        return row
    }

    private fun buildIpConsensusWarningText(consensus: IpConsensusResult): String {
        val warnings = buildList {
            if (consensus.crossChannelMismatch) add(getString(R.string.ip_channels_flag_cross_channel_mismatch))
            if (consensus.warpLikeIndicator) add(getString(R.string.ip_channels_flag_warp_like_behavior))
            if (consensus.geoCountryMismatch) add(getString(R.string.ip_channels_flag_geo_country_mismatch))
            if (consensus.probeTargetDivergence) add(getString(R.string.ip_channels_flag_probe_target_divergence))
            if (consensus.probeTargetDirectDivergence) {
                add(getString(R.string.ip_channels_flag_probe_target_direct_divergence))
            }
            if (consensus.channelConflict.isNotEmpty()) {
                val channels = consensus.channelConflict
                    .sortedBy { it.ordinal }
                    .joinToString(", ") { ipChannelLabel(it) }
                add(getString(R.string.ip_channels_flag_channel_conflict, channels))
            }
            if (consensus.needsReview) add(getString(R.string.ip_channels_flag_needs_review))
        }
        return warnings.joinToString(separator = "\n") { "\u26A0 $it" }
    }

    private fun ipChannelLabel(channel: Channel): String = when (channel) {
        Channel.DIRECT -> getString(R.string.ip_channels_channel_direct)
        Channel.VPN -> getString(R.string.ip_channels_channel_vpn)
        Channel.PROXY -> getString(R.string.ip_channels_channel_proxy)
        Channel.CDN -> getString(R.string.ip_channels_channel_cdn)
    }

    private fun ipTargetGroupLabel(targetGroup: TargetGroup): String = when (targetGroup) {
        TargetGroup.RU -> getString(R.string.ip_channels_target_ru)
        TargetGroup.NON_RU -> getString(R.string.ip_channels_target_non_ru)
    }

    private fun ipFamilyLabel(family: IpFamily): String = when (family) {
        IpFamily.V4 -> getString(R.string.main_card_call_transport_stun_ipv4)
        IpFamily.V6 -> getString(R.string.main_card_call_transport_stun_ipv6)
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

    private fun displayCallTransport(
        leaks: List<CallTransportLeakResult>,
        stunGroups: List<StunProbeGroupResult>,
        privacyMode: Boolean,
    ) {
        val hasContent = leaks.isNotEmpty() || stunGroups.any { it.results.isNotEmpty() }
        if (!hasContent) {
            cardCallTransport.visibility = View.GONE
            return
        }
        cardCallTransport.visibility = View.VISIBLE

        val hasNeedsReview = leaks.any { it.status == CallTransportStatus.NEEDS_REVIEW }
        val hasError = leaks.any { it.status == CallTransportStatus.ERROR }
        bindCardStatus(
            detected = false,
            needsReview = hasNeedsReview,
            icon = iconCallTransport,
            status = statusCallTransport,
            hasError = hasError && !hasNeedsReview,
        )

        val respondedCount = stunGroups.sumOf { it.respondedCount }
        val totalCount = stunGroups.sumOf { it.totalCount }
        if (totalCount > 0) {
            textCallTransportSummary.text = getString(
                R.string.main_card_call_transport_stun_responded,
                respondedCount,
                totalCount,
            )
            textCallTransportSummary.visibility = View.VISIBLE
        } else {
            textCallTransportSummary.visibility = View.GONE
        }

        stunGroupsContainer.removeAllViews()
        if (stunGroups.isNotEmpty()) {
            stunGroupsContainer.visibility = View.VISIBLE
            for (group in stunGroups) {
                stunGroupsContainer.addView(createStunGroupView(group, privacyMode))
            }
        } else {
            stunGroupsContainer.visibility = View.GONE
        }

        findingsCallTransport.removeAllViews()
        if (leaks.isNotEmpty()) {
            findingsCallTransport.visibility = View.VISIBLE
            for (leak in leaks) {
                findingsCallTransport.addView(createCallTransportLeakView(leak, privacyMode))
            }
        } else {
            findingsCallTransport.visibility = View.GONE
        }
    }

    private fun displayNativeSigns(result: CategoryResult, privacyMode: Boolean) {
        if (result.findings.isEmpty() && result.evidence.isEmpty()) {
            cardNativeSigns.visibility = View.GONE
            return
        }
        cardNativeSigns.visibility = View.VISIBLE

        bindCardStatus(
            detected = result.detected,
            needsReview = result.needsReview,
            icon = iconNativeSigns,
            status = statusNativeSigns,
            hasError = result.hasError,
        )

        val summaryFinding = result.findings.firstOrNull { finding ->
            finding.description.startsWith("getifaddrs():") ||
                finding.description.startsWith("Native library not loaded")
        }
        if (summaryFinding != null) {
            textNativeSignsSummary.text = summaryFinding.description
            textNativeSignsSummary.visibility = View.VISIBLE
        } else {
            textNativeSignsSummary.visibility = View.GONE
        }

        findingsNativeSigns.removeAllViews()
        val rest = result.findings.filter { it !== summaryFinding }
        if (rest.isNotEmpty()) {
            findingsNativeSigns.visibility = View.VISIBLE
            for (finding in rest) {
                findingsNativeSigns.addView(createFindingView(finding, privacyMode))
            }
        } else {
            findingsNativeSigns.visibility = View.GONE
        }
    }

    private fun createStunGroupView(group: StunProbeGroupResult, privacyMode: Boolean): View {
        val groupTitle = when (group.scope) {
            StunScope.GLOBAL -> getString(R.string.main_card_call_transport_stun_group_global)
            StunScope.RU -> getString(R.string.main_card_call_transport_stun_group_ru)
        }
        val respondedCount = group.respondedCount
        val totalCount = group.totalCount
        val statusLabel = if (respondedCount > 0) {
            getString(R.string.main_card_call_transport_stun_responded, respondedCount, totalCount)
        } else {
            getString(R.string.main_card_call_transport_stun_none_responded)
        }
        val groupResult = com.notcvnt.rknhardering.model.IpCheckerGroupResult(
            title = groupTitle,
            detected = false,
            needsReview = false,
            statusLabel = statusLabel,
            summary = statusLabel,
            responses = emptyList(),
        )

        val card = com.google.android.material.card.MaterialCardView(themedContext()).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = 8.dp }
            radius = 14.dp.toFloat()
            strokeWidth = 1.dp
            strokeColor = outlineVariantColor()
            setCardBackgroundColor(surfaceColor())
        }

        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(12.dp, 12.dp, 12.dp, 12.dp)
        }

        val header = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val title = TextView(themedContext()).apply {
            text = groupTitle
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val statusView = TextView(themedContext()).apply {
            text = statusLabel
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(
                ContextCompat.getColor(
                    themedContext(),
                    if (respondedCount > 0) R.color.status_green else R.color.status_amber,
                ),
            )
        }

        val expanded = respondedCount > 0
        val toggle = TextView(themedContext()).apply {
            text = if (expanded) "▼" else "▶"
            textSize = 12f
            setPadding(8.dp, 0, 0, 0)
            setTextColor(onSurfaceVariantColor())
        }

        val details = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            visibility = if (expanded) View.VISIBLE else View.GONE
            setPadding(0, 8.dp, 0, 0)
        }

        for (result in group.results) {
            details.addView(createStunProbeResultView(result, privacyMode))
        }

        val toggleDetails = {
            val nextExpanded = details.visibility != View.VISIBLE
            details.visibility = if (nextExpanded) View.VISIBLE else View.GONE
            toggle.text = if (nextExpanded) "▼" else "▶"
        }
        header.setOnClickListener { toggleDetails() }

        header.addView(title)
        header.addView(statusView)
        header.addView(toggle)
        container.addView(header)
        container.addView(details)
        card.addView(container)
        return card
    }

    private fun createStunProbeResultView(result: com.notcvnt.rknhardering.model.StunProbeResult, privacyMode: Boolean): View {
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 6.dp, 0, 6.dp)
        }

        val hostRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val hostLabel = TextView(themedContext()).apply {
            text = "${result.host}:${result.port}"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val hasAnyResponse = result.hasResponse
        val hasDualStack = result.mappedIpv4 != null && result.mappedIpv6 != null
        val responseLabel = TextView(themedContext()).apply {
            text = when {
                hasAnyResponse && hasDualStack -> "IPv4 + IPv6"
                hasAnyResponse -> result.mappedIpDisplay?.let { ip ->
                    if (privacyMode) maskIp(ip) else ip
                } ?: getString(R.string.main_card_call_transport_stun_no_response)
                result.error != null -> getString(R.string.main_card_call_transport_stun_error)
                else -> getString(R.string.main_card_call_transport_stun_no_response)
            }
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(
                ContextCompat.getColor(
                    themedContext(),
                    if (hasAnyResponse) R.color.status_green else R.color.status_amber,
                ),
            )
        }

        hostRow.addView(hostLabel)
        hostRow.addView(responseLabel)
        container.addView(hostRow)

        if (result.mappedIpv4 != null && result.mappedIpv6 != null) {
            container.addView(createInfoView(
                getString(R.string.main_card_call_transport_stun_ipv4),
                if (privacyMode) maskIp(result.mappedIpv4) else result.mappedIpv4,
            ))
            container.addView(createInfoView(
                getString(R.string.main_card_call_transport_stun_ipv6),
                if (privacyMode) maskIp(result.mappedIpv6) else result.mappedIpv6,
            ))
        }

        result.error?.takeIf { it.isNotBlank() && !hasAnyResponse }?.let { err ->
            container.addView(TextView(themedContext()).apply {
                text = err
                textSize = 11f
                setTextColor(onSurfaceVariantColor())
                setPadding(0, 2.dp, 0, 0)
            })
        }

        return container
    }

    private fun createCallTransportLeakView(leak: CallTransportLeakResult, privacyMode: Boolean): View {
        val container = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val statusLabel = when (leak.status) {
            CallTransportStatus.BASELINE -> getString(R.string.main_card_call_transport_status_baseline)
            CallTransportStatus.NO_SIGNAL -> getString(R.string.main_card_call_transport_status_no_signal)
            CallTransportStatus.NEEDS_REVIEW -> getString(R.string.main_card_call_transport_status_needs_review)
            CallTransportStatus.UNSUPPORTED -> getString(R.string.main_card_call_transport_status_unsupported)
            CallTransportStatus.ERROR -> getString(R.string.main_card_call_transport_status_error)
        }
        val pathLabel = when (leak.networkPath) {
            CallTransportNetworkPath.ACTIVE -> getString(R.string.main_card_call_transport_path_active)
            CallTransportNetworkPath.UNDERLYING -> getString(R.string.main_card_call_transport_path_underlying)
            CallTransportNetworkPath.LOCAL_PROXY -> getString(R.string.main_card_call_transport_path_proxy)
        }
        val serviceLabel = when (leak.service) {
            CallTransportService.TELEGRAM -> "Telegram"
            CallTransportService.WHATSAPP -> "WhatsApp"
        }
        val statusColor = when (leak.status) {
            CallTransportStatus.BASELINE -> ContextCompat.getColor(themedContext(), R.color.status_green)
            CallTransportStatus.NEEDS_REVIEW -> ContextCompat.getColor(themedContext(), R.color.status_amber)
            CallTransportStatus.ERROR -> ContextCompat.getColor(themedContext(), R.color.status_amber)
            CallTransportStatus.NO_SIGNAL -> onSurfaceVariantColor()
            CallTransportStatus.UNSUPPORTED -> onSurfaceVariantColor()
        }

        val headerRow = LinearLayout(themedContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val indicator = TextView(themedContext()).apply {
            text = when (leak.status) {
                CallTransportStatus.BASELINE -> "\u2713"
                CallTransportStatus.NEEDS_REVIEW -> "?"
                CallTransportStatus.ERROR -> "\u26A0"
                CallTransportStatus.NO_SIGNAL -> "\u2014"
                CallTransportStatus.UNSUPPORTED -> "\u2014"
            }
            setTextColor(statusColor)
            textSize = 14f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
        }
        val headerText = TextView(themedContext()).apply {
            text = getString(
                R.string.main_card_call_transport_header,
                serviceLabel,
                pathLabel,
                statusLabel,
            )
            textSize = 13f
            setTextColor(onSurfaceColor())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        headerRow.addView(indicator)
        headerRow.addView(headerText)
        container.addView(headerRow)

        formatCallTransportReason(this, leak, privacyMode)?.let { reason ->
            val reasonColor = if (leak.status == CallTransportStatus.ERROR) {
                ContextCompat.getColor(themedContext(), R.color.status_amber)
            } else {
                onSurfaceVariantColor()
            }
            container.addView(TextView(themedContext()).apply {
                text = reason
                textSize = 12f
                setPadding(22.dp, 2.dp, 0, 0)
                setTextColor(reasonColor)
            })
        }

        val target = leak.targetHost
        if (target != null) {
            val port = leak.targetPort
            val targetStr = if (port != null) {
                if (target.contains(':')) "[$target]:$port" else "$target:$port"
            } else target
            container.addView(createInfoView(
                label = "target",
                value = if (privacyMode) maskIp(targetStr) else targetStr,
            ))
        }
        val mappedIp = leak.mappedIp
        if (!mappedIp.isNullOrBlank()) {
            container.addView(createInfoView(
                label = "mapped IP",
                value = if (privacyMode) maskIp(mappedIp) else mappedIp,
            ))
        }
        val publicIp = leak.observedPublicIp
        if (!publicIp.isNullOrBlank()) {
            container.addView(createInfoView(
                label = "public IP",
                value = if (privacyMode) maskIp(publicIp) else publicIp,
            ))
        }

        return container
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

        private const val CATEGORY_GEO = "geo"
        private const val CATEGORY_IPC = "ipc"
        private const val CATEGORY_CDN = "cdn"
        private const val CATEGORY_IPS = "ip_channels"
        private const val CATEGORY_DIR = "dir"
        private const val CATEGORY_IND = "ind"
        private const val CATEGORY_STN = "stn"
        private const val CATEGORY_LOC = "loc"
        private const val CATEGORY_BYP = "byp"
        private const val CATEGORY_NAT = "nat"

        private const val TILE_STATUS_NEUTRAL = 0
        private const val TILE_STATUS_CLEAN = 1
        private const val TILE_STATUS_REVIEW = 2
        private const val TILE_STATUS_DETECTED = 3
    }

    private fun onTileClicked(id: String) {
        if (expandedCategoryId == id) {
            collapseExpanded()
        } else {
            expandCategory(id)
        }
    }

    private fun collapseExpanded() {
        val currentId = expandedCategoryId ?: return
        androidx.transition.TransitionManager.beginDelayedTransition(mainContentRoot)
        returnDetailContentToHost(currentId)
        expandedDetail.visibility = View.GONE
        expandedCategoryId = null
        tiles.values.forEach { holder ->
            holder.card.strokeColor = android.graphics.Color.TRANSPARENT
        }
    }

    private fun expandCategory(id: String) {
        val holder = tiles[id] ?: return
        val content = legacyContentFor(id) ?: return

        androidx.transition.TransitionManager.beginDelayedTransition(mainContentRoot)
        if (expandedCategoryId != null && expandedCategoryId != id) {
            returnDetailContentToHost(expandedCategoryId!!)
        }

        val parent = content.parent as? android.view.ViewGroup
        parent?.removeView(content)
        detailContentSlot.removeAllViews()
        detailContentSlot.addView(
            content,
            android.view.ViewGroup.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
        setEmbeddedCategoryHeaderVisible(id, visible = false)

        val iconRes = categoryIcon(id)
        detailIcon.setImageResource(iconRes)
        detailTitle.text = holder.title.text
        detailStatusChip.text = holder.hint.text
        detailStatusChip.setTextColor(
            (holder.statusDot.background as? android.graphics.drawable.GradientDrawable)?.let {
                tileStatusChipColor(holder)
            } ?: onSurfaceVariantColor(),
        )
        expandedDetail.visibility = View.VISIBLE
        expandedCategoryId = id

        tiles.values.forEach { h ->
            h.card.strokeColor = if (h.id == id) {
                MaterialColors.getColor(h.card, com.google.android.material.R.attr.colorOutline, 0)
            } else {
                android.graphics.Color.TRANSPARENT
            }
        }
    }

    private fun tileStatusChipColor(holder: TileHolder): Int {
        val tag = holder.statusDot.tag as? Int ?: TILE_STATUS_NEUTRAL
        return when (tag) {
            TILE_STATUS_CLEAN -> ContextCompat.getColor(this, R.color.status_green)
            TILE_STATUS_REVIEW -> ContextCompat.getColor(this, R.color.status_amber)
            TILE_STATUS_DETECTED -> ContextCompat.getColor(this, R.color.status_red)
            else -> onSurfaceVariantColor()
        }
    }

    private fun returnDetailContentToHost(id: String) {
        val host = legacyCardFor(id) ?: return
        val content = detailContentSlot.getChildAt(0) ?: return
        detailContentSlot.removeView(content)
        setEmbeddedCategoryHeaderVisible(id, visible = true)
        host.addView(
            content,
            android.view.ViewGroup.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
    }

    private fun setEmbeddedCategoryHeaderVisible(id: String, visible: Boolean) {
        if (id != CATEGORY_STN && id != CATEGORY_NAT && id != CATEGORY_IPS) return
        val content = legacyContentFor(id) as? android.view.ViewGroup ?: return
        val header = content.getChildAt(0) ?: return
        header.visibility = if (visible) View.VISIBLE else View.GONE
    }

    private fun legacyCardFor(id: String): MaterialCardView? = when (id) {
        CATEGORY_GEO -> cardGeoIp
        CATEGORY_IPC -> cardIpComparison
        CATEGORY_CDN -> cardCdnPulling
        CATEGORY_IPS -> cardIpChannels
        CATEGORY_DIR -> cardDirect
        CATEGORY_IND -> cardIndirect
        CATEGORY_STN -> cardCallTransport
        CATEGORY_LOC -> cardLocation
        CATEGORY_BYP -> cardBypass
        CATEGORY_NAT -> cardNativeSigns
        else -> null
    }

    private fun legacyContentFor(id: String): View? {
        val contentId = when (id) {
            CATEGORY_GEO -> R.id.cardGeoIpContent
            CATEGORY_IPC -> R.id.cardIpComparisonContent
            CATEGORY_CDN -> R.id.cardCdnPullingContent
            CATEGORY_IPS -> R.id.cardIpChannelsContent
            CATEGORY_DIR -> R.id.cardDirectContent
            CATEGORY_IND -> R.id.cardIndirectContent
            CATEGORY_STN -> R.id.cardCallTransportContent
            CATEGORY_LOC -> R.id.cardLocationContent
            CATEGORY_BYP -> R.id.cardBypassContent
            CATEGORY_NAT -> R.id.cardNativeSignsContent
            else -> return null
        }
        // Content может быть либо ещё в своей карточке, либо уже в detailContentSlot
        return findViewById(contentId)
    }

    private fun categoryIcon(id: String): Int = when (id) {
        CATEGORY_GEO -> R.drawable.ic_globe
        CATEGORY_IPC -> R.drawable.ic_compare
        CATEGORY_CDN -> R.drawable.ic_cloud
        CATEGORY_IPS -> R.drawable.ic_compare
        CATEGORY_DIR -> R.drawable.ic_shield
        CATEGORY_IND -> R.drawable.ic_network
        CATEGORY_STN -> R.drawable.ic_phone
        CATEGORY_LOC -> R.drawable.ic_pin
        CATEGORY_BYP -> R.drawable.ic_split
        CATEGORY_NAT -> R.drawable.ic_shield
        else -> R.drawable.ic_help
    }

    private fun setTileStatus(id: String, status: Int, hint: String?) {
        val holder = tiles[id] ?: return
        val dotRes = when (status) {
            TILE_STATUS_CLEAN -> R.drawable.dot_status_green
            TILE_STATUS_REVIEW -> R.drawable.dot_status_amber
            TILE_STATUS_DETECTED -> R.drawable.dot_status_red
            else -> R.drawable.dot_status_neutral
        }
        holder.statusDot.setBackgroundResource(dotRes)
        holder.statusDot.tag = status
        if (hint != null) {
            holder.hint.text = hint
        }
        if (expandedCategoryId == id) {
            detailStatusChip.text = holder.hint.text
            detailStatusChip.setTextColor(tileStatusChipColor(holder))
        }
    }

    private fun resetAllTiles() {
        tiles.keys.forEach { id ->
            setTileStatus(id, TILE_STATUS_NEUTRAL, getString(R.string.tile_hint_placeholder))
        }
        if (expandedCategoryId != null) {
            collapseExpanded()
        }
    }

    private fun statusFromCategory(detected: Boolean, needsReview: Boolean, hasError: Boolean): Int {
        return when {
            detected -> TILE_STATUS_DETECTED
            needsReview || hasError -> TILE_STATUS_REVIEW
            else -> TILE_STATUS_CLEAN
        }
    }

    private fun updateTileFromCategory(id: String, category: CategoryResult) {
        val status = statusFromCategory(category.detected, category.needsReview, category.hasError)
        val hint = buildTileHintForCategory(category)
        setTileStatus(id, status, hint)
    }

    private fun updateTileFromIpComparison(result: IpComparisonResult) {
        val status = statusFromCategory(result.detected, result.needsReview, hasError = false)
        val ru = result.ruGroup.responses.size
        val nonRu = result.nonRuGroup.responses.size
        val total = ru + nonRu
        val hint = when {
            result.detected -> getString(R.string.tile_hint_review)
            result.needsReview -> getString(R.string.tile_hint_review)
            total > 0 -> getString(R.string.tile_hint_clean_count, total)
            else -> null
        }
        setTileStatus(CATEGORY_IPC, status, hint)
    }

    private fun updateTileFromCdn(result: CdnPullingResult) {
        val status = when {
            result.needsReview -> TILE_STATUS_REVIEW
            result.hasError -> TILE_STATUS_REVIEW
            result.detected -> TILE_STATUS_CLEAN
            else -> TILE_STATUS_NEUTRAL
        }
        val total = result.responses.size
        val hint = when {
            result.needsReview -> getString(R.string.tile_hint_review)
            result.hasError -> getString(R.string.tile_hint_error)
            total > 0 -> getString(R.string.tile_hint_clean_count, total)
            else -> null
        }
        setTileStatus(CATEGORY_CDN, status, hint)
    }

    private fun updateTileFromBypass(result: BypassResult) {
        val status = statusFromCategory(result.detected, result.needsReview, hasError = false)
        val hint = when {
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
            hasNeedsReview -> TILE_STATUS_REVIEW
            hasError -> TILE_STATUS_REVIEW
            else -> TILE_STATUS_CLEAN
        }
        val hint = if (totalCount > 0)
            getString(R.string.main_card_call_transport_stun_responded, respondedCount, totalCount)
        else
            getString(R.string.tile_hint_clean_count, leaks.size)
        setTileStatus(CATEGORY_STN, status, hint)
    }

    private fun isCallTransportTileLoading(): Boolean {
        val holder = tiles[CATEGORY_STN] ?: return false
        return holder.statusDot.tag == TILE_STATUS_NEUTRAL &&
            holder.hint.text?.toString() == getString(R.string.tile_hint_loading)
    }

    private fun buildTileHintForCategory(category: CategoryResult): String {
        val nonInfo = category.findings.filterNot { it.isInformational || it.isError }
        val detected = nonInfo.count { it.detected }
        val total = nonInfo.size
        return when {
            category.detected && total > 0 -> getString(R.string.tile_hint_detected_count, detected, total)
            category.detected -> getString(R.string.tile_hint_review)
            category.needsReview -> getString(R.string.tile_hint_review)
            category.hasError -> getString(R.string.tile_hint_error)
            total > 0 -> getString(R.string.tile_hint_clean_count, total)
            else -> getString(R.string.tile_hint_clean)
        }
    }

    private fun bindVerdictHeroIdle() {
        applyVerdictHeroColors(R.color.status_neutral_container, R.color.status_neutral)
        verdictAvatarIcon.setImageResource(R.drawable.ic_minus)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(R.string.verdict_title_idle)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_idle)
    }

    private fun bindVerdictHeroRunning() {
        applyVerdictHeroColors(R.color.status_neutral_container, R.color.status_neutral)
        verdictAvatarIcon.setImageResource(R.drawable.ic_minus)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(R.string.verdict_title_idle)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_running)
    }

    private fun bindVerdictHero(result: CheckResult) {
        val (containerRes, accentRes, iconRes, titleRes) = when (result.verdict) {
            Verdict.NOT_DETECTED -> VerdictStyle(
                R.color.status_green_container,
                R.color.status_green,
                R.drawable.ic_check_circle,
                R.string.verdict_title_clean,
            )
            Verdict.NEEDS_REVIEW -> VerdictStyle(
                R.color.status_amber_container,
                R.color.status_amber,
                R.drawable.ic_help,
                R.string.verdict_title_review,
            )
            Verdict.DETECTED -> VerdictStyle(
                R.color.status_red_container,
                R.color.status_red,
                R.drawable.ic_error,
                R.string.verdict_title_detected,
            )
        }
        applyVerdictHeroColors(containerRes, accentRes)
        verdictAvatarIcon.setImageResource(iconRes)
        verdictLabel.text = getString(R.string.verdict_label)
        verdictTitle.text = getString(titleRes)
        verdictSubtitle.text = getString(R.string.verdict_subtitle_done, tiles.size)
    }

    private data class VerdictStyle(
        @ColorRes val containerRes: Int,
        @ColorRes val accentRes: Int,
        val iconRes: Int,
        val titleRes: Int,
    )

    private fun applyVerdictHeroColors(@ColorRes containerRes: Int, @ColorRes accentRes: Int) {
        val container = ContextCompat.getColor(this, containerRes)
        val accent = ContextCompat.getColor(this, accentRes)
        verdictHero.setCardBackgroundColor(container)
        verdictTitle.setTextColor(accent)
        verdictLabel.setTextColor(accent)
        val avatarBg = android.graphics.drawable.GradientDrawable().apply {
            shape = android.graphics.drawable.GradientDrawable.OVAL
            setColor(accent)
        }
        verdictAvatar.background = avatarBg
    }
}
