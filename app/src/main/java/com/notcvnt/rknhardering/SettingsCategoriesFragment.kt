package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.fragment.app.Fragment
import com.notcvnt.rknhardering.network.DnsResolverMode
import java.util.Locale

internal class SettingsCategoriesFragment : Fragment(R.layout.fragment_settings_categories) {

    private lateinit var prefs: SharedPreferences

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        val activity = requireActivity() as SettingsActivity

        bindRow(
            view, R.id.rowSplitTunnel,
            iconRes = R.drawable.ic_call_split,
            title = getString(R.string.settings_cat_split_tunnel),
        ) { activity.navigateTo(SettingsSplitTunnelFragment(), R.string.settings_cat_split_tunnel) }

        bindRow(
            view, R.id.rowNetwork,
            iconRes = R.drawable.ic_lan,
            title = getString(R.string.settings_cat_network),
        ) { activity.navigateTo(SettingsNetworkFragment(), R.string.settings_cat_network) }

        bindRow(
            view, R.id.rowDns,
            iconRes = R.drawable.ic_public,
            title = getString(R.string.settings_cat_dns),
        ) { activity.navigateTo(SettingsDnsFragment(), R.string.settings_cat_dns) }

        bindRow(
            view, R.id.rowPrivacy,
            iconRes = R.drawable.ic_lock,
            title = getString(R.string.settings_cat_privacy),
        ) { activity.navigateTo(SettingsPrivacyFragment(), R.string.settings_cat_privacy) }

        bindRow(
            view, R.id.rowAppearance,
            iconRes = R.drawable.ic_settings,
            title = getString(R.string.settings_cat_appearance),
        ) { activity.navigateTo(SettingsAppearanceFragment(), R.string.settings_cat_appearance) }

        bindRow(
            view, R.id.rowAbout,
            iconRes = R.drawable.ic_help,
            title = getString(R.string.settings_cat_about),
        ) { activity.navigateTo(SettingsAboutFragment(), R.string.settings_cat_about) }

        renderValues(view)
    }

    override fun onResume() {
        super.onResume()
        view?.let(::renderValues)
    }

    private fun bindRow(
        root: View,
        rowId: Int,
        @DrawableRes iconRes: Int,
        title: String,
        onClick: () -> Unit,
    ) {
        val row = root.findViewById<View>(rowId)
        row.findViewById<ImageView>(R.id.rowIcon).setImageResource(iconRes)
        row.findViewById<TextView>(R.id.rowTitle).text = title
        row.setOnClickListener { onClick() }
    }

    private fun renderValues(root: View) {
        setRowValue(root, R.id.rowSplitTunnel, if (splitTunnelEnabled()) R.string.settings_value_on else R.string.settings_value_off)
        setRowValue(root, R.id.rowNetwork, if (networkRequestsEnabled()) R.string.settings_value_network_all else R.string.settings_value_network_disabled)
        setRowValue(root, R.id.rowDns, dnsValue())
        setRowValue(root, R.id.rowPrivacy, if (privacyModeEnabled()) R.string.settings_value_privacy_masking else R.string.settings_value_off)
        setRowValue(root, R.id.rowAppearance, appearanceValue())
        setRowValue(root, R.id.rowAbout, versionValue())
    }

    private fun setRowValue(root: View, rowId: Int, valueRes: Int) {
        root.findViewById<View>(rowId)
            .findViewById<TextView>(R.id.rowValue)
            .setText(valueRes)
    }

    private fun setRowValue(root: View, rowId: Int, value: String) {
        root.findViewById<View>(rowId)
            .findViewById<TextView>(R.id.rowValue)
            .text = value
    }

    private fun splitTunnelEnabled(): Boolean =
        prefs.getBoolean(SettingsPrefs.PREF_SPLIT_TUNNEL_ENABLED, true)

    private fun networkRequestsEnabled(): Boolean =
        prefs.getBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true)

    private fun privacyModeEnabled(): Boolean =
        prefs.getBoolean(SettingsPrefs.PREF_PRIVACY_MODE, false)

    private fun dnsValue(): String {
        return when (
            DnsResolverMode.fromPref(
                prefs.getString(SettingsPrefs.PREF_DNS_RESOLVER_MODE, DnsResolverMode.SYSTEM.prefValue),
            )
        ) {
            DnsResolverMode.SYSTEM -> getString(R.string.settings_dns_mode_system)
            DnsResolverMode.DIRECT -> getString(R.string.settings_dns_mode_direct)
            DnsResolverMode.DOH -> getString(R.string.settings_dns_mode_doh)
        }
    }

    private fun appearanceValue(): String {
        val theme = when (prefs.getString(SettingsPrefs.PREF_THEME, "system")) {
            "light" -> getString(R.string.settings_theme_light)
            "dark" -> getString(R.string.settings_theme_dark)
            else -> getString(R.string.settings_theme_system)
        }
        val language = when (val stored = prefs.getString(SettingsPrefs.PREF_LANGUAGE, "").orEmpty()) {
            "en" -> "EN"
            "ru" -> "RU"
            "fa" -> "FA"
            "zh-CN" -> "ZH"
            else -> currentLocaleCode()
        }
        return getString(R.string.settings_value_appearance_format, theme, language)
    }

    private fun versionValue(): String {
        return if (BuildConfig.VERSION_NAME.startsWith("v", ignoreCase = true)) {
            BuildConfig.VERSION_NAME
        } else {
            "v${BuildConfig.VERSION_NAME}"
        }
    }

    private fun currentLocaleCode(): String {
        val locale = resources.configuration.locales[0] ?: Locale.getDefault()
        return locale.language.uppercase(Locale.ROOT)
    }
}
