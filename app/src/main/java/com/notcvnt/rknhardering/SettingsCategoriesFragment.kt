package com.notcvnt.rknhardering

import android.os.Bundle
import android.view.View
import androidx.fragment.app.Fragment
import com.google.android.material.card.MaterialCardView

internal class SettingsCategoriesFragment : Fragment(R.layout.fragment_settings_categories) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val activity = requireActivity() as SettingsActivity

        view.findViewById<MaterialCardView>(R.id.cardCategorySplitTunnel).setOnClickListener {
            activity.navigateTo(SettingsSplitTunnelFragment(), R.string.settings_cat_split_tunnel)
        }
        view.findViewById<MaterialCardView>(R.id.cardCategoryNetwork).setOnClickListener {
            activity.navigateTo(SettingsNetworkFragment(), R.string.settings_cat_network)
        }
        view.findViewById<MaterialCardView>(R.id.cardCategoryDns).setOnClickListener {
            activity.navigateTo(SettingsDnsFragment(), R.string.settings_cat_dns)
        }
        view.findViewById<MaterialCardView>(R.id.cardCategoryPrivacy).setOnClickListener {
            activity.navigateTo(SettingsPrivacyFragment(), R.string.settings_cat_privacy)
        }
        view.findViewById<MaterialCardView>(R.id.cardCategoryAppearance).setOnClickListener {
            activity.navigateTo(SettingsAppearanceFragment(), R.string.settings_cat_appearance)
        }
        view.findViewById<MaterialCardView>(R.id.cardCategoryAbout).setOnClickListener {
            activity.navigateTo(SettingsAboutFragment(), R.string.settings_cat_about)
        }
    }
}
