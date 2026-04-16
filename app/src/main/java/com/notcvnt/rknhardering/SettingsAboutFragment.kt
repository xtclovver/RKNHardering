package com.notcvnt.rknhardering

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.core.net.toUri
import androidx.fragment.app.Fragment
import com.google.android.material.card.MaterialCardView

internal class SettingsAboutFragment : Fragment(R.layout.fragment_settings_about) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        view.findViewById<MaterialCardView>(R.id.cardPermissions).setOnClickListener {
            reRequestPermissions()
        }

        view.findViewById<MaterialCardView>(R.id.cardGithub).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, getString(R.string.github_repo_url).toUri()))
        }
    }

    private fun reRequestPermissions() {
        val intent = Intent(requireContext(), MainActivity::class.java).apply {
            putExtra(SettingsActivity.EXTRA_REQUEST_PERMISSIONS, true)
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        startActivity(intent)
        requireActivity().finish()
    }
}
