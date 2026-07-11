package com.notcvnt.rknhardering

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.view.View
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.ui.main.render.MainRenderEnvironment
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowToast

@RunWith(RobolectricTestRunner::class)
class ExternalHelpOpeningTest {

    @Test
    fun `missing browser shows localized error`() {
        val base = ApplicationProvider.getApplicationContext<Context>()
        val failingContext = object : ContextWrapper(base) {
            override fun startActivity(intent: Intent) {
                throw ActivityNotFoundException("no browser")
            }
        }
        val env = MainRenderEnvironment(
            context = failingContext,
            anchorView = View(failingContext),
            statusVisual = { error("unused") },
            colorVisionMode = { ColorVisionMode.OFF },
        )

        env.openExternalHelp("https://example.test/help")

        assertEquals(base.getString(R.string.help_open_failed), ShadowToast.getTextOfLatestToast())
    }
}
