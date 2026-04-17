package com.notcvnt.rknhardering

import android.app.Application

class RknHarderingApp : Application() {

    override fun onCreate() {
        super.onCreate()
        AppUiSettings.applySavedTheme(this)
    }
}
