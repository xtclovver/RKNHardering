package com.notcvnt.rknhardering

import android.view.View
import android.view.ViewGroup

internal fun setViewAndChildrenEnabled(view: View, enabled: Boolean) {
    view.isEnabled = enabled
    if (view is ViewGroup) {
        for (i in 0 until view.childCount) {
            setViewAndChildrenEnabled(view.getChildAt(i), enabled)
        }
    }
}
