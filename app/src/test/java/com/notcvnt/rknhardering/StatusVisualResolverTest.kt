package com.notcvnt.rknhardering

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class StatusVisualResolverTest {

    @Test
    fun `each color vision mode keeps status shapes distinct`() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()

        ColorVisionMode.entries.forEach { mode ->
            val shapes = listOf(
                StatusSemantic.CLEAN,
                StatusSemantic.REVIEW,
                StatusSemantic.DETECTED,
                StatusSemantic.ERROR,
            ).map { status ->
                StatusVisualResolver.resolve(context, status, mode).shape
            }

            assertEquals("Mode $mode should not rely on color-only status", shapes.size, shapes.toSet().size)
        }
    }

    @Test
    fun `indicator drawable exposes resolved semantic shape`() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()

        val drawable = StatusVisualResolver.indicatorDrawable(
            context,
            StatusSemantic.DETECTED,
            ColorVisionMode.RED_GREEN,
        )

        assertTrue(drawable is StatusShapeDrawable)
        assertEquals(StatusIndicatorShape.DIAMOND, (drawable as StatusShapeDrawable).indicatorShape)
    }
}
