package com.notcvnt.rknhardering

import android.graphics.Canvas
import android.graphics.ColorFilter
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PixelFormat
import android.graphics.RectF
import android.graphics.drawable.Drawable
import androidx.annotation.ColorInt
import kotlin.math.max
import kotlin.math.min

internal enum class StatusIndicatorShape {
    CIRCLE,
    TRIANGLE,
    DIAMOND,
    SQUARE,
    LINE,
}

internal class StatusShapeDrawable(
    val indicatorShape: StatusIndicatorShape,
    @ColorInt color: Int,
) : Drawable() {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        this.color = color
    }
    private val path = Path()

    override fun draw(canvas: Canvas) {
        val bounds = bounds
        val size = min(bounds.width(), bounds.height()).toFloat()
        val left = bounds.left + (bounds.width() - size) / 2f
        val top = bounds.top + (bounds.height() - size) / 2f
        val right = left + size
        val bottom = top + size
        val centerX = (left + right) / 2f
        val centerY = (top + bottom) / 2f

        when (indicatorShape) {
            StatusIndicatorShape.CIRCLE -> canvas.drawOval(RectF(left, top, right, bottom), paint)
            StatusIndicatorShape.SQUARE -> canvas.drawRoundRect(RectF(left, top, right, bottom), 1f, 1f, paint)
            StatusIndicatorShape.TRIANGLE -> {
                path.reset()
                path.moveTo(centerX, top)
                path.lineTo(right, bottom)
                path.lineTo(left, bottom)
                path.close()
                canvas.drawPath(path, paint)
            }
            StatusIndicatorShape.DIAMOND -> {
                path.reset()
                path.moveTo(centerX, top)
                path.lineTo(right, centerY)
                path.lineTo(centerX, bottom)
                path.lineTo(left, centerY)
                path.close()
                canvas.drawPath(path, paint)
            }
            StatusIndicatorShape.LINE -> {
                val lineHeight = max(2f, size / 3f)
                canvas.drawRoundRect(
                    RectF(left, centerY - lineHeight / 2f, right, centerY + lineHeight / 2f),
                    lineHeight / 2f,
                    lineHeight / 2f,
                    paint,
                )
            }
        }
    }

    override fun setAlpha(alpha: Int) {
        paint.alpha = alpha
        invalidateSelf()
    }

    override fun setColorFilter(colorFilter: ColorFilter?) {
        paint.colorFilter = colorFilter
        invalidateSelf()
    }

    @Deprecated("Deprecated in Java")
    override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
}
