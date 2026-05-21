package com.notcvnt.rknhardering.customcheck.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.LifecycleCoroutineScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.notcvnt.rknhardering.R
import kotlinx.coroutines.launch

internal class GenericInlineEditorController(
    private val parent: ViewGroup,
    private val scope: LifecycleCoroutineScope,
) {
    data class Config(
        val titleRes: Int,
        val urlHintRes: Int,
        val labelHintRes: Int,
        val extraInputHintRes: Int? = null,
        val extraSwitchTextRes: Int? = null,
        /** When true, shows expected DNS/TCP/TLS checkboxes (for domain reachability) */
        val showExpectedChecks: Boolean = false,
        val testAction: suspend (url: String, extraInput: String, isSwitchChecked: Boolean) -> Pair<Boolean, String>,
        val saveAction: (url: String, label: String, extraInput: String, isSwitchChecked: Boolean) -> Unit,
        /** Extended save that also passes expected booleans */
        val saveActionEx: ((url: String, label: String, extraInput: String, isSwitchChecked: Boolean, expectedDns: Boolean, expectedTcp: Boolean, expectedTls: Boolean) -> Unit)? = null,
    )

    data class InitialValues(
        val url: String = "",
        val label: String = "",
        val extraInput: String = "",
        val switchChecked: Boolean = false,
        val expectedDns: Boolean = true,
        val expectedTcp: Boolean = true,
        val expectedTls: Boolean = true,
    )

    private var rootView: View? = null
    private var cbDns: CheckBox? = null
    private var cbTcp: CheckBox? = null
    private var cbTls: CheckBox? = null

    fun show(
        config: Config,
        onCancel: () -> Unit,
        initialValues: InitialValues? = null,
    ) {
        dismiss()

        val inflater = LayoutInflater.from(parent.context)
        val view = inflater.inflate(R.layout.view_inline_endpoint_editor, parent, false)
        parent.addView(view)
        rootView = view

        val titleText = view.findViewById<TextView>(R.id.inlineEditorTitle)
        val urlLayout = view.findViewById<View>(R.id.inlineEditorUrl).parent.parent as TextInputLayout
        val urlEdit = view.findViewById<TextInputEditText>(R.id.inlineEditorUrl)
        val labelLayout = view.findViewById<View>(R.id.inlineEditorLabel).parent.parent as TextInputLayout
        val labelEdit = view.findViewById<TextInputEditText>(R.id.inlineEditorLabel)
        
        val extraInputLayout = view.findViewById<TextInputLayout>(R.id.inlineEditorExtraInputLayout)
        val extraInput = view.findViewById<TextInputEditText>(R.id.inlineEditorExtraInput)
        val extraSwitch = view.findViewById<MaterialSwitch>(R.id.inlineEditorExtraSwitch)
        
        val btnTest = view.findViewById<MaterialButton>(R.id.inlineEditorTest)
        val btnSave = view.findViewById<MaterialButton>(R.id.inlineEditorSave)
        val btnCancel = view.findViewById<MaterialButton>(R.id.inlineEditorCancel)
        val btnClose = view.findViewById<ImageView>(R.id.inlineEditorClose)
        
        val resultBlock = view.findViewById<View>(R.id.inlineEditorResult)
        val resultType = view.findViewById<TextView>(R.id.inlineEditorResultType)
        val resultStatus = view.findViewById<TextView>(R.id.inlineEditorResultStatus)
        val errorView = view.findViewById<TextView>(R.id.inlineEditorError)

        // Hide CDN/IP specific stuff
        view.findViewById<View>(R.id.inlineEditorScopeChips).visibility = View.GONE
        view.findViewById<View>(R.id.inlineEditorMappingContainer).visibility = View.GONE
        view.findViewById<View>(R.id.inlineEditorRetest).visibility = View.GONE
        view.findViewById<View>(R.id.inlineEditorRawBody).parent.parent?.let { (it as View).visibility = View.GONE }
        
        titleText.setText(config.titleRes)
        urlLayout.hint = view.context.getString(config.urlHintRes)
        labelLayout.hint = view.context.getString(config.labelHintRes)

        if (config.extraInputHintRes != null) {
            extraInputLayout.visibility = View.VISIBLE
            extraInputLayout.hint = view.context.getString(config.extraInputHintRes)
        } else {
            extraInputLayout.visibility = View.GONE
        }

        if (config.extraSwitchTextRes != null) {
            extraSwitch.visibility = View.VISIBLE
            extraSwitch.setText(config.extraSwitchTextRes)
        } else {
            extraSwitch.visibility = View.GONE
        }

        // Expected availability checkboxes for domain reachability
        if (config.showExpectedChecks) {
            val ctx = view.context
            val density = ctx.resources.displayMetrics.density
            val container = view.findViewById<LinearLayout>(R.id.inlineEditorResult).parent as ViewGroup
            
            // Insert expected checks section before save/cancel buttons
            val checksContainer = LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL
                val lp = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                lp.topMargin = (8 * density).toInt()
                layoutParams = lp
            }
            
            val checksLabel = TextView(ctx).apply {
                text = ctx.getString(R.string.editor_expected_availability)
                setTextColor(ctx.getColor(android.R.color.darker_gray))
                textSize = 11f
                setTypeface(null, android.graphics.Typeface.BOLD)
                val lp = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                lp.bottomMargin = (4 * density).toInt()
                layoutParams = lp
            }
            checksContainer.addView(checksLabel)
            
            val row = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
            }
            
            val dnsCb = CheckBox(ctx).apply {
                text = "DNS"
                isChecked = initialValues?.expectedDns ?: true
                textSize = 12f
            }
            val tcpCb = CheckBox(ctx).apply {
                text = "TCP"
                isChecked = initialValues?.expectedTcp ?: true
                textSize = 12f
            }
            val tlsCb = CheckBox(ctx).apply {
                text = "TLS"
                isChecked = initialValues?.expectedTls ?: true
                textSize = 12f
            }
            row.addView(dnsCb)
            row.addView(tcpCb)
            row.addView(tlsCb)
            checksContainer.addView(row)
            
            cbDns = dnsCb
            cbTcp = tcpCb
            cbTls = tlsCb
            
            // Find the error view and add before it
            val errorIdx = (container as LinearLayout).indexOfChild(errorView)
            container.addView(checksContainer, errorIdx)
        }

        // Pre-populate if editing
        if (initialValues != null) {
            urlEdit.setText(initialValues.url)
            labelEdit.setText(initialValues.label)
            if (config.extraInputHintRes != null) {
                extraInput.setText(initialValues.extraInput)
            }
            if (config.extraSwitchTextRes != null) {
                extraSwitch.isChecked = initialValues.switchChecked
            }
            btnSave.isEnabled = true
        }

        resultBlock.visibility = View.GONE
        if (initialValues == null) btnSave.isEnabled = false

        val performTest: () -> Unit = {
            val url = urlEdit.text?.toString()?.trim().orEmpty()
            if (url.isBlank()) {
                errorView.text = view.context.getString(R.string.inline_editor_url_required)
                errorView.visibility = View.VISIBLE
            } else {
                errorView.visibility = View.GONE
                btnTest.isEnabled = false
                btnTest.setText(R.string.inline_editor_testing)
                scope.launch {
                    val extra = extraInput.text?.toString()?.trim().orEmpty()
                    val (success, message) = config.testAction(url, extra, extraSwitch.isChecked)
                    btnTest.isEnabled = true
                    btnTest.setText(R.string.inline_editor_test)
                    
                    resultBlock.visibility = View.VISIBLE
                    if (success) {
                        resultType.text = "OK"
                        resultType.setTextColor(view.context.getColor(R.color.status_green))
                        btnSave.isEnabled = true
                    } else {
                        resultType.text = "ERR"
                        resultType.setTextColor(view.context.getColor(R.color.status_red))
                        btnSave.isEnabled = true // allow saving even if test failed
                    }
                    resultStatus.text = message
                }
            }
        }

        btnTest.setOnClickListener { performTest() }
        
        btnSave.setOnClickListener {
            val url = urlEdit.text?.toString()?.trim().orEmpty()
            if (url.isBlank()) return@setOnClickListener
            val label = labelEdit.text?.toString()?.trim().orEmpty()
            val extra = extraInput.text?.toString()?.trim().orEmpty()
            if (config.saveActionEx != null) {
                config.saveActionEx.invoke(
                    url, label, extra, extraSwitch.isChecked,
                    cbDns?.isChecked ?: true,
                    cbTcp?.isChecked ?: true,
                    cbTls?.isChecked ?: true,
                )
            } else {
                config.saveAction(url, label, extra, extraSwitch.isChecked)
            }
            dismiss()
        }

        val cancelHandler = {
            onCancel()
            dismiss()
        }
        btnCancel.setOnClickListener { cancelHandler() }
        btnClose.setOnClickListener { cancelHandler() }
    }

    fun dismiss() {
        rootView?.let { parent.removeView(it) }
        rootView = null
        cbDns = null
        cbTcp = null
        cbTls = null
    }

    /** Update the expected checkboxes from external test results */
    fun setExpectedChecks(dns: Boolean, tcp: Boolean, tls: Boolean) {
        cbDns?.isChecked = dns
        cbTcp?.isChecked = tcp
        cbTls?.isChecked = tls
    }
}
