package com.notcvnt.rknhardering.customcheck.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.LifecycleCoroutineScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.ChipGroup
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.customcheck.EndpointScope
import com.notcvnt.rknhardering.customcheck.ResponseMapping
import com.notcvnt.rknhardering.customcheck.ResponseType
import com.notcvnt.rknhardering.customcheck.mapper.EndpointResponseMapper
import com.notcvnt.rknhardering.customcheck.mapper.MappingField
import kotlinx.coroutines.launch

/**
 * Controller for view_inline_endpoint_editor.xml. Handles the URL → test → mapping → save flow.
 *
 * Lifecycle:
 *  - Caller inflates the layout into [parent] via [show], passing kind (which fields are visible)
 *    and an [onSave] callback.
 *  - Editor stays in parent until user taps Save or Cancel (close icon also cancels).
 */
internal class InlineEndpointEditorController(
    private val parent: ViewGroup,
    private val scope: LifecycleCoroutineScope,
) {

    enum class Kind { GEO_IP, IP_COMPARISON, CDN }

    data class Result(
        val url: String,
        val label: String,
        val mapping: ResponseMapping,
        val scope: EndpointScope,
    )

    private var rootView: View? = null
    private var currentRawBody: String? = null
    private var currentMapping: ResponseMapping = ResponseMapping()
    private var autoDetectedFields: Set<MappingField> = emptySet()
    private var currentKind: Kind = Kind.GEO_IP

    data class EditData(
        val url: String,
        val label: String,
        val mapping: ResponseMapping,
        val scope: EndpointScope = EndpointScope.RU,
    )

    fun show(
        kind: Kind,
        onCancel: () -> Unit,
        onSave: (Result) -> Unit,
        editData: EditData? = null,
    ) {
        dismiss()

        val inflater = LayoutInflater.from(parent.context)
        val view = inflater.inflate(R.layout.view_inline_endpoint_editor, parent, false)
        parent.addView(view)
        rootView = view
        currentKind = kind

        val urlEdit = view.findViewById<TextInputEditText>(R.id.inlineEditorUrl)
        val labelEdit = view.findViewById<TextInputEditText>(R.id.inlineEditorLabel)
        val scopeChips = view.findViewById<ChipGroup>(R.id.inlineEditorScopeChips)
        val btnTest = view.findViewById<MaterialButton>(R.id.inlineEditorTest)
        val btnSave = view.findViewById<MaterialButton>(R.id.inlineEditorSave)
        val btnCancel = view.findViewById<MaterialButton>(R.id.inlineEditorCancel)
        val btnClose = view.findViewById<ImageView>(R.id.inlineEditorClose)
        val btnRetest = view.findViewById<TextView>(R.id.inlineEditorRetest)
        val resultBlock = view.findViewById<View>(R.id.inlineEditorResult)
        val resultType = view.findViewById<TextView>(R.id.inlineEditorResultType)
        val resultStatus = view.findViewById<TextView>(R.id.inlineEditorResultStatus)
        val rawBody = view.findViewById<TextView>(R.id.inlineEditorRawBody)
        val mappingContainer = view.findViewById<LinearLayout>(R.id.inlineEditorMappingContainer)
        val errorView = view.findViewById<TextView>(R.id.inlineEditorError)

        scopeChips.visibility = if (kind == Kind.IP_COMPARISON) View.VISIBLE else View.GONE

        resultBlock.visibility = View.GONE
        btnSave.isEnabled = false

        if (editData != null) {
            urlEdit.setText(editData.url)
            labelEdit.setText(editData.label)
            currentMapping = editData.mapping
            autoDetectedFields = fieldsFromMapping(editData.mapping)
            if (kind == Kind.IP_COMPARISON && editData.scope == EndpointScope.NON_RU) {
                scopeChips.check(R.id.inlineEditorScopeNonRu)
            }
            btnSave.isEnabled = true
        }

        val performTest: () -> Unit = {
            val url = urlEdit.text?.toString()?.trim().orEmpty()
            if (url.isBlank()) {
                errorView.text = view.context.getString(R.string.inline_editor_url_required)
                errorView.visibility = View.VISIBLE
            } else {
                errorView.visibility = View.GONE
                btnTest.isEnabled = false
                btnRetest.isEnabled = false
                btnTest.setText(R.string.inline_editor_testing)
                scope.launch {
                    val result = EndpointResponseMapper.testEndpoint(url)
                    btnTest.isEnabled = true
                    btnRetest.isEnabled = true
                    btnTest.setText(R.string.inline_editor_test)
                    if (result.success && result.detectedType != null) {
                        currentRawBody = result.rawBody
                        currentMapping = result.suggestedMapping ?: ResponseMapping(responseType = result.detectedType)
                        autoDetectedFields = fieldsFromMapping(currentMapping)
                        resultType.text = result.detectedType.name
                        resultStatus.text = view.context.getString(
                            R.string.inline_editor_result_status,
                            result.statusCode ?: 0,
                            result.responseTimeMs,
                        )
                        rawBody.text = (result.rawBody ?: "").take(2000)
                        resultBlock.visibility = View.VISIBLE
                        rebuildMappingRows(mappingContainer)
                        btnSave.isEnabled = true
                    } else {
                        errorView.text = view.context.getString(
                            R.string.inline_editor_test_failed,
                            result.error ?: view.context.getString(R.string.inline_editor_unknown_error),
                        )
                        errorView.visibility = View.VISIBLE
                        resultBlock.visibility = View.GONE
                        btnSave.isEnabled = false
                    }
                }
            }
        }

        btnTest.setOnClickListener { performTest() }
        btnRetest.setOnClickListener { performTest() }

        btnCancel.setOnClickListener { dismiss(); onCancel() }
        btnClose.setOnClickListener { dismiss(); onCancel() }

        btnSave.setOnClickListener {
            val url = urlEdit.text?.toString()?.trim().orEmpty()
            if (url.isBlank()) {
                errorView.text = view.context.getString(R.string.inline_editor_url_required)
                errorView.visibility = View.VISIBLE
                return@setOnClickListener
            }
            val label = labelEdit.text?.toString()?.trim().orEmpty().ifBlank { url }
            val endpointScope = if (scopeChips.checkedChipId == R.id.inlineEditorScopeNonRu) {
                EndpointScope.NON_RU
            } else {
                EndpointScope.RU
            }
            val mapping = currentMapping.copy(
                responseType = currentMapping.responseType,
            )
            onSave(Result(url = url, label = label, mapping = mapping, scope = endpointScope))
            dismiss()
        }
    }

    fun dismiss() {
        rootView?.let { parent.removeView(it) }
        rootView = null
        currentRawBody = null
        currentMapping = ResponseMapping()
        autoDetectedFields = emptySet()
    }

    fun isShowing(): Boolean = rootView != null

    private fun rebuildMappingRows(container: LinearLayout) {
        container.removeAllViews()
        val inflater = LayoutInflater.from(container.context)
        val fieldsToShow = if (currentKind == Kind.IP_COMPARISON) {
            arrayOf(MappingField.IP)
        } else {
            MappingField.values()
        }
        fieldsToShow.forEach { field ->
            val row = inflater.inflate(R.layout.view_inline_mapping_row, container, false)
            val fieldName = row.findViewById<TextView>(R.id.mappingFieldName)
            val pathView = row.findViewById<TextView>(R.id.mappingPath)
            val autoBadge = row.findViewById<TextView>(R.id.mappingAutoBadge)
            val editorWrap = row.findViewById<TextInputLayout>(R.id.mappingEditorWrap)
            val editor = row.findViewById<TextInputEditText>(R.id.mappingEditor)
            val header = row.findViewById<View>(R.id.mappingHeader)

            fieldName.text = displayName(field)
            val path = pathFor(field)
            val displayPath = path?.takeIf { it.isNotBlank() }
            pathView.text = displayPath ?: container.context.getString(R.string.inline_editor_not_detected)
            pathView.setTextColor(
                if (displayPath != null) {
                    androidx.core.content.ContextCompat.getColor(container.context, R.color.status_green)
                } else {
                    androidx.core.content.ContextCompat.getColor(container.context, android.R.color.darker_gray)
                }
            )
            autoBadge.visibility = if (field in autoDetectedFields) View.VISIBLE else View.GONE

            header.setOnClickListener {
                if (editorWrap.visibility == View.VISIBLE) {
                    editorWrap.visibility = View.GONE
                } else {
                    editor.setText(path.orEmpty())
                    editorWrap.visibility = View.VISIBLE
                    editor.requestFocus()
                }
            }
            editor.setOnFocusChangeListener { _, hasFocus ->
                if (!hasFocus) {
                    val newPath = editor.text?.toString()?.trim().orEmpty()
                    setPathFor(field, newPath.ifBlank { null })
                    pathView.text = newPath.ifBlank {
                        container.context.getString(R.string.inline_editor_not_detected)
                    }
                }
            }

            container.addView(row)
        }
    }

    private fun pathFor(field: MappingField): String? = when (field) {
        MappingField.IP -> currentMapping.ipPath
        MappingField.COUNTRY_CODE -> currentMapping.countryCodePath
        MappingField.COUNTRY_NAME -> currentMapping.countryNamePath
        MappingField.ISP -> currentMapping.ispPath
        MappingField.ORG -> currentMapping.orgPath
        MappingField.ASN -> currentMapping.asnPath
        MappingField.IS_HOSTING -> currentMapping.isHostingPath
        MappingField.IS_PROXY -> currentMapping.isProxyPath
    }

    private fun setPathFor(field: MappingField, value: String?) {
        currentMapping = when (field) {
            MappingField.IP -> currentMapping.copy(ipPath = value)
            MappingField.COUNTRY_CODE -> currentMapping.copy(countryCodePath = value)
            MappingField.COUNTRY_NAME -> currentMapping.copy(countryNamePath = value)
            MappingField.ISP -> currentMapping.copy(ispPath = value)
            MappingField.ORG -> currentMapping.copy(orgPath = value)
            MappingField.ASN -> currentMapping.copy(asnPath = value)
            MappingField.IS_HOSTING -> currentMapping.copy(isHostingPath = value)
            MappingField.IS_PROXY -> currentMapping.copy(isProxyPath = value)
        }
    }

    private fun displayName(field: MappingField): String = when (field) {
        MappingField.IP -> "IP"
        MappingField.COUNTRY_CODE -> "Country code"
        MappingField.COUNTRY_NAME -> "Country name"
        MappingField.ISP -> "ISP"
        MappingField.ORG -> "Organization"
        MappingField.ASN -> "ASN"
        MappingField.IS_HOSTING -> "Hosting"
        MappingField.IS_PROXY -> "Proxy/VPN"
    }

    private fun fieldsFromMapping(m: ResponseMapping): Set<MappingField> {
        val set = mutableSetOf<MappingField>()
        if (!m.ipPath.isNullOrBlank()) set += MappingField.IP
        if (!m.countryCodePath.isNullOrBlank()) set += MappingField.COUNTRY_CODE
        if (!m.countryNamePath.isNullOrBlank()) set += MappingField.COUNTRY_NAME
        if (!m.ispPath.isNullOrBlank()) set += MappingField.ISP
        if (!m.orgPath.isNullOrBlank()) set += MappingField.ORG
        if (!m.asnPath.isNullOrBlank()) set += MappingField.ASN
        if (!m.isHostingPath.isNullOrBlank()) set += MappingField.IS_HOSTING
        if (!m.isProxyPath.isNullOrBlank()) set += MappingField.IS_PROXY
        return set
    }
}
