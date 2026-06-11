package com.notcvnt.rknhardering.customcheck.ui.editor

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.annotation.IdRes
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.customcheck.EndpointScope
import com.notcvnt.rknhardering.customcheck.ui.InlineEndpointEditorController

/**
 * Shared add/edit wiring for the sections backed by InlineEndpointEditorController
 * (GeoIP providers, IP-comparison endpoints, CDN targets). Owns the mutable item
 * list and the pill rendering; the per-section binder supplies the item mapping.
 */
internal class InlineEndpointSection<T>(
    private val host: SectionBinder.Host,
    private val sectionId: String,
    private val kind: InlineEndpointEditorController.Kind,
    @param:IdRes private val slotId: Int,
    @param:IdRes private val addButtonId: Int,
    @param:IdRes private val containerId: Int,
    private val pillName: (T) -> String,
    private val pillUrl: (T) -> String,
    private val pillScope: (T) -> EndpointScope?,
    private val fromResult: (InlineEndpointEditorController.Result) -> T,
    private val toEditData: (T) -> InlineEndpointEditorController.EditData,
) {

    val items = mutableListOf<T>()

    private var editor: InlineEndpointEditorController? = null

    fun bind(body: View, configItems: List<T>) {
        items.clear()
        items.addAll(configItems)
        val container = body.findViewById<LinearLayout>(containerId)
        rebuildPills(body, container)

        val btnAdd = body.findViewById<MaterialButton>(addButtonId)
        btnAdd.setOnClickListener {
            if (editor?.isShowing() == true) return@setOnClickListener
            btnAdd.visibility = View.GONE
            showEditor(body, container, btnAdd, editIndex = -1)
        }
    }

    private fun rebuildPills(body: View, container: LinearLayout) {
        EndpointPills.rebuild(
            container,
            items.mapIndexed { idx, item ->
                EndpointPillData(
                    name = pillName(item),
                    url = pillUrl(item),
                    scope = pillScope(item),
                    onRemove = {
                        items.removeAt(idx)
                        rebuildPills(body, container)
                        host.refreshSummary(sectionId)
                    },
                    onEdit = {
                        val btnAdd = body.findViewById<MaterialButton>(addButtonId)
                        btnAdd.visibility = View.GONE
                        showEditor(body, container, btnAdd, editIndex = idx)
                    },
                )
            },
        )
    }

    private fun showEditor(body: View, container: LinearLayout, btnAdd: MaterialButton, editIndex: Int) {
        val slot = body.findViewById<ViewGroup>(slotId)
        val controller = InlineEndpointEditorController(slot, host.lifecycleScope)
        editor = controller
        controller.show(
            kind = kind,
            onCancel = {
                btnAdd.visibility = View.VISIBLE
                editor = null
            },
            onSave = { result ->
                val item = fromResult(result)
                if (editIndex >= 0) {
                    items[editIndex] = item
                } else {
                    items.add(item)
                }
                rebuildPills(body, container)
                btnAdd.visibility = View.VISIBLE
                editor = null
                host.refreshSummary(sectionId)
            },
            editData = if (editIndex >= 0) toEditData(items[editIndex]) else null,
        )
    }
}
