package com.notcvnt.rknhardering.customcheck.ui.editor

import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.CustomDomain
import com.notcvnt.rknhardering.customcheck.ui.CheckerSectionController
import com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController

internal class DomainReachabilitySectionBinder(host: SectionBinder.Host) : SectionBinder<Boolean>(host) {

    override val sectionId = CheckerSectionController.DOMAIN_REACHABILITY
    override val titleRes = R.string.settings_custom_check_section_domain_reachability
    override val iconRes = R.drawable.ic_public
    override val bodyLayout = R.layout.section_body_domain_reachability

    /** Reachability-type domains split out of profile.customDomains. */
    val domains = mutableListOf<CustomDomain>()

    override fun bind(body: View, profile: CustomCheckProfile) {
        domains.clear()
        profile.customDomains
            .filter { isReachabilityType(it.checkType) }
            .forEach { domains.add(it.copy(checkType = "reachability")) }

        val container = body.findViewById<LinearLayout>(R.id.containerReachabilityDomains)
        rebuildPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddReachabilityDomain).setOnClickListener {
            showEditor(container)
        }
    }

    override fun collect(body: View?, enabled: Boolean): Boolean = enabled

    override fun summary(body: View): String =
        host.string(R.string.editor_summary_domain_reachability, domains.size)

    private fun rebuildPills(container: LinearLayout) {
        EndpointPills.rebuild(container, domains.mapIndexed { idx, d ->
            EndpointPillData(
                name = d.domain,
                url = d.description.ifEmpty { d.domain },
                scope = null,
                onRemove = {
                    domains.removeAt(idx)
                    rebuildPills(container)
                    refreshOwnSummary()
                },
                onEdit = {
                    showEditor(container, editIndex = idx)
                },
            )
        })
    }

    private fun showEditor(container: LinearLayout, editIndex: Int = -1) {
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddReachabilityDomain) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotDomainReachability) }

        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) domains[editIndex] else null
        val initialValues = existing?.let {
            GenericInlineEditorController.InitialValues(
                url = it.domain,
                label = it.description,
                expectedDns = it.expectedDnsAvailable,
                expectedTcp = it.expectedTcpAvailable,
                expectedTls = it.expectedTlsAvailable,
            )
        }

        val controller = GenericInlineEditorController(slot, host.lifecycleScope)
        controller.show(
            config = GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_reachability_domain,
                urlHintRes = R.string.settings_custom_check_domain_field,
                labelHintRes = R.string.settings_custom_check_description_field,
                extraInputHintRes = null,
                extraSwitchTextRes = null,
                showExpectedChecks = true,
                testAction = { domain, _, _ ->
                    val response = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        com.notcvnt.rknhardering.checker.DomainReachabilityChecker.checkSingleDomain(
                            domain = domain,
                            label = domain,
                        )
                    }
                    // Auto-set expected booleans from test result (on Main thread)
                    val dnsOk = response.dnsStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK
                    val tcpOk = response.tcpStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK
                    val tlsOk = response.tlsStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK
                    controller.setExpectedChecks(dnsOk, tcpOk, tlsOk)

                    val statusIcon = { ok: Boolean -> if (ok) "✅" else "❌" }
                    val msg = host.string(
                        R.string.domain_reachability_test_result,
                        statusIcon(dnsOk),
                        statusIcon(tcpOk),
                        statusIcon(tlsOk),
                    )
                    val allOk = dnsOk && tcpOk && tlsOk
                    allOk to msg
                },
                saveAction = { _, _, _, _ -> },
                saveActionEx = { domain, label, _, _, expectedDns, expectedTcp, expectedTls ->
                    val newDomain = CustomDomain(
                        domain = domain,
                        checkType = "reachability",
                        description = label,
                        expectedDnsAvailable = expectedDns,
                        expectedTcpAvailable = expectedTcp,
                        expectedTlsAvailable = expectedTls,
                    )
                    if (editIndex >= 0) {
                        domains[editIndex] = newDomain
                    } else {
                        domains.add(newDomain)
                    }
                    rebuildPills(container)
                    refreshOwnSummary()
                    btnAdd.visibility = View.VISIBLE
                }
            ),
            onCancel = { btnAdd.visibility = View.VISIBLE },
            initialValues = initialValues,
        )
    }

    companion object {
        fun isReachabilityType(checkType: String): Boolean {
            val ct = checkType.trim().lowercase()
            return ct == "reachability" || ct == "dpi"
        }
    }
}
