package com.notcvnt.rknhardering.customcheck.ui.editor

import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.customcheck.CallTransportConfig
import com.notcvnt.rknhardering.customcheck.CustomCheckProfile
import com.notcvnt.rknhardering.customcheck.IcmpSpoofingConfig
import com.notcvnt.rknhardering.customcheck.IcmpTarget
import com.notcvnt.rknhardering.customcheck.RttTarget
import com.notcvnt.rknhardering.customcheck.RttTriangulationConfig
import com.notcvnt.rknhardering.customcheck.StunServer
import com.notcvnt.rknhardering.customcheck.ui.CheckerSectionController
import com.notcvnt.rknhardering.customcheck.ui.GenericInlineEditorController

internal class IcmpSpoofingSectionBinder(host: SectionBinder.Host) : SectionBinder<IcmpSpoofingConfig>(host) {

    override val sectionId = CheckerSectionController.ICMP_SPOOFING
    override val titleRes = R.string.settings_custom_check_section_icmp_spoofing
    override val iconRes = R.drawable.ic_network_check
    override val bodyLayout = R.layout.section_body_icmp_spoofing
    override val enabledFallback = false

    val targets = mutableListOf<IcmpTarget>()

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.icmpSpoofing
        body.findViewById<TextInputEditText>(R.id.editIcmpTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<TextInputEditText>(R.id.editIcmpPingCount).setText(cfg.pingCount.toString())
        body.findViewById<MaterialSwitch>(R.id.switchIcmpBuiltinTargets).isChecked = cfg.builtinTargetsEnabled

        targets.clear()
        targets.addAll(cfg.customTargets)
        val container = body.findViewById<LinearLayout>(R.id.containerIcmpTargets)
        rebuildPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddIcmpTarget).setOnClickListener {
            showEditor(container)
        }
    }

    override fun collect(body: View?, enabled: Boolean): IcmpSpoofingConfig = IcmpSpoofingConfig(
        enabled = enabled,
        timeoutMs = body?.findViewById<TextInputEditText>(R.id.editIcmpTimeout)?.text?.toString()?.toIntOrNull() ?: 5_000,
        pingCount = body?.findViewById<TextInputEditText>(R.id.editIcmpPingCount)?.text?.toString()?.toIntOrNull() ?: 3,
        builtinTargetsEnabled = body?.findViewById<MaterialSwitch>(R.id.switchIcmpBuiltinTargets)?.isChecked ?: true,
        customTargets = targets.toList(),
    )

    override fun summary(body: View): String {
        val builtin = if (body.findViewById<MaterialSwitch>(R.id.switchIcmpBuiltinTargets).isChecked) 1 else 0
        return host.string(R.string.editor_summary_targets, builtin + targets.size)
    }

    private fun rebuildPills(container: LinearLayout) {
        EndpointPills.rebuild(container, targets.mapIndexed { idx, t ->
            EndpointPillData(
                name = t.label.ifBlank { t.host },
                url = "ping ${t.host}",
                scope = null,
                onRemove = {
                    targets.removeAt(idx)
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
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddIcmpTarget) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotIcmp) }

        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) targets[editIndex] else null
        val initialValues = existing?.let {
            GenericInlineEditorController.InitialValues(
                url = it.host, label = it.label, switchChecked = it.isControl,
            )
        }

        val controller = GenericInlineEditorController(slot, host.lifecycleScope)
        controller.show(
            config = GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_icmp_target,
                urlHintRes = R.string.settings_custom_check_target_host,
                labelHintRes = R.string.settings_custom_check_target_label,
                extraInputHintRes = null,
                extraSwitchTextRes = R.string.settings_custom_check_icmp_target_is_control,
                testAction = { hostName, _, _ ->
                    val result = runCatching { com.notcvnt.rknhardering.probe.SystemPingProber.probe(hostName, count = 1, replyTimeoutSeconds = 3) }.getOrNull()
                    if (result != null && result.hasReplies) {
                        true to "Ping OK: ${result.avgRttMs}ms"
                    } else {
                        false to "Ping failed or timeout"
                    }
                },
                saveAction = { hostName, label, _, isControl ->
                    val l = label.ifBlank { hostName }
                    val target = IcmpTarget(host = hostName, label = l, isControl = isControl)
                    if (editIndex >= 0) {
                        targets[editIndex] = target
                    } else {
                        targets.add(target)
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
}

internal class RttTriangulationSectionBinder(host: SectionBinder.Host) : SectionBinder<RttTriangulationConfig>(host) {

    override val sectionId = CheckerSectionController.RTT_TRIANGULATION
    override val titleRes = R.string.settings_custom_check_section_rtt_triangulation
    override val iconRes = R.drawable.ic_compare_arrows
    override val bodyLayout = R.layout.section_body_rtt_triangulation
    override val enabledFallback = false

    val targets = mutableListOf<RttTarget>()

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.rttTriangulation
        body.findViewById<TextInputEditText>(R.id.editRttTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<TextInputEditText>(R.id.editRttPingCount).setText(cfg.pingCount.toString())
        body.findViewById<MaterialSwitch>(R.id.switchRttBuiltinTargets).isChecked = cfg.builtinTargetsEnabled

        targets.clear()
        targets.addAll(cfg.customTargets)
        val container = body.findViewById<LinearLayout>(R.id.containerRttTargets)
        rebuildPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddRttTarget).setOnClickListener {
            showEditor(container)
        }
    }

    override fun collect(body: View?, enabled: Boolean): RttTriangulationConfig = RttTriangulationConfig(
        enabled = enabled,
        timeoutMs = body?.findViewById<TextInputEditText>(R.id.editRttTimeout)?.text?.toString()?.toIntOrNull() ?: 5_000,
        pingCount = body?.findViewById<TextInputEditText>(R.id.editRttPingCount)?.text?.toString()?.toIntOrNull() ?: 5,
        builtinTargetsEnabled = body?.findViewById<MaterialSwitch>(R.id.switchRttBuiltinTargets)?.isChecked ?: true,
        customTargets = targets.toList(),
    )

    override fun summary(body: View): String {
        val builtin = if (body.findViewById<MaterialSwitch>(R.id.switchRttBuiltinTargets).isChecked) 1 else 0
        return host.string(R.string.editor_summary_targets, builtin + targets.size)
    }

    private fun rebuildPills(container: LinearLayout) {
        EndpointPills.rebuild(container, targets.mapIndexed { idx, t ->
            EndpointPillData(
                name = t.label.ifBlank { t.host },
                url = "ping ${t.host}",
                scope = null,
                onRemove = {
                    targets.removeAt(idx)
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
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddRttTarget) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotRtt) }

        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) targets[editIndex] else null
        val initialValues = existing?.let {
            GenericInlineEditorController.InitialValues(
                url = it.host, label = it.label, extraInput = it.expectedLocation,
            )
        }

        val controller = GenericInlineEditorController(slot, host.lifecycleScope)
        controller.show(
            config = GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_rtt_target,
                urlHintRes = R.string.settings_custom_check_target_host,
                labelHintRes = R.string.settings_custom_check_target_label,
                extraInputHintRes = R.string.settings_custom_check_rtt_expected_location,
                extraSwitchTextRes = null,
                testAction = { hostName, _, _ ->
                    val result = runCatching { com.notcvnt.rknhardering.probe.SystemPingProber.probe(hostName, count = 1, replyTimeoutSeconds = 3) }.getOrNull()
                    if (result != null && result.hasReplies) {
                        true to "Ping OK: ${result.avgRttMs}ms"
                    } else {
                        false to "Ping failed or timeout"
                    }
                },
                saveAction = { hostName, label, loc, _ ->
                    val l = label.ifBlank { hostName }
                    val target = RttTarget(host = hostName, label = l, expectedLocation = loc)
                    if (editIndex >= 0) {
                        targets[editIndex] = target
                    } else {
                        targets.add(target)
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
}

internal class CallTransportSectionBinder(host: SectionBinder.Host) : SectionBinder<CallTransportConfig>(host) {

    override val sectionId = CheckerSectionController.CALL_TRANSPORT
    override val titleRes = R.string.settings_custom_check_section_call_transport
    override val iconRes = R.drawable.ic_call
    override val bodyLayout = R.layout.section_body_call_transport
    override val enabledFallback = false

    val servers = mutableListOf<StunServer>()

    override fun bind(body: View, profile: CustomCheckProfile) {
        val cfg = profile.checksConfig.callTransport
        body.findViewById<TextInputEditText>(R.id.editCallTransportTimeout).setText(cfg.timeoutMs.toString())
        body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinGlobalStun).isChecked = cfg.builtinGlobalStunEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinRuStun).isChecked = cfg.builtinRuStunEnabled
        body.findViewById<MaterialSwitch>(R.id.switchCallTransportMtproto).isChecked = cfg.checkMtproto

        servers.clear()
        servers.addAll(cfg.customStunServers)
        val container = body.findViewById<LinearLayout>(R.id.containerStunServers)
        rebuildPills(container)
        body.findViewById<MaterialButton>(R.id.btnAddStunServer).setOnClickListener {
            showEditor(container)
        }
    }

    override fun collect(body: View?, enabled: Boolean): CallTransportConfig = CallTransportConfig(
        enabled = enabled,
        timeoutMs = body?.findViewById<TextInputEditText>(R.id.editCallTransportTimeout)?.text?.toString()?.toIntOrNull() ?: 5_000,
        builtinGlobalStunEnabled = body?.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinGlobalStun)?.isChecked ?: true,
        builtinRuStunEnabled = body?.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinRuStun)?.isChecked ?: true,
        checkMtproto = body?.findViewById<MaterialSwitch>(R.id.switchCallTransportMtproto)?.isChecked ?: true,
        customStunServers = servers.toList(),
    )

    override fun summary(body: View): String {
        val builtin = (if (body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinGlobalStun).isChecked) 1 else 0) +
            (if (body.findViewById<MaterialSwitch>(R.id.switchCallTransportBuiltinRuStun).isChecked) 1 else 0)
        return host.string(R.string.editor_summary_targets, builtin + servers.size)
    }

    private fun rebuildPills(container: LinearLayout) {
        EndpointPills.rebuild(container, servers.mapIndexed { idx, s ->
            EndpointPillData(
                name = s.label.ifBlank { "${s.host}:${s.port}" },
                url = "stun://${s.host}:${s.port}",
                scope = null,
                onRemove = {
                    servers.removeAt(idx)
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
        val btnAdd = container.parent.let { (it as ViewGroup).findViewById<View>(R.id.btnAddStunServer) }
        val slot = container.parent.let { (it as ViewGroup).findViewById<FrameLayout>(R.id.inlineEditorSlotStun) }

        btnAdd.visibility = View.GONE

        val existing = if (editIndex >= 0) servers[editIndex] else null
        val initialValues = existing?.let {
            GenericInlineEditorController.InitialValues(
                url = it.host, label = it.label, extraInput = it.port.toString(),
            )
        }

        val controller = GenericInlineEditorController(slot, host.lifecycleScope)
        controller.show(
            config = GenericInlineEditorController.Config(
                titleRes = R.string.settings_custom_check_add_stun_server,
                urlHintRes = R.string.settings_custom_check_target_host,
                labelHintRes = R.string.settings_custom_check_target_label,
                extraInputHintRes = R.string.settings_custom_check_stun_port,
                extraSwitchTextRes = null,
                testAction = { hostName, portStr, _ ->
                    val port = portStr.toIntOrNull() ?: 3478
                    val result = runCatching {
                        com.notcvnt.rknhardering.probe.StunBindingClient.probeDualStack(
                            host = hostName,
                            port = port,
                            resolverConfig = com.notcvnt.rknhardering.network.DnsResolverConfig.system(),
                            binding = null
                        )
                    }.getOrNull()

                    val mappedIp = result?.ipv4Result?.getOrNull()?.mappedIp ?: result?.ipv6Result?.getOrNull()?.mappedIp
                    if (mappedIp != null) {
                        true to "STUN OK. Mapped IP: $mappedIp"
                    } else {
                        false to "STUN failed"
                    }
                },
                saveAction = { hostName, label, portStr, _ ->
                    val p = portStr.toIntOrNull() ?: 3478
                    val l = label.ifBlank { hostName }
                    val server = StunServer(host = hostName, port = p, label = l)
                    if (editIndex >= 0) {
                        servers[editIndex] = server
                    } else {
                        servers.add(server)
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
}
