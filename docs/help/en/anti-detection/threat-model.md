---
title: Threat Model and Order of Countermeasures
permalink: /help/en/anti-detection/threat-model/
---

# Threat Model and Order of Countermeasures

Before choosing a module, divide the inspection into three independent layers. Most unsuccessful configurations cover only one layer and mistake that for a complete bypass.

## 1. The Server and the Real Network Path

This layer exists outside the Android process. RKNHardering compares the external address, country, ASN/ISP, responses from RU and non-RU services, the DNS path, CDN redirects, STUN, and transport probes. Neither LSPosed nor a kernel module can turn a foreign data-center IP into a Russian residential address. Only routing and an appropriate egress can change this layer.

The practical question is: **which address and route does the remote side actually observe?** The answer depends on split tunneling, DNS, IPv4/IPv6, UDP, and the specific endpoint. See the [network-path section](../network-path/) for details.

## 2. Android’s Local Network Model

This layer consists of Binder/Java APIs and native kernel interfaces:

- `NetworkCapabilities`, `NetworkInfo`, `LinkProperties`, and callbacks;
- `NetworkInterface`, `getifaddrs()`, `ioctl(SIOCGIF*)`, and netlink `RTM_GET*`;
- `/proc/net/*`, `/sys/class/net`, policy rules, qdisc, and socket identity;
- the system proxy, local ports, and control APIs;
- visibility of installed packages and `VpnService`.

This is where the fundamental non-root limit lies. An ordinary VPN app can exclude a package from its tunnel, but it cannot rewrite `system_server` and kernel responses for another UID. An external router removes local indicators because no VPN is created on the Android device under test at all. Root solutions can filter data in `system_server` and the kernel.

## 3. Device and Process Integrity

A hiding module can itself become a signal. RKNHardering checks root files and properties, mounts, SELinux, hooks, RWX regions, library integrity, Java/native inconsistencies, emulator indicators, and the current user profile. A module injected directly into the RKNHardering process may remove `TRANSPORT_VPN` while leaving a stronger hook or tampering artifact.

A sound root architecture keeps these responsibilities separate: Java data is filtered in `system_server`, native data is filtered at kernel level, and the target process receives no Xposed or Zygisk injection. This is why VPNHide recommends a system Java layer together with one kernel backend, while retaining Zygisk as a fallback.

## Without Root

Four honest actions are available without root.

First, change the actual traffic path. For example, exclude `com.notcvnt.rknhardering` from the VPN and send it directly or through the expected egress. This helps with GeoIP and IP-consensus checks, but the current TUN Active Probe can detect the combination “a TUN exists, but this app has no VPN transport.”

Second, move the VPN off the phone. A router, separate gateway, or hotspot provides the cleanest local view: Android sees ordinary Wi-Fi rather than `VpnService`. This is the only general non-root way to remove Binder, TUN, netlink, and VPN-client package signals from the device under test at the same time.

Third, remove unnecessary configuration leaks: the system proxy, PAC settings, loopback listeners, Clash/sing-box/Xray APIs, weak authentication, and a separate DNS path. This does not hide the TUN interface, but it closes independent detections.

Fourth, use a separate profile or user. It separates data and installed packages but is not invisible: Android assigns the profile a separate user ID and UID range, and RKNHardering has both stable and beta isolation signals. In the current `VerdictEngine`, one profile signal normally results in review, but combined with a network inconsistency, the beta quorum may produce `DETECTED`.

## With Root

Root expands what can be changed but does not eliminate the network layer. A working arrangement contains four independent elements:

1. Per-app routing and a consistent egress.
2. Java/Binder filtering in `system_server`.
3. Exactly one native/kernel backend for `ioctl`, netlink, routes, and proc/sysfs.
4. Blocking the localhost control plane and minimizing root/hook artifacts.

For a supported GKI kernel, a VPNHide kernel module is preferable. On older or non-GKI kernels, a KPM/KernelPatch backend may be possible. Zygisk is easier to deploy, but raw syscalls can bypass its libc hooks, and process-integrity checks can detect it. VPNHide Next claims additional coverage for MTU/MSS/TCP_INFO, PMTU/GSO, eBPF, qdisc, timing, and IPv6 link-local paths. The project itself warns about boot loops and kernel panics, however, so this is an experimental branch rather than a safe default “maximum mode.”

## How RKNHardering Reaches the Final Verdict

Project-verified: the final result is not a simple sum of every row. The source, independence, and evidence domain matter.

- An explicit bypass through split tunneling, a local proxy or Xray/Clash API, a gateway leak, or binding to the underlying network can immediately provide strong evidence.
- A consistent mismatch in external IP addresses or geolocation participates in separate consensus logic.
- Root, hooks, isolation, and some native signals more often move the result to `NEEDS_REVIEW` when no independent network confirmation exists.
- Beta checks are disabled by default. The only standalone hard-authority paths are `beta.vpn_binder` and `beta.tun_fd`, and they still require repeated stable samples. Other beta signals become `DETECTED` through a quorum of independent groups or in combination with stable evidence.

The practical implication is important: trying to “fix” every informational row is pointless. Address the strongest independent sources first—the real egress, Binder VPN state, native interface and route enumeration, localhost APIs, and explicit root or hook artifacts.

## False Senses of Security

**Split tunnel only.** Traffic exits directly, but the TUN interface and VPN network remain. The current check specifically looks for this combination.

**Only an LSPosed hook inside the app.** Java APIs appear clean, while `getifaddrs()`, netlink, and raw syscalls remain visible, and the process gains hook markers.

**Only Zygisk native hiding.** Common libc paths are covered, but direct syscalls, alternative receive functions, and process-integrity checks may expose the intervention.

**Only renaming `tun0`.** RKNHardering checks more than the name: the TUN/TAP type, interface index, netlink, routes, MTU/MSS, policy rules, qdisc, and indirect socket signals.

**Only a second space.** Packages and data are separated, but user ID and profile state remain visible. OEM clone systems often use recognizable user IDs that the code checks separately.

**Only a root-hiding module.** It does not change the external IP, DNS, STUN, or CDN behavior. An incompatible module may also create new mount, RWX, or linker anomalies.

## Recommended Diagnostic Sequence

Run four scenarios without changing several variables at once:

1. A clean phone with the VPN disabled—the device and firmware baseline.
2. VPN enabled with RKNHardering inside the tunnel—the full set of local and server-side signals.
3. VPN enabled with the package excluded—separates server-side mismatches from the TUN/per-app bypass.
4. The chosen hiding method—shows which signals genuinely disappeared and which new root or hook signals appeared.

For reproducibility, record the time, network, user ID, module list, VPN client, profile, and two consecutive results. The full template is in the [laboratory methodology](../lab/).

[Back to the anti-detection index](../)
