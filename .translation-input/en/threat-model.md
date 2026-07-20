---
title: Threat model and order of countermeasures
permalink: /help/en/anti-detection/threat-model/
---

# Threat model and order of countermeasures

Before choosing a module, divide the inspection into three independent layers. Most failed configurations cover only one layer and mistake that for a complete bypass.

## 1. The server and the real network path

This layer exists outside the Android process. RKNHardering compares the public address, country, ASN/ISP, responses from RU and non-RU services, the DNS path, CDN redirects, STUN, and transport probes. Neither LSPosed nor a kernel module can turn a foreign datacenter IP into a Russian residential address. Only routing and a suitable exit can change this layer.

The practical question is: **which address and route does the remote side actually observe?** The answer depends on split tunneling, DNS, IPv4/IPv6, UDP, and the specific endpoint. See the [network-path section](../network-path/) for details.

## 2. Android’s local network model

This consists of Binder/Java APIs and native kernel interfaces:

- `NetworkCapabilities`, `NetworkInfo`, `LinkProperties`, and callbacks;
- `NetworkInterface`, `getifaddrs`, `ioctl(SIOCGIF*)`, and netlink `RTM_GET*`;
- `/proc/net/*`, `/sys/class/net`, policy rules, qdisc, and socket identity;
- the system proxy, local ports, and control APIs;
- visibility of installed packages and `VpnService`.

This is where the fundamental non-root boundary lies. An ordinary VPN application can exclude a package from the tunnel, but it cannot rewrite `system_server` and kernel responses for another UID. An external router removes local indicators because no VPN is created on the inspected Android device at all. Root solutions can filter data in `system_server` and in the kernel.

## 3. Device and process integrity

A concealment module can become a signal itself. RKNHardering checks root files and properties, mounts, SELinux, hooks, RWX regions, library integrity, Java/native inconsistencies, emulation, and the current user profile. A module injected directly into the RKNHardering process may remove `TRANSPORT_VPN` while leaving a stronger hook or tampering trace.

The correct root architecture is therefore: sanitize Java data in `system_server`, filter native data at kernel level, and do not inject Xposed/Zygisk into the target process. This is why VPNHide recommends combining its system Java layer with exactly one kernel backend and treating Zygisk as a fallback.

## Without root

Four honest actions are available without root.

First, change the real traffic path. For example, exclude `com.notcvnt.rknhardering` from the VPN and route it directly or through the expected exit. This helps with GeoIP and IP-consensus checks, but the current TUN Active Probe can detect the combination “a TUN exists, but the application itself has no VPN.”

Second, move the VPN off the phone. A router, separate gateway, or hotspot provides the cleanest local view: Android sees ordinary Wi-Fi rather than `VpnService`. This is the only general non-root method that removes Binder, TUN, netlink, and VPN-package signals from the inspected device at the same time.

Third, remove unnecessary configuration leaks: system proxy, PAC, loopback listeners, Clash/sing-box/Xray APIs, weak authentication, and a separate DNS path. This does not hide the TUN interface, but it closes independent detection channels.

Fourth, use a separate profile or user. This separates data and installed packages, but it is not invisible: Android assigns the profile a separate userId/UID, and RKNHardering has stable and beta isolation signals. In the current VerdictEngine, one profile signal usually produces a review; combined with a network discrepancy, the beta quorum can produce a detected result.

## With root

Root expands the available controls, but does not eliminate the network layer. A working design has four independent elements:

1. Application routing and consistent egress.
2. Java/Binder filtering in `system_server`.
3. Exactly one native/kernel backend for `ioctl`, netlink, routes, and proc/sysfs.
4. Blocking localhost/control-plane access and minimizing root/hook traces.

For supported GKI devices, the VPNHide kernel module is preferable. Older or non-GKI kernels may use the KPM/KernelPatch backend. Zygisk is more convenient, but raw syscalls bypass its libc hooks and process-integrity checks can expose it. VPNHide Next claims additional coverage for MTU/MSS/TCP_INFO, PMTU/GSO, eBPF, qdisc, timing, and IPv6 link-local signals; however, the project itself warns about bootloop and kernel-panic risks. It is an experimental branch, not a safe default “maximum mode.”

## How RKNHardering reaches the final verdict

Verified by the project: the verdict is not a simple sum of all rows. The evidence source, independence, and evidence domain matter.

- An explicit bypass through split tunneling, a local proxy/Xray/Clash API, a gateway leak, or binding to the underlying network may immediately produce strong evidence.
- A consistent discrepancy in public IP or location participates in separate consensus logic.
- Root, hooks, isolation, and some native signals more often produce `NEEDS_REVIEW` when there is no independent network confirmation.
- Beta checks are disabled by default. The only individual hard-authority paths are `beta.vpn_binder` and `beta.tun_fd`, and even those require repeated stable samples. Other beta signals become `DETECTED` through a quorum of independent groups or in combination with stable evidence.

The practical conclusion is important: trying to “fix” every informational row is pointless. Close the strongest independent sources first: real egress, Binder VPN state, native interface/route enumeration, localhost APIs, and explicit root/hook traces.

## False senses of security

**Split tunnel only.** Traffic goes directly, but the TUN interface and VPN network remain. The current probe explicitly searches for this combination.

**Only an LSPosed hook inside the application.** Java APIs appear clean, but `getifaddrs`, netlink, and raw syscalls remain, while the process acquires hook markers.

**Only Zygisk native hiding.** Ordinary libc paths are covered, but direct syscalls, alternative receive functions, and process-integrity checks can reveal the intervention.

**Only renaming `tun0`.** RKNHardering checks more than the name: TUN/TAP type, ifindex, netlink, routes, MTU/MSS, policy rules, qdisc, and indirect socket signals.

**Only a secondary space.** Packages and data are separated, but userId/profile state remains visible. OEM clones often use characteristic userId values that the code checks separately.

**Only a root-hiding module.** It does not change the public IP, DNS, STUN, or CDN path. An incompatible module can also introduce new mounts, RWX regions, or linker anomalies.

## Recommended diagnostic sequence

Perform four runs and do not change several variables at the same time:

1. Clean phone without a VPN — the baseline for the device and firmware.
2. VPN enabled, RKNHardering inside the tunnel — shows the complete set of local and server-side signals.
3. VPN enabled, package excluded — separates server-side discrepancies from TUN/per-app bypass evidence.
4. Selected hiding method — shows which signals actually disappeared and which new ones were introduced by root or hooks.

For reproducibility, record the time, network, userId, module list, VPN client, profile, and two consecutive results. The complete template is in the [laboratory procedure](../lab/).

[Back to the contents](../)
