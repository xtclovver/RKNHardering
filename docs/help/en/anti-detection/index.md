---
title: Practical Countermeasures for VPN and Modification Detection
permalink: /help/en/anti-detection/
---

# Practical Countermeasures for VPN and Modification Detection

This guide explains the reverse side of RKNHardering’s checks: what the app actually observes, which approaches genuinely change the observable state, and which merely create the appearance of a solution. It is written for development, compatibility testing, and validation of defensive mechanisms you control. The settings below do not guarantee passage through third-party antifraud systems, which may use additional server-side signals, hardware-backed attestation, and proprietary rules.

The material has been checked against the RKNHardering 2.10.0 source code included in this project copy. Completeness is tracked against three registries: **65 `EvidenceSource` entries**, **85 `NativeSignalId` entries**, and **41 beta checks**. In the [complete matrix](./matrix/), every identifier has separate columns for “without root,” “with root,” and “what remains visible.”

## Choose the Right Class of Solution First

| What RKNHardering detects | What actually needs to change | Best practical option |
|---|---|---|
| GeoIP, differing IPs across RU/non-RU checks, CDN, STUN, and call tests | The route and the real external address | Correct per-app routing and consistent DNS/HTTP/UDP behavior; where required, an egress with the expected country and network type |
| `TRANSPORT_VPN`, TUN, routes, netlink, `/proc`, and interfaces | Android’s local network view | Without root, move the VPN to a router or another device; with root, use a system Java layer plus one kernel/native backend |
| Localhost ports and Clash/sing-box/Xray APIs | The target UID’s access to the local control plane | Disable the listener or API; with root, block loopback access for the target UID |
| Installed VPN applications | Package visibility | A separate profile helps only partially; with root, filter `PackageManager` in `system_server` |
| Magisk/KernelSU/APatch, hooks, RWX regions, `maps`, properties, and mounts | Process state and the mount namespace | Do not inject hooks into the target process; minimize the root surface; prefer a kernel-level solution over Zygisk |
| Second Space, work profiles, and app clones | Android user/profile identity | Run in the primary user; moving into a profile is not a complete bypass and creates its own signal |

## The Main Non-Root Limitation

Android `VpnService` creates a virtual interface and a system VPN model. Excluding an app from the tunnel through per-app routing changes the path used by that app’s traffic, but it does not necessarily hide the existence of the TUN interface, VPN network, or related routes. RKNHardering checks this separately: an active TUN interface while the app itself has no VPN transport is treated as evidence of explicit per-app exclusion. Adding RKNHardering to a bypass list can therefore help with server-side IP signals, but it is not VPN hiding by itself.

The strongest non-root design is to **remove the VPN from the phone as a system object**: run it on a router, travel router, separate phone acting as a hotspot, or another gateway. The Android device under test then has no `VpnService`, TUN interface, or VPN client package. The external IP and server-side indicators must still remain internally consistent.

The official Android references are [`VpnService`](https://developer.android.com/reference/android/net/VpnService) and [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder). `addAllowedApplication` and `addDisallowedApplication` control app routing, while `establish()` creates the VPN interface itself.

## How to Read This Guide

Source labels are used consistently throughout the text:

- **Project-verified** — the conclusion follows from the RKNHardering code in this copy and its registries.
- **Claimed by an external project** — the capability is described by the developers of VPNHide, VPNHide Next, a root framework, or another tool; it must be reproduced on the specific firmware.
- **Community-reported** — a reported working scenario or configuration, not a universal guarantee.

Start with the [threat model and order of operations](./threat-model/) rather than installing modules immediately. Then use the relevant page:

- [Network path: GeoIP, IP consensus, DNS, CDN, STUN, calls, and RTT](./network-path/)
- [Local Android signals: Binder, TUN, routes, packages, proxy, and localhost](./local-signals/)
- [Root stack: VPNHide, VPNHide Next, Vector/LSPosed, Magisk, KernelSU, and APatch](./root-vpnhide/)
- [Second spaces, work profiles, Private Space, and clones](./profiles/)
- [Root, hooks, emulators, and process integrity](./root-integrity/)
- [Beta checks and their quorum](./beta/)
- [Complete matrix of every identifier](./matrix/)
- [Laboratory methodology, verification commands, and rollback](./lab/)
- [Sources, downloads, and verification date](./sources/)

## Minimum Safe Order of Operations

1. Save a clean recovery point: firmware version, `boot.img` or `init_boot.img` as appropriate for the root solution, module list, VPN configurations, and a backup of profile data.
2. Correct the actual network path before adding hooks: external IP, DNS, per-app routing, and localhost APIs.
3. Test local Android signals separately. Do not combine an egress change and TUN hiding into a single conclusion.
4. With root, use **exactly one** VPNHide native backend. Concurrent kernel backends can hang the device or cause a kernel panic.
5. After every change, restart the target app and repeat the test at least twice under one stable network state.
6. When the result gets worse, disable the most recent change instead of stacking another module on top of it.

## What Counts as Success

Success is not one green card. All of the following must hold together:

- the expected external IP is consistent across HTTP, DNS, and UDP where applicable;
- no high-confidence local VPN signals remain;
- no obvious localhost or control-plane leaks remain;
- the bypass method has not introduced new root, hook, or isolation signals;
- the result is reproducible after a force-stop, network change, and reboot.

[Back to the English help index](../)
