---
title: Practical countermeasures against VPN and modification detection
permalink: /help/en/anti-detection/
---

# Practical countermeasures against VPN and modification detection

This guide describes the other side of RKNHardering checks: what an application can actually observe, which methods genuinely change the observable state, and which merely create the appearance of a solution. It is intended for development, compatibility testing, and verification of your own defensive mechanisms. The settings below do not provide a universal guarantee of passing third-party anti-fraud systems: they may use additional server-side signals, hardware attestation, and proprietary rules.

The material was verified against the RKNHardering 2.10.0 source code included in this project copy. Completeness is tracked against three registries: **65 `EvidenceSource` entries**, **85 `NativeSignalId` entries**, and **41 beta checks**. For every identifier, the [complete matrix](./matrix/) contains separate columns for “without root,” “with root,” and “what remains visible anyway.”

## Choose the correct class of solution first

| What RKNHardering detects | What must actually be changed | Best practical option |
|---|---|---|
| GeoIP, different IPs in RU/non-RU checks, CDN, STUN, calls | The route and the real public address | Correct application routing and consistent DNS/HTTP/UDP; where necessary, an exit with the required country/network type |
| `TRANSPORT_VPN`, TUN, routes, netlink, `/proc`, interfaces | Android’s local representation of the network | Without root: move the VPN to a router or another device; with root: a system Java layer plus exactly one kernel/native backend |
| Localhost ports, Clash/sing-box/Xray APIs | Access by the target UID to the local control plane | Disable the listener/API; with root, block loopback for the target UID |
| Installed VPN applications | Package visibility | A separate profile helps only partially; with root, filter `PackageManager` in `system_server` |
| Magisk/KernelSU/APatch, hooks, RWX, `maps`, properties, mounts | Process state and mount namespace | Do not inject hooks into the target process; minimize the root surface; prefer a kernel-level solution over Zygisk |
| Secondary space, work profile, clone | Android user/profile identity | Run under the primary user; moving the app to a profile is not a complete bypass and produces its own signal |

## The main non-root limitation

Android `VpnService` creates a virtual interface and a system VPN model. Excluding an application from the tunnel through per-app routing changes the path of that application’s traffic, but does not necessarily hide the existence of the TUN interface, VPN network, and related routes. Current RKNHardering checks these separately: an active TUN interface while the application itself has no VPN is treated as evidence of an explicit per-app exclusion. Therefore, adding RKNHardering to a bypass list can help against server-side IP signals, but is not VPN concealment by itself.

The strongest option without root is to **remove the VPN from the phone as a system object**: run it on a router, travel router, another phone acting as a hotspot, or another gateway. Then the inspected Android device has no `VpnService`, TUN interface, or VPN application. The public IP and server-side characteristics must still remain consistent.

Official Android documentation: [`VpnService`](https://developer.android.com/reference/android/net/VpnService) and [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder). The `addAllowedApplication`/`addDisallowedApplication` methods control per-application routing, while `establish()` creates the VPN interface itself.

## How to read this guide

Source labels are used directly throughout the text:

- **Verified by the project** — the conclusion follows from the RKNHardering code and registries in this copy.
- **Claimed by an external project** — the capability is described by the developers of VPNHide, VPNHide Next, a root framework, or another tool; it must be reproduced on the specific firmware.
- **Reported by the community** — a working scenario or configuration, but not a universal guarantee.

Start with the [threat model and recommended order of work](./threat-model/) rather than immediately installing modules. Then choose the relevant page:

- [Network path: GeoIP, IP consensus, DNS, CDN, STUN, calls, and RTT](./network-path/)
- [Local Android signals: Binder, TUN, routes, packages, proxy, and localhost](./local-signals/)
- [Root stack: VPNHide, VPNHide Next, Vector/LSPosed, Magisk, KernelSU, and APatch](./root-vpnhide/)
- [Secondary spaces, work profiles, Private Space, and clones](./profiles/)
- [Root, hooks, emulators, and process integrity](./root-integrity/)
- [Beta checks and their quorum](./beta/)
- [Complete matrix of all identifiers](./matrix/)
- [Laboratory procedure, verification commands, and rollback](./lab/)
- [Sources, downloads, and verification date](./sources/)

## Minimum safe sequence

1. Save a clean restore point: firmware version, `boot.img`/`init_boot.img` as required by your root solution, module list, VPN configuration, and a backup of profile data.
2. First correct the real network path without hooks: public IP, DNS, application routing, and localhost APIs.
3. Test local Android signals separately. Do not combine egress changes and TUN concealment into a single conclusion.
4. When using root, enable **exactly one** VPNHide native backend. Concurrent kernel backends can freeze the device or cause a kernel panic.
5. After every change, restart the target application and repeat the test at least twice while the network state remains stable.
6. If the result becomes worse, disable the most recent change instead of stacking another module on top of it.

## What counts as a successful result

Success is not a single green card. All of the following are required at the same time:

- the same expected public IP over HTTP, DNS, and UDP wherever applicable;
- no high-confidence local VPN signals;
- no obvious localhost/control-plane leaks;
- no new root, hook, or isolation signals introduced by the bypass method itself;
- reproducible results after force-stop, network changes, and reboot.

[Back to the English reference](../)
