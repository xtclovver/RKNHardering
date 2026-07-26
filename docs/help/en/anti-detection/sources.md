---
title: Sources, Downloads, and Claim Status
permalink: /help/en/anti-detection/sources/
---

# Sources, Downloads, and Claim Status

The key links and current project states were last checked manually on **July 19, 2026**. Always download through `releases/latest` in the official repository rather than using repackaged APK or ZIP files from chats. When a project publishes a SHA-256 checksum or signature, verify it before installation.

## RKNHardering — project-verified

- [Original RKNHardering project](https://github.com/xtclovver/RKNHardering)
- [Architecture and current checks in the README](https://github.com/xtclovver/RKNHardering/blob/main/README.md)
- Local sources in this copy: `DirectSignsChecker`, `IndirectSignsChecker`, `BypassChecker`, `NativeSignsChecker`, `VpnNativeDetectorChecker`, `BetaCheckRegistry`, `BetaEvidencePolicy`, `VerdictEngine`, `NativeSignalId`, and `EvidenceSource`.
- [Research note on β checks](https://github.com/xtclovver/RKNHardering/blob/main/docs/beta-checks-research.md)

Every exact count and ID in this guide was derived from the local code rather than from a third-party list.

## Android and AOSP — architectural constraints

- [`VpnService`](https://developer.android.com/reference/android/net/VpnService) — virtual-interface creation, `protect()`, and underlying networks.
- [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder) — allowed and disallowed applications, routes, DNS, MTU, and proxy configuration.
- [Package visibility filtering](https://developer.android.com/training/package-visibility) — Android 11+ restrictions on package visibility.
- [AOSP Work profiles](https://source.android.com/docs/devices/admin/managed-profiles) — separate user ID, UID, and profile data.
- [AOSP Private space](https://source.android.com/docs/security/features/private-space) — private profiles and locked or stopped state.
- [AOSP Application Sandbox](https://source.android.com/docs/security/app-sandbox) — UID-based isolation.

## Upstream VPNHide — external claims; verify on the device

- [Repository](https://github.com/okhsunrog/vpnhide)
- [Latest release](https://github.com/okhsunrog/vpnhide/releases/latest)
- [Complete detection-vector map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)
- [kmod README](https://github.com/okhsunrog/vpnhide/blob/main/kmod/README.md)
- [KPM README](https://github.com/okhsunrog/vpnhide/blob/main/kmod/kpm/README.md)
- [Zygisk README](https://github.com/okhsunrog/vpnhide/blob/main/zygisk/README.md)
- [LSPosed/application README](https://github.com/okhsunrog/vpnhide/blob/main/lsposed/README.md)
- [portshide README](https://github.com/okhsunrog/vpnhide/blob/main/portshide/README.md)

Important limitations documented by the project: server-side signals are outside its scope; raw syscalls bypass Zygisk; kernel backends and Zygisk should not be stacked; and some procfs and KPM-parity cases remain conditional.

## VPNHide Next — broader experimental fork

- [Repository](https://github.com/soranerai/vpnhide_next)
- [Latest release](https://github.com/soranerai/vpnhide_next/releases/latest)
- [LSPosed/system_server README](https://github.com/soranerai/vpnhide_next/blob/main/lsposed/README.md)
- [Kernel-module README](https://github.com/soranerai/vpnhide_next/blob/main/kmod/README.md)

The project claims additional coverage for MTU, MSS, `TCP_INFO`, PMTU, GSO, BPF, qdisc, timing, sysfs, procfs, and profile vectors. Its README separately warns about instability, boot loops, and kernel panics. This guide labels those capabilities as external claims.

## Root and frameworks

- [Magisk](https://github.com/topjohnwu/Magisk), [releases](https://github.com/topjohnwu/Magisk/releases/latest), [install.md](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md)
- [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next), [releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest), [documentation](https://kernelsu-next.github.io/webpage/)
- [APatch](https://github.com/bmax121/APatch), [releases](https://github.com/bmax121/APatch/releases/latest), [Russian installation guide](https://apatch.dev/ru/install.html)
- [Vector](https://github.com/JingMatrix/Vector), [releases](https://github.com/JingMatrix/Vector/releases/latest)
- [Archived LSPosed](https://github.com/LSPosed/LSPosed)
- [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext), [releases](https://github.com/Dr-TSNG/ZygiskNext/releases/latest)
- [NoHello](https://github.com/MhmRdd/NoHello), [releases](https://github.com/MhmRdd/NoHello/releases/latest)
- [SUSFS core](https://gitlab.com/simonpunk/susfs4ksu), [SUSFS userspace module](https://github.com/sidex15/susfs4ksu-module), [releases](https://github.com/sidex15/susfs4ksu-module/releases/latest)
- [Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist), [releases](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest)

NoHello, Zygisk Next, SUSFS, and HMA are not required and are not guaranteed to work against RKNHardering. They are listed as options for researching the root surface. It is particularly important not to confuse HMA with VPNHide Apps: HMA usually operates in the selected application's context, whereas VPNHide filters PackageManager through `system_server`.

## Profiles and clones

- [Shelter](https://gitea.angry.im/PeterCxy/Shelter)
- [Insular](https://gitlab.com/secure-system/Insular)
- [AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles)
- [AOSP Private Space](https://source.android.com/docs/security/features/private-space)

Removing a profile erases its data. Make a separate backup before experimenting.

## VPN clients and routing

- [sing-box Android](https://sing-box.sagernet.org/clients/android/)
- [sing-box route rules](https://sing-box.sagernet.org/configuration/route/rule/)
- [sing-box DNS](https://sing-box.sagernet.org/configuration/dns/)
- [Mihomo general configuration](https://wiki.metacubex.one/en/config/general/)
- [RKNHardering-defense](https://github.com/jinndi/RKNHardering-defense)
- [Community Sub-Store guide](https://github.com/jinndi/RKNHardering-defense/blob/main/SUB-STORE.md)
- [Community S-UI guide](https://github.com/jinndi/RKNHardering-defense/blob/main/S-UI.md)

The `RKNHardering-defense` materials are labeled as community reports. They are useful examples for split routing and external gateways, but they do not demonstrate concealment of every local and β vector in version 2.10.0.

## Why this guide does not link random “universal bypass APKs”

An application that demands disabling Play Protect, granting Accessibility or Device Admin without a clear reason, uploading a SuperKey, importing a private subscription, or installing an unsigned kernel ZIP creates disproportionate risk. Verify the source, repository history, release signature or hash, and requested permissions. Never give root keys, VPN secrets, or logs containing tokens to authors of unverified builds.

[Back to the contents](../)
