---
title: "Primary network-interface enumeration"
permalink: /help/en/native/interface-enumeration/
---

# Primary network-interface enumeration

> **ID:** `INTERFACE_ENUMERATION`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Mixed

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`NativeInterfaceProbe.collectInterfaces()` obtains interfaces through native `getifaddrs()`, groups records by name, and adds the index, MTU, flags, ARP type, and addresses. `evaluateInterfaces()` always emits a summary of total and active interface counts. It then compares active names against the patterns `tun*`, `tap*`, `wg*`, `ppp*`, `utun*`, `zt*`, `tailscale*`, `svpn*`, `gre*`, `l2tp*`, and `he-ipv6*`.

### Exact trigger condition

A high-confidence finding is created only for an interface with `isUp=true` whose normalized name matches a VPN pattern. An empty interface list produces a low-confidence review finding; the ordinary summary is informational.

## What the result means

A line containing a specific VPN-like name is a strong local indicator of a TUN, WireGuard, or PPP path. A summary without such a name proves nothing and exists for comparison between runs.

**How the line affects the report:** The same ID is used for both informational summaries and suspicious lines. The outcome depends on the specific detail and checker branch.

## Limitations and possible false positives

OEM and corporate interface names may match a pattern. The reverse problem is also possible: a renamed tunnel may evade the name pattern but still be exposed by its TUN/TAP type, netlink, routes, or a JVM/native inconsistency.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy.

### With root

Laboratory-grade hiding usually requires a system Java layer and one native backend. With VPNHide, this means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod/KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but also warns about possible boot loops and kernel panics; it should be tested only on a test device.

### How to verify the result

```bash
adb shell ip -details link show
adb shell ip -br address show
adb shell cat /proc/net/dev
```
Compare the name, UP state, index, and MTU with the RKNHardering detail. Remember that the shell UID is not the app UID; perform the final verification after `adb shell am force-stop com.notcvnt.rknhardering` and a fresh launch.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

An external gateway changes the entire network path. Root or kernel filtering can cause loss of connectivity, a hung `getifaddrs()`, or a boot loop on an incompatible kernel.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Mixed.** Verified against `evaluateInterfaces()`, `NetworkInterfacePatterns`, and the C++ interface collector. The primary signal is covered by catalog and checker unit tests.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NetworkInterfacePatterns.kt` — interface-name rules](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [getifaddrs(3)](https://man7.org/linux/man-pages/man3/getifaddrs.3.html).
- External primary documentation or official project: [Android VpnService](https://developer.android.com/reference/android/net/VpnService).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `tuntap-type`, `jvm-native-mismatch`, `getifaddrs-vpn`, `rtm-getlink-vpn`.

[Back to the Native signs reference](../)
