---
title: "ARPHRD_TUNNEL/TUN-TAP Interface Type Regardless of Name"
permalink: /help/en/native/tuntap-type/
---

# ARPHRD_TUNNEL/TUN-TAP Interface Type Regardless of Name

> **ID:** `TUNTAP_TYPE`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

After the main `getifaddrs()` snapshot, the checker reads each interface type and compares it with `ARPHRD_TUNTAP = 65534`. The check specifically selects active interfaces with this type whose names do not match known VPN patterns. This defeats a simple rename of `tun0` to a neutral name.

### Exact trigger condition

`iface.isUp && iface.ifaceType == 65534 && !isVpnInterface(iface.name)` sets `detected=true` with high confidence.

## What the result means

A neutral name paired with a TUN/TAP type is treated as a strong inconsistency. Simply renaming the interface is not enough to pass this check.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

A driver or OEM component may use an unusual ARP hardware type for a legitimate virtual interface. Compare `/sys/class/net/<iface>/type`, the interface’s purpose, and its active routes.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy. Renaming the interface without changing its type does not help. Without root, an app cannot change the kernel-reported type of another interface.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. The backend must hide the interface itself or substitute its type consistently; filtering only the name is insufficient.

### How to verify the result

```bash
adb shell 'for i in /sys/class/net/*; do printf "%s type=" "${i##*/}"; cat "$i/type" 2>/dev/null; done'
adb shell ip -details link show
```
Locate the interface from the detail and confirm the value `65534`.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Substituting the type in the kernel affects the networking stack and may break the VPN. Do not patch the sysfs file; it is a representation of kernel state, not a normal setting.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified directly from the `ARPHRD_TUNTAP` condition in `NativeSignsChecker`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NetworkInterfacePatterns.kt` — interface-name rules](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [netdevice(7)](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- External primary documentation or official project: [Android VpnService](https://developer.android.com/reference/android/net/VpnService).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `interface-enumeration`, `sysclassnet-vpn`, `sysfs-vpn-leak`.

[Back to the Native signs reference](../)
