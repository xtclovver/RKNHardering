---
title: "Reserved deep qdisc ID"
permalink: /help/en/native/deep-vpn-qdisc/
---

# Reserved deep qdisc ID

> **ID:** `DEEP_VPN_QDISC`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The `fromDeepVpnKind("vpn_qdisc")` catalog mapping routes the line to `DEEP_VPN_QDISC`, but the current `nativeDetectVpnDetector()` does not call the function that emits `vpn_qdisc`. The active producer exists only in the legacy `nativeDetectVpnAdvanced()` path and is documented on the `vpn-qdisc` page.

### Exact trigger condition

There is no separate trigger in the current deep pipeline. The ID will appear only if a future `nativeDetectVpnDetector()` starts returning the `vpn_qdisc` kind or the native bridge changes.

## What the result means

The page is normally reached from the catalog, but there is no runtime finding with this ID. Do not treat the absence of the deep ID as proof that qdisc state or counters are hidden.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

The name `qdisc` is also imprecise in the legacy producer: the current function reads RX/TX values from `/proc/net/dev` for tun0/wg0 rather than querying qdisc state through rtnetlink TC. Both articles note this distinction.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not change anything for an inactive ID. For the actual signal, see `vpn-qdisc` and `proc-net-dev-vpn`.

### With root

Do not install a kernel module merely for an empty registry line. If you add a real qdisc detector, first define the `RTM_GETQDISC`/TC semantics and a separate false-positive model.

### How to verify the result

```bash
rg -n 'detectQdisc|nativeDetectVpnDetector|nativeDetectVpnAdvanced|"vpn_qdisc"' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering
```
Confirm that the call is absent specifically from the consolidated deep function.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Attempting to hide traffic-control state globally can break shaping, QoS, and NetworkStack. There is nothing to fix here until a producer exists.

### Rollback

If you added the call experimentally, revert only the pipeline and test changes; no device changes are required.

## Evidence level

**Registry/compatibility.** Verified against the JNI function call list and catalog mapping; registry-only status.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Linux traffic control netlink](https://man7.org/linux/man-pages/man8/tc.8.html).
- External primary documentation or official project: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `vpn-qdisc`, `proc-net-dev-vpn`, `route-count`.

[Back to the Native signs reference](../)
