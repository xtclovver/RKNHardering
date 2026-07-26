---
title: "Mismatch between Java `NetworkInterface` and native `getifaddrs`"
permalink: /help/en/native/jvm-native-mismatch/
---

# Mismatch between Java `NetworkInterface` and native `getifaddrs`

> **ID:** `JVM_NATIVE_MISMATCH`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Mixed

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The checker builds two independent snapshots: C/C++ `getifaddrs()` and Java `NetworkInterface.getNetworkInterfaces()`. It compares the sets of names, the index of the same interface, and address sets. A VPN-like name present in only one layer is high confidence; ordinary index or address differences produce a medium-confidence review finding.

### Exact trigger condition

High: a VPN-like interface is visible only to native code or only to the JVM. Medium: any other missing interface, different ifindex, or nonempty mismatched address sets.

## What the result means

This signal more often indicates incomplete hiding or a hook applied to only one API than the VPN itself. That is why Java-only hooks without native coverage, or libc-only hooks without framework coverage, create an oracle.

**How the line affects the report:** The same ID is used for both informational summaries and suspicious lines. The outcome depends on the specific detail and checker branch.

## Limitations and possible false positives

The snapshots are taken sequentially, so a genuine race is possible during handover, Wi-Fi/cellular switching, CLAT changes, or a brief IPv6 address change. Repeat the test on a stable network.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Stabilize the network and prevent switching between Wi-Fi and mobile data during the test. If the VPN remains local, ordinary non-root software cannot make two system APIs consistently hide another app’s interface; an external gateway removes the underlying cause.

### With root

Both layers are required: framework filtering in `system_server` and native/kernel filtering. Do not include RKNHardering itself in the Xposed scope; that may clean the Java list while adding process hooks. After a change, verify names, indices, and addresses, not merely the absence of `tun0`.

### How to verify the result

```bash
adb shell ip -o address show
adb shell ip -o link show
```
For an exact comparison, use the built-in RKNHardering detail or a custom test APK that calls both `NetworkInterface` and JNI `getifaddrs()` in one process. Shell commands do not fully reproduce the app namespace.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Partial spoofing is more conspicuous than no spoofing because it creates an observable contradiction. Inconsistent kernel hooks can break networking libraries and cause enumeration to hang.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Mixed.** Verified against `evaluateJvmNativeMismatch()`; missing-VPN-interface branches are high confidence, while index/address mismatches are medium confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NetworkInterfacePatterns.kt` — interface-name rules](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Java NetworkInterface](https://developer.android.com/reference/java/net/NetworkInterface).
- External primary documentation or official project: [getifaddrs(3)](https://man7.org/linux/man-pages/man3/getifaddrs.3.html).
- External primary documentation or official project: [VPNHide architecture](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `interface-enumeration`, `getifaddrs-vpn`, `library-integrity`, `trim-oracle`.

[Back to the Native signs reference](../)
