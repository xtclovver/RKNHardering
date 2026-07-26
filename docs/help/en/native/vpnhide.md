---
title: "VPNHide Artifacts and Regression Oracles"
permalink: /help/en/native/vpnhide/
---

# VPNHide Artifacts and Regression Oracles

> **ID:** `VPNHIDE`
> **Category:** Hooks and process integrity
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Mixed

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

One ID combines two different sources. The legacy `detectVpnFiles()` checks `/data/local/tmp/vpnhide`, `/data/data/com.vpnhide`, `/data/local/tmp/.vpnhide`, and `/data/data/com.vpn.hide`; a matching path produces a high-confidence `vpnhide` finding. The deep detector also routes the results of two regression probes here: SIOCGIFINDEX/SIOCGIFNAME consistency and the SIOCGIFCONF tail. Oracle and tail-vpn results are high confidence, tail-oracle is medium, clean is informational, and unavailable is an error.

### Exact trigger condition

High confidence: an accessible legacy path, a stable interface index without a reverse name, or a VPN-like name in the tail of the SIOCGIFCONF buffer. Medium confidence: a plausible stale non-VPN tail. Clean and unavailable results are not detections.

## What the result means

The signal may indicate either a direct file artifact or incomplete interface filtering. The title alone does not identify the cause; inspect the detail and check ID.

**How the line affects the report:** The same ID is used for both informational summaries and suspicious lines. The outcome depends on the specific detail and checker branch.

## Limitations and possible false positives

The legacy path names do not match the current paths used by every VPNHide version. Regression oracles test specific implementation errors and may miss a different bypass.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

VPNHide is not normally installed without root, so the path should be absent. If an oracle signal appears without VPNHide, another filter or a ROM bug may be responsible; repeat the test against a clean baseline. To keep the VPN itself off a non-rooted phone, use an external gateway.

### With root

Install only from the [official VPNHide release](https://github.com/okhsunrog/vpnhide/releases/latest). Configure `System Framework` and exactly one native backend. After every update, run both regression check IDs: the absence of `tun0` is insufficient if an index or stale tail remains. Do not combine kmod and KPM.

### How to verify the result

```bash
# Read-only check of accessible paths:
adb shell 'for p in /data/local/tmp/vpnhide /data/data/com.vpnhide /data/local/tmp/.vpnhide /data/data/com.vpn.hide; do [ -e "$p" ] && echo "$p"; done'
# Regression probe source:
rg -n 'vpnhide_ifindex|vpnhide_ifconf' app/src/main/cpp/vpnhide_regression_probe.cpp
```
In the UI, distinguish check IDs `native.vpnhide.ifindex_consistency` and `native.vpnhide.ifconf_tail`.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

A kernel backend may cause a boot loop or panic; running multiple backends at once is especially dangerous. Deleting package data erases settings.

### Rollback

Before installation, save the boot/init_boot image and the module list. If a boot loop occurs, disable the most recent module through the manager’s safe mode or restore a known-good image.

## Evidence level

**Mixed.** Verified from the legacy path list, the C++ regression probe, and the `VpnNativeDetectorChecker` confidence policy.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`vpnhide_regression_probe.cpp` — consistency and oracle probes](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [VPNHide](https://github.com/okhsunrog/vpnhide).
- External primary documentation or official project: [VPNHide releases](https://github.com/okhsunrog/vpnhide/releases/latest).
- External primary documentation or official project: [VPNHide detection vectors](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- External primary documentation or official project: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `ifindexname-vpn`, `trim-oracle`, `jvm-native-mismatch`, `lsposed`.

[Back to the Native signs reference](../)
