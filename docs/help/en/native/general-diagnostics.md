---
title: "The deep native detector returned no lines"
permalink: /help/en/native/general-diagnostics/
---

# The deep native detector returned no lines

> **ID:** `GENERAL_DIAGNOSTICS`
> **Category:** Service signals
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Service

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`VpnNativeDetectorChecker` adds `GENERAL_DIAGNOSTICS` only when `findings` is empty after parsing. This may mean that all producer functions were silent, the scan was cancelled before output was produced, or the parser discarded the lines. A different ID is used when the native library is unavailable.

### Exact trigger condition

`findings.isEmpty()` after `detectVpnDetector()` and `parseRow()`.

## What the result means

The “no anomalies found” message applies only to the deep category and only to successfully parsed rows. It does not guarantee that no VPN is present, and it does not override legacy, Java, server-side, or beta checks.

**How the line affects the report:** This is an umbrella or fallback ID. It links a group of lines to the documentation, but does not always have its own positive producer.

## Limitations and possible false positives

Some probes are intentionally silent when clean, but `route_count`, `normal_pmtu`, timing, and UDP PMTU normally produce telemetry. A completely empty result may therefore also indicate cancellation, parser behavior, or ABI-specific issues. `gso_ok` is currently discarded because it has no detail field, but other rows normally remain.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Confirm that the scan completed, the native library loaded, and the category was not cancelled. Review the log and repeat the scan on a stable network.

### With root

Temporarily exclude RKNHardering from all modules and scopes, then repeat the test. Do not treat empty output as an anti-detection objective: disrupted diagnostics are visible and reduce confidence in the report.

### How to verify the result

```bash
adb logcat -c
adb shell am force-stop com.notcvnt.rknhardering
# Run a full scan, then:
adb logcat -d | grep -Ei 'RKNHardering|native|vpn detector|cancel|JNI' | tail -200
```
Also check the neighboring `native-library` result.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Forcibly disrupting JNI or the scan can hide real errors and is not a valid way to pass the check.

### Rollback

Restore the official APK, disable the interfering module, and reboot. Repeat the complete baseline scan.

## Evidence level

**Service.** Verified against the `findings.isEmpty()` branch and parser behavior.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignsBridge.kt` — JNI loading and native bridge](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/probe/NativeSignsBridge.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android JNI guidance](https://developer.android.com/training/articles/perf-jni).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `native-library`, `unknown-signals`, `route-count`.

[Back to the Native signs reference](../)
