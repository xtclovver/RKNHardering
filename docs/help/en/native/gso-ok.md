---
title: "UDP GSO was accepted and the loopback send succeeded"
permalink: /help/en/native/gso-ok/
---

# UDP GSO was accepted and the loopback send succeeded

> **ID:** `GSO_OK`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** A native producer exists, but the line is lost by the current UI parser
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`UDP_SEGMENT=1200` is accepted, after which `sendto()` successfully sends 4,800 bytes to loopback port 53. In the native result, the kind has no detail, so the parser can receive `gso_ok` only if the row is serialized with a separator. The current C++ code appends exactly `gso_ok` without `|`, while the deep `parseRow()` requires a kind and a nonempty detail after the second separator. With the prefix, the row becomes `vdet|gso_ok`, so the current Kotlin parser discards it.

### Exact trigger condition

At the C++ level, both setsockopt and sendto succeed. At the UI level in version 2.10.0, the producer does not reach a finding because the format lacks a detail field.

## What the result means

If the line is not displayed, that does not mean GSO failed; it reflects the current producer/parser format mismatch. After the format is fixed, the signal should remain informational.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

Apart from the parser gap, loopback GSO does not measure the VPN path and does not confirm hardware offload. Success itself is not an anti-detection result.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not change anything merely because the UI line is absent. For development, change the C++ output to `gso_ok|sent=4800`, or allow an empty detail in the parser and add a unit test.

### With root

Root is neither required nor appropriate. Do not patch the kernel merely to make a diagnostic line appear.

### How to verify the result

```bash
rg -n 'gso_ok|parseRow|indexOf' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt
```
After the fix, run the checker unit test and test on a real device that supports `UDP_SEGMENT`.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Changing the parser affects all malformed deep rows; add a test so that empty or damaged kinds are not accepted without validation.

### Rollback

Revert only the code change if tests or telemetry regress. There are no persistent changes on the device.

## Evidence level

**Registry/compatibility.** Verified against the C++ row without a separator/detail and Kotlin `parseRow()` with `sep <= 0` and blank-field rejection. The ID remains cataloged.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `gso-failed`, `gso-send-failed`, `general-diagnostics`.

[Back to the Native signs reference](../)
