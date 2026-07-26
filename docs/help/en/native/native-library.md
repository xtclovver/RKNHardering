---
title: "Loading the native checks library"
permalink: /help/en/native/native-library/
---

# Loading the native checks library

> **ID:** `NATIVE_LIBRARY`
> **Category:** Service signals
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Availability

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

Before any JNI probes run, `NativeSignsBridge` loads the native library. If `System.loadLibrary` fails, both `NativeSignsChecker` and the deep VPN detector return a line with ID `NATIVE_LIBRARY`, including the exception text when available. Interface, route, root, and hook probes are not considered completed after this failure.

### Exact trigger condition

The trigger is a `.so` loading failure, incompatible ABI, missing library, linker or namespace error, or JNI exception. A successful load does not produce a separate positive line.

## What the result means

This is neither a clean-device indicator nor a VPN indicator. It means that a substantial part of the native coverage is unavailable, so the overall result must be treated as incomplete.

**How the line affects the report:** The signal means that the probe could not be performed. `unavailable` must not be interpreted as proof that no VPN is present.

## Limitations and possible false positives

Possible causes include a damaged APK, a split APK missing the required ABI, an incompatible 32/64-bit process, packer interference, a build error, or an environment restriction. This failure is especially likely after repacking.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Reinstall the official APK of the same version; do not extract and re-sign it. Confirm that the device supports the build’s ABI and that installation completed without a split conflict. For development, build the APK with the standard Gradle task and inspect the `lib/*` entries inside it.

### With root

First disable modules that alter the linker namespace, Zygote, or library loading for RKNHardering. Do not attempt to hide a VPN by deliberately breaking JNI: the app explicitly reports that the check is unavailable rather than treating it as clean.

### How to verify the result

```bash
adb shell pm path com.notcvnt.rknhardering
adb shell dumpsys package com.notcvnt.rknhardering | grep -E 'primaryCpuAbi|secondaryCpuAbi'
adb logcat -c
adb shell am force-stop com.notcvnt.rknhardering
# Then open the app and look for UnsatisfiedLinkError/dlopen in logcat:
adb logcat | grep -Ei 'rknhardering|UnsatisfiedLinkError|dlopen|linker'
```
For a local build, also run `unzip -l app-release.apk | grep '/lib/'`.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Reinstallation may remove local app data if `adb install -r` is used with an incompatible signature or if the app is uninstalled first. Save exported reports and settings.

### Rollback

Restore the APK with its original signature and revert only changes that affected loading. If the problem appeared after installing a root module, disable that specific module and reboot.

## Evidence level

**Availability.** Verified against the `libraryUnavailableResult()` branches in both Kotlin checkers and the JNI method registration. The signal describes check coverage, not network state.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsBridge.kt` — JNI loading and native bridge](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/probe/NativeSignsBridge.kt).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android ABI management](https://developer.android.com/ndk/guides/abis).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `general-diagnostics`, `syscall-unavailable`, `library-integrity`.

[Back to the Native signs reference](../)
