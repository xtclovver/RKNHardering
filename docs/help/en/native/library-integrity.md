---
title: "Origin of key libc symbols"
permalink: /help/en/native/library-integrity/
---

# Origin of key libc symbols

> **ID:** `LIBRARY_INTEGRITY`
> **Category:** Hooks and process integrity
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

C++ calls `dlsym(RTLD_DEFAULT)` and `dladdr()` for `getifaddrs`, `if_nametoindex`, `socket`, `fopen`, `inet_ntop`, and `ioctl`. A symbol is considered suspicious if it is missing or its library name does not contain `libc.so`, `libc++`, or `libm.so`. Each such line produces a medium-confidence review finding.

### Exact trigger condition

A missing symbol, or resolution of its address to an unexpected library.

## What the result means

The signal detects some forms of PLT/ELF interposition and nonstandard libc wrappers. It does not prove a VPN, but it can explain why API results may have been altered.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

An inline hook inside the original `libc.so`, trampolines, and raw syscalls may not change the `dladdr` result. A vendor library or sanitizer in a debug build may be legitimate.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Use the official APK without repacking, sanitizers, or a third-party loader. If this is your debug build, repeat the test with a release build. Rootless virtualization or LSPatch must be removed completely from the process, not merely renamed.

### With root

Exclude RKNHardering from the Zygisk/Xposed scope. For VPN hiding, use an out-of-process `system_server`/kernel backend. Verify after a reboot, because force-stop does not unload a framework from zygote.

### How to verify the result

The built-in detail shows the symbol, address, and library. A native test harness can repeat the `dlsym`/`dladdr` calls; ordinary `ldd` output for an APK does not reproduce the runtime namespace. A useful developer command is:
```bash
rg -n 'nativeLibraryIntegrity|dlsym|dladdr' app/src/main/cpp/native_signs_probe.cpp
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Replacing the system libc or linker configuration can make the device unbootable. Do not attempt to “fix” addresses with a binary patch on a production phone.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Medium.** Verified against the exact list of six symbols and the library allowlist in `evaluateLibraryIntegrity()`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [dladdr(3)](https://man7.org/linux/man-pages/man3/dladdr.3.html).
- External primary documentation or official project: [dlsym(3)](https://man7.org/linux/man-pages/man3/dlsym.3.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `hook-markers`, `rwx-memory-regions`, `jvm-native-mismatch`.

[Back to the Native signs reference](../)
