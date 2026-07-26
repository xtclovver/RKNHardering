---
title: "Large RWX Memory Regions"
permalink: /help/en/native/rwx-memory-regions/
---

# Large RWX Memory Regions

> **ID:** `RWX_MEMORY_REGIONS`
> **Category:** Hooks and process integrity
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

While reading `/proc/self/maps`, the C++ code counts mappings with `rwx` permissions and a size of at least 256 KiB. If at least one exists, it reports the `rwx_large` count; Kotlin displays it as low-confidence informational data.

### Exact trigger condition

One or more regions of at least 256 KiB are simultaneously writable and executable.

## What the result means

This may indicate JIT compilation, runtime patching, or instrumentation, but it is not proof. In the current version, the line does not create a review finding or change `detected`.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

ART/JIT, games, WebView, emulators, and legitimate engines may use RWX or transitional mappings. The check does not record their lifetime or hash their contents.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, the best option is a clean APK from a trusted source, with no repacking, LSPatch, Frida Gadget, virtualization, or rootless Xposed. Moving the app into a “second space” does not automatically clean its process: the container may inject its own libraries and leave even more discrepancies. If the signal appears with a clean APK, repeat the test after a cold start and without opening WebView or a resource-intensive screen; it may be normal JIT activity.

### With root

With root access, do not include the target app in the Xposed/Vector scope or load a Zygisk module into it unnecessarily. For VPN hiding, prefer an arrangement in which Java filtering occurs in `system_server` and native filtering occurs in the kernel. DenyList/App Profile, NoHello, Zygisk Next, SUSFS, and similar tools may reduce some traces, but none guarantees simultaneous protection against `maps`, linker, mount, and raw-syscall checks. Do not disable JIT through system properties merely to remove one line; this reduces performance and does not eliminate other hook indicators.

### How to verify the result

```bash
# Only for a debuggable build:
adb shell run-as com.notcvnt.rknhardering cat /proc/self/maps | grep -E '^[0-9a-f]+-[0-9a-f]+ rwx'
```
Compare the address range and size. On a release build, rely on the built-in line.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Attempting to change memory protections through a third-party module may cause crashes and violate W^X. Do not publish a complete maps listing without redacting it.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Low.** Verified from the 256 KiB threshold in `nativeReadSelfMapsSummary()`; the checker deliberately treats the line as informational.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `hook-markers`, `library-integrity`.

[Back to the Native signs reference](../)
