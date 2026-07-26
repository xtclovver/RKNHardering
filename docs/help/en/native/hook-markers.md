---
title: "Named injection markers in `/proc/self/maps`"
permalink: /help/en/native/hook-markers/
---

# Named injection markers in `/proc/self/maps`

> **ID:** `HOOK_MARKERS`
> **Category:** Hooks and process integrity
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The native function reads `/proc/self/maps` for the current process and searches for `frida-agent`, `frida-gadget`, `libfrida`, `libsubstrate`, `com.saurik.substrate`, `XposedBridge`, `libxposed`, `lspatch`, `LSPosed`, `libriru`, and `libzygisk`. For a match, it records the marker and the complete map line. Kotlin treats known markers as high confidence, but sets `needsReview` rather than marking the category directly as detected.

### Exact trigger condition

Any maps line containing one of the fixed markers creates a review finding; known markers receive high confidence.

## What the result means

The check shows that a library or mapping with a recognizable name is loaded into the process. This is strong evidence of instrumentation, but not necessarily malicious instrumentation; a test build, accessibility or monitoring SDK, or a user-installed module may also be responsible.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

Renaming a file bypasses the string list but not other integrity checks. Anonymous or memfd mappings may have no marker. Conversely, a harmless path containing one of these words could theoretically match.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, the best option is a clean APK from a trusted source, with no repacking, LSPatch, Frida Gadget, virtualization, or rootless Xposed. Moving the app into a “second space” does not automatically clean its process: the container may inject its own libraries and leave even more discrepancies.

### With root

On a rooted device, do not include the target app in the Xposed/Vector scope or load a Zygisk module into it unless necessary. For VPN hiding, prefer a design in which Java filtering runs in `system_server` and native filtering runs in the kernel. DenyList/App Profile, NoHello, Zygisk Next, SUSFS, and similar tools may reduce some traces, but none guarantees protection against maps, linker, mount, and raw-syscall checks at the same time.

### How to verify the result

For your own debuggable build, you can capture maps with `run-as`:
```bash
adb shell run-as com.notcvnt.rknhardering cat /proc/self/maps 2>/dev/null | grep -Ei 'frida|xposed|lsposed|zygisk|riru|substrate|lspatch'
```
For a release build, `run-as` is normally unavailable. Use the check’s own detail and compare it with the list of loaded modules.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

`/proc/self/maps` output contains paths and process-layout information; do not publish it in full without redaction. Disabling modules may affect other applications.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Medium.** Verified against the fixed `kSuspiciousMarkers` array and `evaluateHookMarkers()`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/pid/maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html).
- External primary documentation or official project: [Vector](https://github.com/JingMatrix/Vector).
- External primary documentation or official project: [Magisk/Zygisk](https://github.com/topjohnwu/Magisk).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `rwx-memory-regions`, `library-integrity`, `lsposed`, `hook-property`.

[Back to the Native signs reference](../)
