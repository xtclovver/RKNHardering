---
title: "System properties LSPosed/Magisk/Zygote hook"
permalink: /help/en/native/hook-property/
---

# System properties LSPosed/Magisk/Zygote hook

> **ID:** `HOOK_PROPERTY`
> **Category:** Hooks and process integrity
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectVpnFiles()` reads `persist.sys.lspd.hook`, `ro.magisk.version`, and `init.svc.zygote_restart`; any nonempty value emits `hook_prop`. The legacy policy classifies this kind as high confidence and sets `detected=true`.

### Exact trigger condition

One of the three hook-related properties is nonempty.

## What the result means

This is a high-confidence legacy indicator of a modified runtime or root framework. The property name matters more than its value.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The list is short and version-specific. An OEM could theoretically use `init.svc.zygote_restart`, while modern frameworks may not expose these keys.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, the best option is a clean APK from a trusted source, with no repacking, LSPatch, Frida Gadget, virtualization, or rootless Xposed. Moving the app into a “second space” does not automatically clean its process: the container may inject its own libraries and leave even more discrepancies.

### With root

On a rooted device, do not include the target app in the Xposed/Vector scope or load a Zygisk module into it unless necessary. For VPN hiding, prefer a design in which Java filtering runs in `system_server` and native filtering runs in the kernel. DenyList/App Profile, NoHello, Zygisk Next, SUSFS, and similar tools may reduce some traces, but none guarantees protection against maps, linker, mount, and raw-syscall checks at the same time. If an old module creates the property, update or remove it. Broad `resetprop` rules are not a substitute for excluding the target from injection.

### How to verify the result

```bash
adb shell getprop persist.sys.lspd.hook
adb shell getprop ro.magisk.version
adb shell getprop init.svc.zygote_restart
```
A nonempty string satisfies the trigger condition.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Spoofing zygote service properties may disrupt app startup and complicate crash diagnostics.

### Rollback

Remove the specific `resetprop` rules or legacy module and reboot.

## Evidence level

**High.** Verified against `hookPropNames`; the kind is included in the legacy high-confidence set.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Magisk](https://github.com/topjohnwu/Magisk).
- External primary documentation or official project: [Vector](https://github.com/JingMatrix/Vector).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `lsposed`, `hook-markers`, `root-magisk-property`.

[Back to the Native signs reference](../)
