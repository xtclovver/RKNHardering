---
title: "File artifacts of an LSPosed/Vector-like stack"
permalink: /help/en/native/lsposed/
---

# File artifacts of an LSPosed/Vector-like stack

> **ID:** `LSPOSED`
> **Category:** Hooks and process integrity
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The legacy file probe checks `/data/adb/lspd`, `/data/adb/modules/lsposed`, `/data/misc/lspd`, and `/data/data/org.lsposed.manager`. An accessible path emits `lsposed`; the legacy policy treats it as a medium-confidence review finding rather than direct detection.

### Exact trigger condition

One of the four fixed paths exists and is visible to the app.

## What the result means

This is an artifact of a framework or an old installation. Modern Vector versions may use different names, and a path may remain after uninstalling the framework.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The check is path-based and does not prove that RKNHardering is in scope. Conversely, a framework may operate without a visible fixed path but still appear in maps or library-integrity checks.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, the best option is a clean APK from a trusted source, with no repacking, LSPatch, Frida Gadget, virtualization, or rootless Xposed. Moving the app into a “second space” does not automatically clean its process: the container may inject its own libraries and leave even more discrepancies. Remove the rootless or repacked framework through its normal uninstall flow and install a clean APK.

### With root

On a rooted device, do not include the target app in the Xposed/Vector scope or load a Zygisk module into it unless necessary. For VPN hiding, prefer a design in which Java filtering runs in `system_server` and native filtering runs in the kernel. DenyList/App Profile, NoHello, Zygisk Next, SUSFS, and similar tools may reduce some traces, but none guarantees protection against maps, linker, mount, and raw-syscall checks at the same time. For VPNHide, the scope should include only `System Framework`, not RKNHardering. Download the current framework from [Vector releases](https://github.com/JingMatrix/Vector/releases/latest); the original LSPosed repository remains an archival source.

### How to verify the result

```bash
adb shell 'for p in /data/adb/lspd /data/adb/modules/lsposed /data/misc/lspd /data/data/org.lsposed.manager; do [ -e "$p" ] && echo "$p"; done'
```
Also check `hook-markers` and `library-integrity`.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Removing the framework without disabling its modules can leave the system in a partially configured state. Scoping the target app creates in-process traces.

### Rollback

Disable the module, reboot, then remove the framework through its normal manager. If the device enters a boot loop, use the root manager’s safe mode.

## Evidence level

**Medium.** Verified against the four paths and the legacy medium-confidence policy.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Vector releases](https://github.com/JingMatrix/Vector/releases/latest).
- External primary documentation or official project: [Archived LSPosed](https://github.com/LSPosed/LSPosed).
- External primary documentation or official project: [VPNHide framework setup](https://github.com/okhsunrog/vpnhide).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `hook-markers`, `hook-property`, `library-integrity`, `vpnhide`.

[Back to the Native signs reference](../)
