---
title: "SELinux Permissive Mode or an Inaccessible Enforce File"
permalink: /help/en/native/root-selinux/
---

# SELinux Permissive Mode or an Inaccessible Enforce File

> **ID:** `ROOT_SELINUX`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

C++ reads `/sys/fs/selinux/enforce`. A value of `0` emits `selinux|permissive` with high confidence. If the file cannot be opened at all, it emits `selinux|absent`; Kotlin treats this as a low-confidence review finding.

### Exact trigger condition

Either `enforce=0` or an inability to open the enforce file.

## What the result means

Permissive mode is a major security modification. `absent` is ambiguous: the path may be hidden by SELinux or a namespace, missing inside a container, or inaccessible to an ordinary app.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The check does not analyze the policy as a whole. Enforcing mode does not imply a stock policy; a root module may add permissions. A missing file is not equivalent to permissive mode.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not install firmware that starts SELinux in permissive mode when a clean baseline is required. Keep SELinux enforcing on a production ROM. If the file is absent only for the app, evaluate neighboring signals instead of weakening the policy.

### With root

Never switch SELinux to permissive mode for VPNHide or another module. Address a specific AVC denial with the narrowest possible rule, or stop using the incompatible module. Substituting the visible `enforce` value without actual enforcement creates a false sense of security.

### How to verify the result

```bash
adb shell getenforce
adb shell cat /sys/fs/selinux/enforce 2>/dev/null
adb logcat -d | grep 'avc: denied' | tail -50
```
The shell’s `getenforce` result and a read by the app UID may differ in accessibility, not in the kernel’s actual mode.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Permissive mode disables SELinux enforcement and increases the impact of a compromise. An incorrect sepolicy may cause a boot loop.

### Rollback

Restore enforcing mode and remove the most recent broad sepolicy rule. If the device no longer boots, restore the boot image or disable the module through safe mode.

## Evidence level

**Medium.** Verified from the two `nativeDetectRoot()` branches; confidence differs between permissive and absent results.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-property`, `root-system-rw`, `syscall-unavailable`.

[Back to the Native signs reference](../)
