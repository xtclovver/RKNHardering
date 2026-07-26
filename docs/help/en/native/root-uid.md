---
title: "Process UID/EUID/GID Equals 0"
permalink: /help/en/native/root-uid/
---

# Process UID/EUID/GID Equals 0

> **ID:** `ROOT_UID`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe calls `getuid()`, `geteuid()`, and `getgid()`. If any value is zero, the detail contains all three numbers; the checker assigns a high-confidence review finding.

### Exact trigger condition

RKNHardering is actually running with UID, EUID, or GID 0.

## What the result means

For an ordinary Android app, this is an extremely strong anomaly. The most common causes are execution under root or in a container, a modified launcher, or a test harness.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

Ordinary device root does not make every app run as UID 0, so the absence of this signal says nothing about Magisk or KernelSU. Privileged supplemental groups other than GID 0 are not analyzed here.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Install the APK through the normal PackageManager and launch it from the standard launcher. Do not use `su -c am start` or a root wrapper. Reinstalling it for the owner user normally restores a regular app UID.

### With root

Do not grant root to the app, and verify that no module changes its process credentials. Root hiding is not the remedy here: the correct state is an ordinary app UID even when a root manager is installed.

### How to verify the result

```bash
adb shell pidof com.notcvnt.rknhardering
adb shell ps -A -o USER,UID,GID,PID,NAME | grep rknhardering
```
The `ps` format differs on some Android versions; the app’s detail remains the source of truth.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Running a GUI app as UID 0 gives it full access to data and greatly increases the impact of any bug.

### Rollback

Stop the root wrapper, remove its autostart entry, and reinstall the APK normally.

## Evidence level

**Medium.** Verified from the direct `uid/euid/gid == 0` condition.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android application sandbox](https://source.android.com/docs/security/app-sandbox).
- External primary documentation or official project: [credentials(7)](https://man7.org/linux/man-pages/man7/credentials.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-su-binary`, `root-management`.

[Back to the Native signs reference](../)
