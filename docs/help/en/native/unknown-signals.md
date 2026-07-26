---
title: "Unknown or Unmapped Native Kind"
permalink: /help/en/native/unknown-signals/
---

# Unknown or Unmapped Native Kind

> **ID:** `UNKNOWN`
> **Category:** Service signals
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Service

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`NativeSignalCatalog.info(null)` and unknown IDs use `UNKNOWN`. In the legacy and deep mappers, an unknown kind normally resolves to `null`, after which a finding may receive a fallback article or may not pass a particular parser at all. This page exists for forward compatibility rather than for one C++ probe.

### Exact trigger condition

The UI or link receives a null/unknown `NativeSignalId`, or a new native row has not yet been added to the catalog mapping.

## What the result means

This is a version-alignment defect among the producer, parser, enum, and documentation. Confidence or mitigation cannot be assigned from one unknown row; the raw kind/detail and commit/version are required first.

**How the line affects the report:** This is an umbrella or fallback ID. It links a group of lines to the documentation, but does not always have its own positive producer.

## Limitations and possible false positives

A release APK may not display the complete raw row. When APK and documentation versions are mixed, slugs and titles may diverge. An unknown result must not automatically be treated as either clean or detected.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Save the exported report, APK version, ABI, and exact detail. Reinstall the official release without repacking and repeat the test. Attach only the minimum necessary log to an issue, with personal data removed.

### With root

Repeat the test without modules that alter JNI or strings. When adding a custom native probe, update `NativeSignalId`, `NativeSignalCatalog`, the mapper, UI strings, the Russian article, and unit tests together.

### How to verify the result

```bash
rg -n 'NativeSignalId|fromLegacyVpnKind|fromDeepVpnKind|UNKNOWN' app/src/main/java/com/notcvnt/rknhardering
./gradlew testDebugUnitTest --tests com.notcvnt.rknhardering.NativeSignalCatalogTest
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

A published raw log may contain interface names, IP addresses, paths, and package names. Remove secrets and personal data before filing an issue.

### Rollback

Revert the incompatible producer/catalog change, or install matching versions of the APK and documentation.

## Evidence level

**Structural.** Verified from the catalog fallback and mapping tables. This is a service-level signal.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- External primary documentation or official project: [Project issues](https://github.com/xtclovver/RKNHardering/issues).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `native-library`, `general-diagnostics`, `syscall-unavailable`.

[Back to the Native signs reference](../)
