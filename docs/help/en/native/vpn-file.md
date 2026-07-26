---
title: "Reserved General ID for VPN Files"
permalink: /help/en/native/vpn-file/
---

# Reserved General ID for VPN Files

> **ID:** `VPN_FILE`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The catalog contains the legacy `vpn_file` kind, but the current `detectVpnFiles()` does not emit it. It separates paths by the prefixes `vpnhide`, `lsposed`, and `zygisk`. The first two receive dedicated IDs; `zygisk` is not in the legacy allowlist and is displayed through `UNKNOWN`.

### Exact trigger condition

There is no dedicated `vpn_file` producer in version 2.10.0; this ID normally appears only as an informational “not found” row.

## What the result means

This is a compatibility URL, not an active file check. The actual path checks are documented under `vpnhide`, `lsposed`, and `unknown-signals`.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

The name can be misleading: the app does check specific files, but it does not assign them this general ID.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not change the filesystem for this row. Remove only an actually unnecessary VPN or root framework through its normal uninstall procedure rather than masking a catalog-only ID.

### With root

Root-level masking of the general `vpn_file` ID is pointless. When a specific path is visible, address its producer and inspect mounts and properties at the same time.

### How to verify the result

```bash
rg -n 'vpn_file|detectVpnFiles|findings.emplace_back' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Manually deleting `/data/adb` or package data may damage the root manager and its modules.

### Rollback

Use the tool’s normal reinstall procedure. Do not restore directories by copying them without correct SELinux labels.

## Evidence level

**Registry/compatibility.** Verified from the mapping and the actual C++ prefix strings.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Android app data sandbox](https://source.android.com/docs/security/app-sandbox).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `vpnhide`, `lsposed`, `unknown-signals`.

[Back to the Native signs reference](../)
