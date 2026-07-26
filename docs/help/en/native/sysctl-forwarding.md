---
title: "IPv4 Forwarding Enabled"
permalink: /help/en/native/sysctl-forwarding/
---

# IPv4 Forwarding Enabled

> **ID:** `SYSCTL_FORWARDING`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`/proc/sys/net/ipv4/ip_forward` is read as an integer. A nonzero value emits `sysctl_forwarding|ip_forward=1`; the legacy policy treats it as a medium-confidence review finding.

### Exact trigger condition

`ip_forward != 0`.

## What the result means

Forwarding is common in router, tethering, and root-VPN configurations, but Android may enable it for a hotspot or a system networking mode. It is not an independent VPN indicator.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The probe checks only the global IPv4 key, not IPv6 forwarding or per-interface behavior. The value may change when a hotspot is enabled.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Disable the hotspot or USB tethering and repeat the test. An ordinary app cannot change this sysctl. If forwarding is required by design, treat the review finding as an accurate description of the system.

### With root

Do not set `ip_forward=0` blindly; this breaks tethering and router/VPN forwarding. For testing, record the original value and make changes only on a separate device.

### How to verify the result

```bash
adb shell cat /proc/sys/net/ipv4/ip_forward 2>&1
adb shell dumpsys connectivity | grep -i tether -A3 -B2
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Disabling forwarding interrupts tethering and some root-based VPN designs.

### Rollback

Restore the saved value, or restart tethering or the device so Android reapplies its normal setting.

## Evidence level

**Medium.** Verified from `detectSysctl()`; medium kind.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [ip-sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `sysctl-rp-filter`, `route-table`.

[Back to the Native signs reference](../)
