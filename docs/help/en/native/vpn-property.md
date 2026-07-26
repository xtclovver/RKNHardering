---
title: "Legacy VPN/DNS System Properties"
permalink: /help/en/native/vpn-property/
---

# Legacy VPN/DNS System Properties

> **ID:** `VPN_PROPERTY`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectVpnPropertiesAll()` reads `net.vpn.dns1..4`, `dhcp.tun0.dns1/2`, `net.interfaces.default.type`, and `net.interfaces.default.name`. Any nonempty value produces `vpn_prop`. In addition, `net.interfaces.default.type` is checked again for the substrings `tun` or `vpn`. Under the legacy policy, this kind has high confidence and sets `detected=true`.

### Exact trigger condition

A fixed VPN property is nonempty, or `default.type` contains `tun` or `vpn`.

## What the result means

This is a strong legacy indicator when the firmware actually exports these properties. On newer Android versions, these names are often absent even while a VPN is active.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The property list is not part of a stable Android API. An OEM may leave a stale value after the VPN is disabled or may not use these keys at all.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Stop the VPN client completely and restart networking, then check whether the property disappears. If the firmware sets it, an ordinary app cannot change it. An external gateway may not clear a stale property until reboot, but it does not create a new `VpnService`.

### With root

`resetprop` can hide a legacy key, but that covers only one surface. Do not substitute a DNS value without keeping it consistent with the actual resolver path. Prefer removing the source of the property or using a system filter that does not alter global networking.

### How to verify the result

```bash
for p in net.vpn.dns1 net.vpn.dns2 net.vpn.dns3 net.vpn.dns4 dhcp.tun0.dns1 dhcp.tun0.dns2 net.interfaces.default.type net.interfaces.default.name; do
  printf '%s=' "$p"; adb shell getprop "$p"
done
```
Repeat the check after disabling the VPN and rebooting.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Globally substituting DNS or property values may cause DNS leaks or loss of name resolution. Do not clear all `net.*` properties with a script.

### Rollback

Remove the targeted `resetprop` rule and reboot; restore the original VPN and DNS configuration.

## Evidence level

**High.** Verified from the exact property list; `vpn_prop` is included in the legacy high-confidence kinds.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Android system properties](https://source.android.com/docs/core/architecture/configuration/sysprops-apis).
- External primary documentation or official project: [VpnService.Builder DNS](https://developer.android.com/reference/android/net/VpnService.Builder).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `dns-property`, `hook-property`, `interface-enumeration`.

[Back to the Native signs reference](../)
