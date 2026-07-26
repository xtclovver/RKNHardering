---
title: "Reserved `dns_prop` ID"
permalink: /help/en/native/dns-property/
---

# Reserved `dns_prop` ID

> **ID:** `DNS_PROPERTY`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`DNS_PROPERTY` and the legacy `dns_prop` mapping remain in the catalog and UI, but `native_signs_probe.cpp` in version 2.10.0 does not emit a `dns_prop` line. DNS-like keys such as `net.vpn.dns*` and `dhcp.tun0.dns*` currently fall under the shared `vpn_prop` kind and therefore the `vpn-property` page.

### Exact trigger condition

There is no separate positive producer. The checker still emits an informational “not found” line for this kind.

## What the result means

The page exists to preserve stable URLs and backward compatibility. It does not mean that DNS is not checked at all: server-side DNS checks and `vpn_prop` belong to other categories.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

A future version may restore a separate `dns_prop`; when the code changes, this page must be reviewed again.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

There is no need to bypass this ID in the current version. Address the real DNS signals instead: align the resolver with the expected route, eliminate leaks, and test HTTP, DNS, and UDP together.

### With root

Root is not needed for a producer that does not exist. Do not install a module merely to obtain a green `dns-property` line; the module may introduce root or hook indicators.

### How to verify the result

```bash
rg -n 'dns_prop|DNS_PROPERTY' app/src/main
rg -n 'net\.vpn\.dns|dhcp\.tun0\.dns' app/src/main/cpp/native_signs_probe.cpp
```
The first search shows the catalog/UI mapping; the second shows the actual `vpn_prop` producer.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

The main risk is mistaking a registry-only line for proof that no DNS leak exists.

### Rollback

No rollback is required; revert only DNS changes that degraded connectivity.

## Evidence level

**Registry/compatibility.** Verified by the absence of a literal `dns_prop` producer in C++ and the presence of its mapping in `NativeSignalCatalog`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Android DNS/VPN Builder](https://developer.android.com/reference/android/net/VpnService.Builder).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `vpn-property`, `general-diagnostics`.

[Back to the Native signs reference](../)
