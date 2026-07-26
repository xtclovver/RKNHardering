---
title: "IPsec/XFRM interfaces"
permalink: /help/en/native/ipsec-interface/
---

# IPsec/XFRM interfaces

> **ID:** `IPSEC_INTERFACE`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

Active interfaces are matched against the regular expression `^(ipsec|xfrm).*`. Unlike TUN patterns, the line is informational: Android, OEM VPNs, and system IPsec components may legitimately create such interfaces.

### Exact trigger condition

Any active interface named `ipsec*` or `xfrm*` creates an informational line containing its name and index.

## What the result means

The signal alone does not mark the category as detected and does not require a bypass. It becomes useful only when combined with routes, XFRM or beta data, an external IP, or an active VPN transport.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

IPsec can use policy/XFRM state without a separate interface, and an OEM may choose a different name. Conversely, an enterprise profile may legitimately create an XFRM interface.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If IPsec is genuinely unnecessary, disable the corresponding enterprise VPN or always-on profile through normal system controls. If it is needed, do not rename the interface merely because of an informational line. An external gateway removes IPsec state from the phone.

### With root

Kernel filtering is viable only as part of consistent hiding across interfaces, routes, and XFRM state. Do not delete XFRM state with `ip xfrm state flush`; doing so breaks the connection and may violate enterprise policy. Use a separate device for testing.

### How to verify the result

```bash
adb shell ip -details link show | grep -Ei 'ipsec|xfrm'
adb shell ip xfrm state 2>&1 | head -80
adb shell ip xfrm policy 2>&1 | head -80
```
Some XFRM data may be inaccessible from an ordinary shell; that does not mean it is absent.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Disabling an always-on or lockdown VPN may remove mandatory traffic protection. Changing XFRM state requires privileges and immediately breaks the session.

### Rollback

Restore the enterprise profile or VPN configuration, then restart networking. If a root module was used, disable it and reboot.

## Evidence level

**Low.** Verified against `NetworkInterfacePatterns.IPSEC_INTERFACE_PATTERN` and the informational branch in `evaluateInterfaces()`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NetworkInterfacePatterns.kt` — interface-name rules](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Linux XFRM device documentation](https://docs.kernel.org/networking/xfrm_device.html).
- External primary documentation or official project: [Android VPN guide](https://developer.android.com/develop/connectivity/vpn).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `interface-enumeration`, `vpn-policy-rules-netlink`, `route-table`.

[Back to the Native signs reference](../)
