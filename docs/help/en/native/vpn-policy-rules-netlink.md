---
title: "Suspicious Policy Rules via RTM_GETRULE"
permalink: /help/en/native/vpn-policy-rules-netlink/
---

# Suspicious Policy Rules via RTM_GETRULE

> **ID:** `VPN_POLICY_RULES_NETLINK`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe requests an IPv4 `RTM_GETRULE` dump and parses `RTM_NEWRULE`. The table is taken from `rtm_table` or `RTA_TABLE`, the output interface from `RTA_OIF`, and a provisional mark from `RTA_FLOW`. Tables 100 through 200 are considered; a rule is treated as VPN-like when the interface equals one of the fixed tunnel names or the table number is between 100 and 110.

### Exact trigger condition

At least one rule uses table 100 through 110 regardless of interface, or table 100 through 200 with OIF `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, or `xfrm0`.

## What the result means

The routing policy database contains a rule that the heuristic associates with a VPN. The checker treats the row as high confidence.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The table ranges are heuristic and may overlap with OEM, enterprise, tethering, or custom-routing configurations. `RTA_FLOW` is labeled as an fwmark here even though Linux policy rules normally use `FRA_FWMARK`; the detail may therefore be incomplete. Only `AF_INET` is checked, not IPv6.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, address the routing design rather than the way the table is displayed. Use an external gateway for a clean phone. If the VPN remains in `VpnService`, configure split routing so that the app under test actually exits through the expected physical network, but do not treat this as hiding local routes: the interface and policy rules may remain visible. Do not delete routes with `ip route` on a live device—Android and the VPN service will recreate them, and connectivity may be interrupted. If your VPN client creates the rule, disabling TUN/VpnService mode removes it. Per-app exclusion does not necessarily remove shared rules.

### With root

On a rooted device, the backend must filter the data source rather than libc alone. In upstream VPNHide, the kernel backends are intended for `ioctl`, netlink, and some route/procfs vectors; Zygisk remains a conditional fallback. Do not install kmod and KPM together, because they may intercept the same kernel functions. VPNHide Next claims broader PMTU/MSS/qdisc/BPF coverage, but this is an external claim that must be reproduced on the specific kernel. Upstream VPNHide kernel backends claim `RTM_GETRULE` filtering. After installation, compare the target UID with a shell snapshot because rule filtering must be UID-specific.

### How to verify the result

```bash
adb shell ip rule show
adb shell ip -details rule show
adb shell ip route show table all
```
Correlate tables 100 through 200, OIF values, and actual destinations. Do not delete a rule until you understand what created it.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting a policy rule may remove network access for the VPN, a system UID, IMS, tethering, or a work profile. An incorrect netlink filter may alter routing itself rather than only the displayed view.

### Rollback

Before making changes, save the output of `ip rule show` and `ip route show table all`. Restore the normal VPN or NetworkStack, disable the module, and reboot; Android normally recreates system rules.

## Evidence level

**High.** Verified from the `RTM_GETRULE` parser, table ranges, and `HIGH_CONFIDENCE` mapping. The `RTA_FLOW`/fwmark inaccuracy is documented.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [rtnetlink rules](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- External primary documentation or official project: [ip-rule manual](https://man7.org/linux/man-pages/man8/ip-rule.8.html).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `vpn-policy-rules`, `route-table`, `route-count`.

[Back to the Native signs reference](../)
