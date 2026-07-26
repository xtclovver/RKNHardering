---
title: "Interface Count Mismatch Between if_indextoname and RTM_GETLINK"
permalink: /help/en/native/trim-oracle/
---

# Interface Count Mismatch Between if_indextoname and RTM_GETLINK

> **ID:** `TRIM_ORACLE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe counts successful `if_indextoname()` calls for indices 1 through 127 (`bind_probe`) and separately counts `RTM_NEWLINK` messages in a complete `RTM_GETLINK` dump. If the counts differ, it reports `MISMATCH`. The kind is a medium-confidence review finding.

### Exact trigger condition

`bindCount != rtmCount` after two independent enumerations.

## What the result means

This most often indicates an incomplete filter: one API hides an interface while another leaves its index or entry visible. A mismatch may also result from an index above 127, a race while an interface is created or removed, or an incomplete netlink dump.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The name `bind_probe` is historical: the implementation actually uses `if_indextoname()`, not `bind()`. The upper limit of 127 can create a false mismatch on systems with a larger interface index. The snapshot is not atomic and is not repeated for confirmation.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not try to “fix” anything at first. Record a baseline on the same device without the VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between the two series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Repeat the check several times. If the mismatch appears only while switching Wi-Fi, mobile data, or the VPN, it is a race rather than a persistent bypass.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. Consistency must be restored across all paths. Do not hide only `RTM_NEWLINK` by trimming the dump: `if_indextoname()`, `SIOCGIFNAME`, routes, and addresses must present a compatible view.

### How to verify the result

```bash
adb shell 'ip -o link show | wc -l'
adb shell 'ip -o link show'
```
An exact comparison requires a native harness that iterates over `if_indextoname(1..127)` immediately after an `RTM_GETLINK` dump. Repeat the test at least five times on a stable network.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Incorrect filtering of multipart netlink messages can make the dump loop indefinitely or break system networking calls.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Medium.** Verified from the two-count algorithm; the kind is medium confidence and does not set `detected`. The limit of 127 and race condition are documented.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`vpnhide_regression_probe.cpp` — consistency and oracle probes](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- External primary documentation or official project: [if_nametoindex(3)](https://man7.org/linux/man-pages/man3/if_nametoindex.3.html).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `rtm-getlink-vpn`, `ifindexname-vpn`, `vpnhide`.

[Back to the Native signs reference](../)
