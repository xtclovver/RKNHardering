---
title: "Reserved deep ID for BPF map accessibility"
permalink: /help/en/native/deep-bpf-map-accessible/
---

# Reserved deep ID for BPF map accessibility

> **ID:** `DEEP_BPF_MAP_ACCESSIBLE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`fromDeepVpnKind("bpf_map_accessible")` maps to `DEEP_BPF_MAP_ACCESSIBLE`, but the consolidated `nativeDetectVpnDetector()` does not call `detectBpfMaps()`. At present, the same kind string is emitted only by the legacy pipeline and receives the ID `BPF_MAP_ACCESSIBLE`.

### Exact trigger condition

There is no producer in the current deep pipeline. A potential trigger would be a successful open of one of the three netd BPF pin paths.

## What the result means

The absence of a deep finding does not show whether the BPF maps are protected. Check the legacy `bpf-map-accessible` signal and the actual access available to the app UID.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

Two IDs for one kind may be misleading after future changes. This documentation records the state of version 2.10.0; if the function is connected later, the mapping and tests must be updated.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Keep the stock SELinux/BPF permissions and do not weaken access controls on `/sys/fs/bpf`. No action is needed for the current ID.

### With root

Do not delete pinned netd maps or disable eBPF. If the goal is to close access, make the smallest possible policy change for `untrusted_app` and test traffic accounting.

### How to verify the result

```bash
rg -n 'detectBpfMaps|nativeDetectVpnDetector|nativeDetectVpnAdvanced|bpf_map_accessible' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting or corrupting netd BPF maps can break the firewall, data-usage statistics, and networking. Do not perform destructive cleanup.

### Rollback

Revert the sepolicy or module change and reboot the device. If netd state has been damaged, restore the boot/system image rather than recreating maps manually.

## Evidence level

**Registry/compatibility.** Verified by the absence of a call in the deep function and the presence of a legacy producer; registry-only status.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Linux BPF](https://docs.kernel.org/bpf/index.html).
- External primary documentation or official project: [AOSP eBPF traffic monitoring](https://source.android.com/docs/core/datausage/ebpf-traffic-monitor).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `bpf-map-accessible`, `proc-net-dev-vpn`.

[Back to the Native signs reference](../)
