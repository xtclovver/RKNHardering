---
title: "Access to `/proc/net/fib_trie` was denied or failed"
permalink: /help/en/native/fib-trie-denied/
---

# Access to `/proc/net/fib_trie` was denied or failed

> **ID:** `FIB_TRIE_DENIED`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectFibTrieAccess()` only opens `/proc/net/fib_trie`. A successful open emits nothing; `EACCES` or `EPERM` produces `SELinux denies`, `ENOENT` is neutral, and any other errno also emits a line. In the deep checker, the kind is neither high-confidence nor informational, so it produces medium-confidence `needsReview` evidence.

### Exact trigger condition

Opening `/proc/net/fib_trie` returned `EACCES`, `EPERM`, or any error other than `ENOENT`.

## What the result means

This checks access to a diagnostic path; it is not VPN detection. On modern Android, denial for `untrusted_app` may be normal policy. The line warrants review, but it is not a reason to “fix” SELinux.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The name can be misleading: denial normally improves privacy and closes an information leak. The code does not attempt to read the contents after a successful open and does not report “accessible.” The shell and app UID run in different SELinux domains.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not weaken anything. Record the Android version and ROM, then compare the result with a clean device running the same build. If the app reports `errno=N`, decode the errno and check whether the procfs mount is damaged.

### With root

Do not add an allow rule merely to make the line disappear; that would expose route data to an ordinary app. For laboratory diagnostics, inspect AVC logs instead of putting SELinux into permissive mode.

### How to verify the result

```bash
adb shell 'cat /proc/net/fib_trie >/dev/null; echo shell_rc=$?'
adb logcat -d | grep -E 'avc: denied.*fib_trie' | tail -30
```
Shell success or failure does not reproduce the `untrusted_app` context; the final result must be checked inside RKNHardering.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

SELinux permissive mode or a broad allow rule exposes network state and weakens the entire sandbox. That is worse than the review signal itself.

### Rollback

Remove the test sepolicy rule, restore enforcing mode, and reboot the device. Confirm that `getenforce` returns `Enforcing`.

## Evidence level

**Medium.** Verified against the errno branches; the kind remains a medium-confidence review finding.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- External primary documentation or official project: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `bpf-map-accessible`, `sysfs-vpn-leak`, `syscall-unavailable`.

[Back to the Native signs reference](../)
