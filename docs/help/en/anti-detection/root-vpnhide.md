---
title: Root Stack — VPNHide, VPNHide Next, Vector, Magisk, KernelSU, and APatch
permalink: /help/en/anti-detection/root-vpnhide/
---

# Root Stack — VPNHide, VPNHide Next, Vector, Magisk, KernelSU, and APatch

This page describes an installation architecture, not a “one-click” solution. Any kernel or boot module can cause a boot loop, kernel panic, loss of networking, or incompatibility after an OTA update. Before starting, save the stock image for the relevant partition and make sure you know how to enter the bootloader or recovery environment and disable a module. Unlocking the bootloader erases user data on most devices.

## Without root

VPNHide and VPNHide Next do not have a complete non-root mode: their purpose requires intervention in `system_server`, the kernel, or the Zygote process. Without root, an APK can only serve as a user interface, diagnostic tool, or configurator; it cannot obtain the privileges needed to filter Binder or netlink responses for another UID.

The closest non-root equivalent in terms of outcome is an external router or gateway. It does not falsify local responses; it removes the local VPN from the phone altogether. A secondary user, repackaging, or rootless Xposed does not provide comparable coverage and adds isolation or integrity signals.

## With root: choosing the foundation

| Foundation | Main strength | Primary risk or limitation | Official download |
|---|---|---|---|
| Magisk | Widely used root solution, module ecosystem, built-in Zygisk | Root and userspace artifacts; boot image handling is device-specific | [Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest), [official installation guide](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md) |
| KernelSU Next | Kernel-based `su`, App Profile, module mounts | Requires a compatible kernel or LKM; manager and kernel versions must match | [KernelSU Next releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest), [documentation](https://kernelsu-next.github.io/webpage/) |
| APatch | KernelPatch runtime suitable for KPM scenarios | Patches `boot.img`, ARM64 only; a wrong image or key is dangerous | [APatch releases](https://github.com/bmax121/APatch/releases/latest), [Russian installation guide](https://apatch.dev/ru/install.html) |

Do not copy flashing commands between devices. Magisk may use either the `boot` or `init_boot` partition, while APatch documentation specifically requires `boot.img`. Follow the selected project's instructions and use the factory image from the exact build installed on your device.

### Checking an APK or ZIP before installation

A downloaded kernel or root module is not trustworthy merely because its filename resembles an official release. First preserve the release-page URL and calculate a local hash:

```bash
sha256sum vpnhide*.zip *.apk
unzip -l vpnhide*.zip | sed -n '1,120p'
unzip -p vpnhide*.zip module.prop 2>/dev/null
```

For an APK, use `apksigner` from Android SDK Build-Tools:

```bash
apksigner verify --verbose --print-certs vpnhide.apk
```

Compare a SHA-256 value only with a checksum published by the project itself. A hash posted in an arbitrary message beside the same file is not an independent verification. Do not install a ZIP that asks for a SuperKey, VPN subscription, or another secret through a third-party site or bot. Inspecting `unzip -l` does not prove that scripts are safe, but it can reveal an unexpected boot image, binary, or unrelated installer before installation.

## Choosing a framework: Vector or legacy LSPosed

The original [LSPosed/LSPosed](https://github.com/LSPosed/LSPosed) repository was archived on May 2, 2026 and advertised support for Android 8.1–14. On current devices, a more reasonable starting point is [JingMatrix/Vector](https://github.com/JingMatrix/Vector/releases/latest), which advertises Android 8.1–17 Beta support and Xposed API compatibility.

VPNHide requires only the system scope from the framework. After installation:

1. Enable the VPNHide or VPNHide Next module.
2. Select **only `System Framework`**.
3. Do not add `com.notcvnt.rknhardering` to the scope.
4. Reboot the device, because `system_server` must start with the module already active.

When a specific VPNHide release explicitly requires LSPosed rather than Vector, use the compatible combination documented in that release's notes. Do not run two Xposed frameworks at the same time.

## Upstream VPNHide: recommended stable arrangement

Source and downloads: [okhsunrog/vpnhide](https://github.com/okhsunrog/vpnhide), [latest release](https://github.com/okhsunrog/vpnhide/releases/latest), and [detection-vector map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).

Architecture:

- the VPNHide APK configures targets;
- Vector or LSPosed in `System Framework` handles Java/Binder and PackageManager filtering;
- **exactly one** native backend is used: kmod, KPM, or Zygisk;
- optional `portshide` handles loopback access.

### Choosing a native backend

Choose **kmod** first on a supported GKI device. It operates in the kernel, does not modify RKNHardering's process memory, and cannot be bypassed by a raw syscall. VPNHide publishes builds by KMI generation, such as `android14-6.1`; this identifies the kernel generation and does not necessarily equal the Android version.

Use **KPM** for older or non-GKI kernels, or when a `.ko` cannot be loaded. It requires a KernelPatch runtime through APatch or KPatch-Next-Module. This is a beta path with less field testing.

Use **Zygisk** only as a fallback. It filters at the libc level inside the target process, so RKNHardering may observe discrepancies in `maps`, RWX memory, the linker, or hooks, and a raw syscall can bypass the filter. Do not describe it as equivalent to a kernel backend.

**Never install kmod and KPM together.** They may hook the same kernel functions. The result can be a hang, kernel panic, or boot loop. If multiple backend ZIPs remain installed, remove the extras and verify that only one is active.

### Installing upstream VPNHide

1. Download the APK and recommended module ZIP only from the [official release](https://github.com/okhsunrog/vpnhide/releases/latest). Check the filename and SHA-256 when the author provides a checksum.
2. Install the APK normally.
3. Enable the module in Vector or LSPosed with `System Framework` as its scope, then reboot.
4. Grant root only to the VPNHide configurator application, never to RKNHardering.
5. On the overview tab, select the recommended native backend and install **one** ZIP through the root manager.
6. Install the separate Ports module only when needed.
7. After rebooting, select `com.notcvnt.rknhardering` as the Java, Native, and Ports target and as the observer for Apps, then save.
8. Force-stop RKNHardering and perform two checks.

In current upstream releases, user configuration is stored in `/data/system/vpnhide_config.json`. Edit it manually only after making a backup and validating the JSON; `invalid config` means a syntax or schema error. Using the UI is normally safer.

Read-only inspection:

```bash
adb shell uname -r
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

## VPNHide Next: broader experimental coverage

Source and downloads: [soranerai/vpnhide_next](https://github.com/soranerai/vpnhide_next), [latest release](https://github.com/soranerai/vpnhide_next/releases/latest).

Externally claimed by the project: the fork adds kernel-level port blocking, MTU, MSS and `TCP_INFO` filtering, GSO and PMTU handling, eBPF traffic statistics, qdisc, UDP timing, IPv6 link-local handling, and broader proc/sysfs concealment. The `Min`, `Medium`, and `Max` modes control how many hooks are enabled. The project's README explicitly warns that stability is not guaranteed on every kernel and that boot loops or kernel panics are possible.

Practical selection:

- start with `Min` to verify basic `ioctl`, `getifaddrs`, netlink, and route filtering;
- move to `Medium` when RKNHardering still observes socket, MTU, MSS, or PMTU indicators;
- use `Max` only in a laboratory device with working recovery when specific proc, sysfs, BPF, qdisc, or timing findings have been confirmed.

Do not enable `Max` “just in case.” More kernel hooks increase compatibility risk and make the source of a regression harder to isolate.

The VPNHide Next LSPosed module should likewise operate through `System Framework` without entering the target process. Its kmod README identifies `dev_ioctl`, `sock_ioctl`, `rtnl_fill_ifinfo`, IPv4 and IPv6 address netlink, and `/proc/net/route` as baseline hook points. Keep the APK and ZIP on the exact same release: a control-protocol mismatch can produce partial behavior.

### Starting VPNHide Next step by step

1. Download the APK and kernel module only from the [official release](https://github.com/soranerai/vpnhide_next/releases/latest). Do not use an upstream VPNHide kmod: this is a different project with a different control protocol.
2. Record `uname -r`, the Android build, and the downloaded asset name. When the release does not claim compatibility with the installed kernel, do not flash it “to see what happens” on a primary device.
3. Install the APK, enable it in Vector or LSPosed, keep only `System Framework` in scope, and reboot.
4. Install exactly one VPNHide Next kernel ZIP through a supported root manager and reboot again.
5. In the application, select the UID or copy of `com.notcvnt.rknhardering`, start with `Min`, and save the configuration.
6. Perform two identical runs. Move to `Medium`, then `Max`, only when a specific MTU, MSS, PMTU, BPF, qdisc, proc, or sysfs finding remains positive.

The top-level README describes a newer control device at `/dev/vpnhide_ctrl`, while separate READMEs or older builds may still mention `/proc/vpnhide_targets` and `targets.txt`. This indicates documentation differences between revisions; it is not a reason to create a missing file manually. Use the UI for the exact release and perform only read-only checks:

```bash
adb shell su -c 'cat /proc/modules | grep -i vpnhide'
adb shell su -c 'ls -l /dev/vpnhide_ctrl /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VPNHide Next|VpnHide|Vector|LSPosed'
```

`no such file or directory` means the path is absent or that revision uses another interface. When the module does not appear in `/proc/modules` but the UI reports a working native layer, first check the architecture of the exact release: KPM or an integrated kernel patch does not have to look like a conventional LKM.

## Zygisk Next and root concealment are separate concerns

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) supplies the Zygisk API for KernelSU or APatch, or can replace Magisk's built-in Zygisk. Its modern linker and anonymous-memory modes are intended to reduce artifacts, but module compatibility is not guaranteed. It does not turn a process-local VPNHide backend into a kernel-level filter.

Root concealment is covered separately in the [integrity section](../root-integrity/). First establish that VPNHide works correctly, then minimize the root surface. Installing several concealment modules at once makes diagnosis difficult and can introduce new mount or linker signals.

## Verifying each layer

After installation, do not rely only on VPNHide's green status indicator.

**Framework:** `DIRECT_NETWORK_CAPABILITIES`, `INDIRECT_NETWORK_CAPABILITIES`, and VPN interface names or routes from `LinkProperties` should disappear in RKNHardering.

**Native:** `INTERFACE_ENUMERATION`, `TUNTAP_TYPE`, `GETIFADDRS_VPN`, `RTM_GETLINK_VPN`, and route or interface-index indicators should disappear. When Java results are clean but native findings remain, the problem is the native backend, not LSPosed.

**Ports:** the loopback scan should no longer confirm SOCKS, HTTP, Xray, or Clash APIs. A port being open to the shell but inaccessible to the target UID is expected.

**Integrity:** no new `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, `LSPOSED`, or β hook-consistency signals should appear. When they do, inspect the framework scope and abandon the process-local backend.

## Risks and rollback

Before every kernel or module change, preserve:

- the stock `boot` or `init_boot` image according to the root solution's official guide;
- the currently working patched image;
- the `/data/adb/modules` list and exact APK and ZIP versions;
- the VPNHide configuration;
- a way to reach recovery or the bootloader without booting Android.

Roll back one step at a time: disable the most recently added module through the manager or safe mode, reboot, verify networking, and only then uninstall it. Do not remove several components at once, because the cause will remain unknown. For a boot loop, use the root manager's official rescue mechanism or restore the saved stock image according to the device instructions. Do not improvise with partitions.

[Back to the contents](../)
