---
title: Root stack — VPNHide, VPNHide Next, Vector, Magisk, KernelSU, and APatch
permalink: /help/en/anti-detection/root-vpnhide/
---

# Root stack — VPNHide, VPNHide Next, Vector, Magisk, KernelSU, and APatch

This page describes an installation architecture, not a “one-click” promise. Any kernel or boot module can cause a bootloop, kernel panic, loss of networking, or incompatibility after an OTA update. Before starting, save the stock image for the relevant partition and make sure you know how to boot into the bootloader/recovery and disable a module. Unlocking the bootloader erases user data on most devices.

## Without root

VPNHide and VPNHide Next do not have a complete non-root mode: their purpose requires intervention in `system_server`, the kernel, or the zygote process. An APK without root can only act as a user interface, diagnostics tool, or configurator; it does not gain permission to filter Binder or netlink for another UID.

The non-root equivalent in terms of outcome is an external router or gateway. It does not “spoof” responses; it removes the local VPN from the phone altogether. A second space and repackaged/rootless Xposed do not provide comparable coverage and add isolation/integrity signals.

## With root: choosing the foundation

| Foundation | Strength | Main risk/limitation | Official download |
|---|---|---|---|
| Magisk | Most widespread root solution, modules, built-in Zygisk | Root/userspace traces; boot image is device-specific | [Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest), [official installation](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md) |
| KernelSU Next | Kernel-based `su`, App Profile, module mounts | Requires a compatible kernel/LKM; manager and kernel versions must match | [KernelSU Next releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest), [documentation](https://kernelsu-next.github.io/webpage/) |
| APatch | KernelPatch runtime, suitable for KPM scenarios | Patches `boot.img`, ARM64 only; a wrong image or key is dangerous | [APatch releases](https://github.com/bmax121/APatch/releases/latest), [Russian guide](https://apatch.dev/ru/install.html) |

Do not copy flashing commands between devices. Magisk may use either the `boot` or `init_boot` partition, whereas APatch documentation specifically requires `boot.img`. Follow the instructions for the selected project and use the factory image for your exact build.

### Checking an APK/ZIP before installation

A downloaded kernel/root module is not safe merely because its name resembles an official release. First save the release-page URL and calculate a local hash:

```bash
sha256sum vpnhide*.zip *.apk
unzip -l vpnhide*.zip | sed -n '1,120p'
unzip -p vpnhide*.zip module.prop 2>/dev/null
```

For an APK, use `apksigner` from Android SDK Build-Tools:

```bash
apksigner verify --verbose --print-certs vpnhide.apk
```

Compare a SHA-256 value only with a checksum published by the project itself. A checksum posted in a random message next to the same file is not an independent verification. Do not install a ZIP that asks for a SuperKey, VPN subscription, or another secret through a third-party site or bot. Inspecting `unzip -l` does not prove that scripts are safe, but it can reveal an unexpected boot image, binaries, or an unrelated installer before installation.

## Choosing a framework: Vector or the old LSPosed

The original [LSPosed/LSPosed](https://github.com/LSPosed/LSPosed) repository was archived on May 2, 2026 and claimed support for Android 8.1–14. For current devices it is more reasonable to begin with [JingMatrix/Vector](https://github.com/JingMatrix/Vector/releases/latest), which claims Android 8.1–17 Beta support and Xposed API compatibility.

VPNHide needs only system scope from the framework. After installation:

1. Enable the VPNHide/VPNHide Next module.
2. Select **only `System Framework`**.
3. Do not add `com.notcvnt.rknhardering` to the scope.
4. Reboot the device, because `system_server` must start with the module already active.

If a specific VPNHide release explicitly requires LSPosed rather than Vector, use the compatible combination documented in its release notes. Do not run two Xposed frameworks at the same time.

## VPNHide upstream: recommended stable layout

Source and download: [okhsunrog/vpnhide](https://github.com/okhsunrog/vpnhide), [latest release](https://github.com/okhsunrog/vpnhide/releases/latest), [vector map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).

Architecture:

- the VPNHide APK configures targets;
- Vector/LSPosed in `System Framework` handles Java/Binder and `PackageManager`;
- **exactly one** native backend: kmod, KPM, or Zygisk;
- optional `portshide` handles loopback.

### Choosing a native backend

Choose **kmod** first on a supported GKI device. It operates in the kernel, does not modify RKNHardering process memory, and cannot be bypassed with a raw syscall. VPNHide publishes builds by KMI generation, such as `android14-6.1`; this identifies the kernel generation, not necessarily the Android version.

Use **KPM** for older or non-GKI kernels, or when a `.ko` cannot be loaded. It requires a KernelPatch runtime: APatch or KPatch-Next-Module. This is a beta path with less field testing.

**Zygisk** is a fallback. It works at the libc layer inside the target process, so RKNHardering may observe `maps`, RWX/linker/hook discrepancies, and a raw syscall may bypass the filter. Do not describe it as equivalent to a kernel backend.

**Never install kmod and KPM at the same time.** They may hook the same kernel functions. The result can be a hang, kernel panic, or bootloop. If several backend ZIPs remain installed, remove the extras and confirm that only one is active.

### Installing upstream VPNHide

1. Download the APK and recommended module ZIP only from the [official release](https://github.com/okhsunrog/vpnhide/releases/latest). Verify the filename and SHA-256 if the author published a checksum.
2. Install the APK normally.
3. Enable the module in Vector/LSPosed with the `System Framework` scope, then reboot.
4. Grant root only to the VPNHide configurator application, never to RKNHardering.
5. On the overview tab, select the recommended native backend and install **one** ZIP through your root manager.
6. Install the separate Ports module only when needed.
7. After rebooting, select `com.notcvnt.rknhardering` as the Java/Native/Ports target and as the observer for Apps, then save.
8. Force-stop RKNHardering and run two checks.

In current upstream versions, user configuration is stored in `/data/system/vpnhide_config.json`. Edit it manually only after making a backup and validating the JSON; `invalid config` means a syntax or schema error. Using the UI is normally safer.

Read-only checks:

```bash
adb shell uname -r
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

## VPNHide Next: extended experimental coverage

Source and download: [soranerai/vpnhide_next](https://github.com/soranerai/vpnhide_next), [latest release](https://github.com/soranerai/vpnhide_next/releases/latest).

The external project claims that the fork adds kernel-level port blocking, MTU/MSS/TCP_INFO handling, GSO/PMTU, eBPF traffic statistics, qdisc, UDP timing, IPv6 link-local handling, and more complete proc/sysfs hiding. The `Min`, `Medium`, and `Max` modes change the number of hooks. The project README explicitly warns that stability is not guaranteed on every kernel and that bootloops or kernel panics are possible.

Practical selection:

- `Min` — start here to test basic `ioctl/getifaddrs/netlink/routes` handling;
- `Medium` — use when RKNHardering still sees socket/MTU/MSS/PMTU indicators;
- `Max` — laboratory use only, with working recovery, after specific proc/sysfs/BPF/qdisc/timing findings have been confirmed.

Do not enable `Max` “just in case.” More kernel hooks increase compatibility risk and make the cause of a regression harder to isolate.

The VPNHide Next LSPosed module should likewise work through `System Framework`, without being present in the target process. Its kmod README describes `dev_ioctl`, `sock_ioctl`, `rtnl_fill_ifinfo`, IPv4/IPv6 address netlink, and `/proc/net/route` as basic hook points. Keep the APK and ZIP at the exact same release version: a control-protocol mismatch can result in partial operation.

### Step-by-step VPNHide Next start

1. Download the APK and kernel module only from the [official release](https://github.com/soranerai/vpnhide_next/releases/latest). Do not use a kmod from upstream VPNHide: this is a different project with a different control protocol.
2. Record `uname -r`, the Android build, and the downloaded asset name. If the release does not claim compatibility with your kernel, do not flash it “for testing” on a primary device.
3. Install the APK, enable it in Vector/LSPosed, leave only `System Framework` in scope, and reboot.
4. Install exactly one VPNHide Next kernel ZIP through a supported root manager, then reboot again.
5. In the application, select the UID/copy of `com.notcvnt.rknhardering`, begin with `Min`, and save the configuration.
6. Perform two identical runs. Move to `Medium`, then `Max`, only when a specific MTU/MSS/PMTU/BPF/qdisc/proc/sysfs finding remains positive.

The top-level README describes the newer control device `/dev/vpnhide_ctrl`, while separate READMEs or older builds may still mention `/proc/vpnhide_targets` and `targets.txt`. This indicates differences between documentation revisions; it is not a reason to create a missing file manually. Use the UI for the exact release and these read-only checks for diagnostics:

```bash
adb shell su -c 'cat /proc/modules | grep -i vpnhide'
adb shell su -c 'ls -l /dev/vpnhide_ctrl /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VPNHide Next|VpnHide|Vector|LSPosed'
```

`no such file or directory` means that the path is absent or that this revision uses another interface. If the module does not appear in `/proc/modules` while the UI reports a working native layer, first check the architecture of the specific release: KPM or an integrated kernel patch does not have to appear as an ordinary LKM.

## Zygisk Next and root hiding are separate tasks

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) provides the Zygisk API for KernelSU/APatch or can replace Magisk's built-in Zygisk. Its current linker/anonymous-memory mode is claimed to reduce traces, but module compatibility is not guaranteed. It does not turn a process-local VPNHide backend into a kernel-level filter.

Root hiding is discussed separately in the [integrity section](../root-integrity/). First make VPNHide work correctly, then minimize the root surface. Installing several hiding modules at once makes diagnosis difficult and may introduce new mount/linker signals.

## Verification by layer

After installation, do not look only at VPNHide's green status.

**Framework:** `DIRECT_NETWORK_CAPABILITIES`, `INDIRECT_NETWORK_CAPABILITIES`, and VPN interface names/routes from `LinkProperties` should disappear in RKNHardering.

**Native:** `INTERFACE_ENUMERATION`, `TUNTAP_TYPE`, `GETIFADDRS_VPN`, `RTM_GETLINK_VPN`, and route/ifindex indicators should disappear. If Java results are clean but native findings remain, the problem is the native backend, not LSPosed.

**Ports:** loopback scanning should not confirm SOCKS/HTTP/Xray/Clash APIs. A port that is open to the shell but inaccessible to the target UID is expected.

**Integrity:** no new `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, `LSPOSED`, or β hook-consistency signals should appear. If they do, check the scope and abandon the process-local backend.

## Risks and rollback

Before each kernel/module change, preserve:

- the stock `boot`/`init_boot` image according to the official instructions for your root solution;
- the currently working patched image;
- the `/data/adb/modules` list and the APK/ZIP versions;
- the VPNHide configuration;
- a method for entering recovery/bootloader without booting Android.

Roll back sequentially: disable the most recently added module in the manager or safe mode, reboot, verify networking, and only then uninstall it. Do not remove several components at once, or the cause will remain unknown. For a bootloop, use the official rescue mechanism of the root manager or restore the saved stock image according to the device instructions. Do not improvise with partitions.

[Back to contents](../)
