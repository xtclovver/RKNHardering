---
title: Root, hooks, emulators, and process integrity
permalink: /help/en/anti-detection/root-integrity/
---

# Root, hooks, emulators, and process integrity

Hiding a VPN while adding an obvious Xposed/Zygisk layer to the process is a poor trade-off. RKNHardering separately checks root, mounts, SELinux, properties, `su`, hook markers, RWX regions, linker/library integrity, Java/native discrepancies, and emulators. The goal of this section is to minimize the exposed surface, not to promise undetectable root access.

## Without root

The most reliable configuration for these checks is a physical device with stock enforcing firmware, returned to a locked boot state after the normal installation process where possible, and without `su`, `/data/adb` modules, Xposed, or a repackaged APK.

Changing `Build.MODEL` does not turn an emulator into a physical device. RKNHardering checks QEMU properties, pipes, and drivers, as well as Goldfish, BlueStacks, and the build profile. Use a real phone for the control baseline. An emulator is useful for functional testing, but expect `NATIVE_EMULATOR` or a review result.

Do not use rootless Xposed/NPatch for RKNHardering. Repackaging changes the APK signature and structure, while runtime injection creates process-local hooks. This directly overlaps with `LIBRARY_INTEGRITY`, `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `beta.linker_integrity`, and `beta.direct_syscall_consistency`.

## With root

### Reduce the surface first, then add hiding

1. Never grant root access to RKNHardering.
2. In the root manager, enable unmount/deny behavior for the target UID. The feature name differs between Magisk, KernelSU, and APatch.
3. Do not enable the VPNHide Zygisk backend for the target when a kernel backend is available.
4. In the Vector/LSPosed scope, leave only `System Framework`.
5. Do not switch SELinux to permissive and do not make `/system` writable.
6. Do not add random `resetprop` substitutions. Inconsistent properties are more conspicuous than the original value.
7. After every module, check the mount namespace, `maps`, and native/library signals.

### What the root signals check

`ROOT_SU_BINARY` searches typical paths for an executable `su`. `ROOT_MANAGEMENT` checks `/data/adb/magisk`, `/data/adb/modules`, KernelSU/APatch directories, and similar traces. `ROOT_PROPERTY` and `ROOT_MAGISK_PROPERTY` inspect unsafe or characteristic properties. `ROOT_SYSTEM_RW`, `ROOT_SUSPICIOUS_MOUNT`, and `ROOT_OVERLAY_MOUNT` cover a writable system and unusual bind/overlay mounts. `ROOT_SELINUX` checks for permissive mode or the absence of enforcing. `ROOT_UID` checks for UID/GID 0.

DenyList/unmount helps only with paths that are actually hidden in the target's mount namespace. It does not change global kernel properties, repair SELinux, or remove process-local Zygisk code.

### Magisk

Download it only from the [official repository](https://github.com/topjohnwu/Magisk/releases/latest). The built-in DenyList and Zygisk behavior have changed between releases, so consult the release notes. For RKNHardering the rule is simple: the target must not receive root and must not see module mounts. When VPNHide runs through the kernel plus `system_server`, the target process can remain free of Zygisk injection.

### KernelSU Next

App Profile can restrict root on a per-application basis and unmount module changes. Official sources are the [repository](https://github.com/KernelSU-Next/KernelSU-Next) and [documentation](https://kernelsu-next.github.io/webpage/). Make sure the profile is applied to the correct UID, especially inside a work or private profile.

### APatch

Use a strong SuperKey and do not store it in logs or screenshots. The APatch documentation requires a backup of the original `boot.img`. The VPNHide KPM backend may depend on a correctly functioning KernelPatch runtime; this does not mean root traces are hidden automatically.

### Zygisk Next, NoHello, SUSFS, and Hide My Applist

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) provides the Zygisk API and linker/memory/unmount modes. [NoHello](https://github.com/MhmRdd/NoHello/releases/latest) claims root/Zygisk hiding and mount rules. [SUSFS core](https://gitlab.com/simonpunk/susfs4ksu) and the [userspace module](https://github.com/sidex15/susfs4ksu-module/releases/latest) are intended for kernel-level hiding of mounts and paths, but require a kernel already built with a compatible SUSFS patch. Installing a single ZIP on an ordinary kernel does not add the missing kernel patch.

These are additional external projects, not mandatory parts of VPNHide. They may help with individual `ROOT_*` or mount signals, but they also add their own code, settings, and compatibility risks. Install only one new component per iteration. Do not use unknown builds from Telegram or file-sharing sites; verify the repository and the release signature/checksum, and never disclose a SuperKey or other secrets to third parties.

SUSFS is especially sensitive to kernel version and integration. The kernel patch, userspace module, and root manager must be mutually compatible. An incompatible combination may fail to boot, break mounts, or cause a bootloop. On a primary device without a recovery path, it is not a sensible first step.

[Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest) and its current forks can filter package-list channels, but usually require Xposed/Zygisk handling inside the selected application. For RKNHardering this is a poor default: hiding `INSTALLED_APP` can introduce `HOOK_MARKERS`, `LSPOSED`, linker/RWX findings, or a direct-syscall mismatch. VPNHide's Apps role, operating through `system_server`, is preferable because it does not require placing HMA in the target's scope. Keep HMA as a separate comparison experiment rather than stacking it on top of an already working `PackageManager` filter.

### SELinux and system properties

Keep `getenforce` equal to `Enforcing`. `Permissive` weakens the device and is a direct signal. Do not change `ro.secure`, `ro.debuggable`, `ro.build.tags`, `service.adb.root`, or similar properties at random: a substitution must be internally consistent with the build fingerprint and firmware mode, otherwise it creates a new integrity conflict.

### Hooks and memory

`HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, `LSPOSED`, `HOOK_PROPERTY`, and the β linker/direct-syscall checks look for the consequences of modification, not merely a module name. Renaming the LSPosed APK or package is therefore insufficient.

Preference order for invisibility to the target:

1. External router — no root or hooks on the phone.
2. Kernel VPNHide plus a `system_server` hook — the target is not injected.
3. Zygisk native hiding — a process-local trace; use only as a fallback.
4. Xposed scope on RKNHardering or a repackaged APK — the worst option for integrity.

## Read-only checks

```bash
adb shell id
adb shell getenforce
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell getprop ro.build.tags
adb shell mount | head -n 80
adb shell cat /proc/self/mountinfo | head -n 80
adb shell cmd package list packages -U | grep com.notcvnt.rknhardering
```

For the application's own namespace, shell output is insufficient: the shell and the target may see different mounts. Use RKNHardering results and root-manager diagnostics. Do not publish complete `mountinfo`, `getprop`, or module lists without sanitizing them; they may contain paths, serial data, and names of private modules.

Root-only reads:

```bash
adb shell su -c 'ls -la /data/adb'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /sys/fs/selinux/enforce'
```

A `permission denied` result without `su` is expected. With `su`, it means insufficient permissions or policy restrictions, or a different namespace. Do not “fix” it by granting broad permissions to the application.

## Verification and rollback

After installing a hiding component, compare four groups: local VPN signals, root signals, hook/integrity signals, and network stability. If the VPN disappears but `LIBRARY_INTEGRITY` and `RWX` appear, switch to the kernel backend or remove the target from the scope.

Rollback: disable the most recently added module, reboot, force-stop RKNHardering, and repeat the baseline test. If the phone no longer boots, use the root manager's official module safe mode/rescue mechanism or the saved stock boot image. Do not randomly delete directories under `/data/adb` from recovery without knowing which manager owns them.

[Back to contents](../)
