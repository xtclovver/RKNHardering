---
title: Root, Hooks, Emulators, and Process Integrity
permalink: /help/en/anti-detection/root-integrity/
---

# Root, Hooks, Emulators, and Process Integrity

Hiding a VPN while adding an obvious Xposed or Zygisk layer to the process is a poor trade. RKNHardering separately checks for root access, mounts, SELinux state, system properties, `su`, hook markers, RWX memory, linker and library integrity, Java/native discrepancies, and emulation. The purpose of this section is to minimize the exposed surface, not to promise undetectable root access.

## Without root

The most reliable arrangement for these checks is a physical device running a stock, enforcing build, with the boot state relocked after a supported installation where possible, and without `su`, `/data/adb` modules, Xposed, or a repackaged APK.

Changing `Build.MODEL` does not turn an emulator into a physical device. RKNHardering checks QEMU properties, pipes and drivers, Goldfish artifacts, BlueStacks indicators, and the overall build profile. Use a real phone for the control baseline. An emulator remains useful for functional testing, but expect `NATIVE_EMULATOR` or a review state.

Do not use rootless Xposed or NPatch on RKNHardering. Repackaging changes the APK signature and structure, while runtime injection creates process-local hooks. That directly intersects with `LIBRARY_INTEGRITY`, `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `beta.linker_integrity`, and `beta.direct_syscall_consistency`.

## With root

### Reduce the exposed surface before adding concealment

1. Never grant root access to RKNHardering.
2. Enable unmount or deny behavior for the target UID in the root manager. The feature name differs between Magisk, KernelSU, and APatch.
3. Do not enable the VPNHide Zygisk backend for the target when a kernel backend is available.
4. In Vector or LSPosed, keep only `System Framework` in scope.
5. Do not switch SELinux to permissive or make `/system` writable.
6. Do not add arbitrary `resetprop` substitutions. Inconsistent properties are more conspicuous than the original value.
7. After adding each module, inspect the mount namespace, `maps`, and native/library signals.

### What the root signals inspect

`ROOT_SU_BINARY` looks for an executable `su` at common paths. `ROOT_MANAGEMENT` covers `/data/adb/magisk`, `/data/adb/modules`, KernelSU or APatch directories, and similar traces. `ROOT_PROPERTY` and `ROOT_MAGISK_PROPERTY` cover unsafe or characteristic properties. `ROOT_SYSTEM_RW`, `ROOT_SUSPICIOUS_MOUNT`, and `ROOT_OVERLAY_MOUNT` cover writable system partitions and unusual bind or overlay mounts. `ROOT_SELINUX` covers permissive state or the absence of enforcing mode. `ROOT_UID` covers UID or GID 0.

A deny list or namespace unmount helps only with paths that are genuinely hidden from the target's mount namespace. It does not change global kernel properties, repair SELinux state, or remove process-local Zygisk code.

### Magisk

Download it only from the [official repository](https://github.com/topjohnwu/Magisk/releases/latest). The built-in DenyList and Zygisk behavior have changed across releases, so consult the release notes. The rule for RKNHardering is simple: the target must not receive root access and must not see module mounts. When VPNHide operates through the kernel and `system_server`, the target process can remain free of Zygisk injection.

### KernelSU Next

App Profile can restrict root per application and unmount module changes. Official references: the [repository](https://github.com/KernelSU-Next/KernelSU-Next) and [documentation](https://kernelsu-next.github.io/webpage/). Confirm that the profile applies to the correct UID, especially in a work or private profile.

### APatch

Use a strong SuperKey and never expose it in logs or screenshots. APatch documentation requires a backup of the original `boot.img`. VPNHide's KPM backend may depend on a correctly functioning KernelPatch runtime; that does not mean root artifacts are concealed automatically.

### Zygisk Next, NoHello, SUSFS, and Hide My Applist

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) provides the Zygisk API and linker, memory, and unmount modes. [NoHello](https://github.com/MhmRdd/NoHello/releases/latest) advertises root and Zygisk concealment plus mount rules. [SUSFS core](https://gitlab.com/simonpunk/susfs4ksu) and its [userspace module](https://github.com/sidex15/susfs4ksu-module/releases/latest) are intended for kernel-level concealment of mounts and paths, but require a kernel already built with a compatible SUSFS patch. Installing one ZIP over an ordinary kernel does not add the missing kernel patch.

These are additional external projects, not required parts of VPNHide. They may help with individual `ROOT_*` or mount signals, but they also add their own code, configuration, and compatibility risk. Add only one new component per iteration. Do not install unknown builds from Telegram or file-sharing sites; verify the repository, release signature or checksum, and never disclose a SuperKey or other secrets to third parties.

SUSFS is particularly sensitive to kernel version and integration. The kernel patch, userspace module, and root manager must be mutually compatible. A mismatched combination may fail to load, break mounts, or cause a boot loop. On a primary device without a recovery path, it is not a sensible first step.

[Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest) and current forks can filter package-list channels, but they usually require Xposed or Zygisk processing inside the selected application. That is a poor default for RKNHardering: concealing `INSTALLED_APP` can introduce `HOOK_MARKERS`, `LSPOSED`, linker or RWX findings, or a direct-syscall mismatch. VPNHide's Apps role, operating through `system_server`, is preferable because it does not require putting HMA in the target's scope. Keep HMA as a separate comparative experiment rather than stacking it on top of an already functioning PackageManager filter.

### SELinux and system properties

Keep `getenforce` at `Enforcing`. `Permissive` weakens the device and is a direct signal. Do not alter `ro.secure`, `ro.debuggable`, `ro.build.tags`, `service.adb.root`, or similar properties at random. Any substitution must remain internally consistent with the build fingerprint and firmware mode; otherwise it creates a new integrity conflict.

### Hooks and memory

`HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, `LSPOSED`, `HOOK_PROPERTY`, and the β linker and direct-syscall checks look for the effects of intervention, not merely a module name. Renaming the LSPosed APK or package is therefore insufficient.

Preferred order from least visible to the target:

1. External router — no root or hook is present on the phone.
2. Kernel VPNHide plus a `system_server` hook — the target is not injected.
3. Zygisk native hiding — a process-local footprint remains; use only as a fallback.
4. Xposed scope on RKNHardering or a repackaged APK — the worst option for integrity.

## Read-only inspection

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

Shell output is not sufficient to inspect the application's own namespace: the shell and target can see different mounts. Use RKNHardering results and the root manager's diagnostics. Do not publish complete `mountinfo`, `getprop`, or module lists without redaction; they can contain paths, serial-related data, and names of private modules.

Root-only reads:

```bash
adb shell su -c 'ls -la /data/adb'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /sys/fs/selinux/enforce'
```

`permission denied` is expected without `su`; with `su`, it means insufficient privileges, policy restrictions, or a different namespace. Do not “fix” it by granting the application broad permissions.

## Verification and rollback

After installing a concealment component, compare four groups: local VPN signals, root signals, hook and integrity signals, and network stability. When the VPN indicators disappear but `LIBRARY_INTEGRITY` and `RWX` appear, switch to a kernel backend or remove the target from the injection scope.

To roll back, disable the last module, reboot, force-stop RKNHardering, and repeat the baseline check. If the phone no longer boots, use the root manager's official module safe mode or rescue procedure, or restore the saved stock boot image. Do not delete arbitrary `/data/adb` directories from recovery without knowing which manager owns them.

[Back to the contents](../)
