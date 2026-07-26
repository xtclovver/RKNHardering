---
title: Root、Hook、模拟器与进程完整性
permalink: /help/zh-CN/anti-detection/root-integrity/
---

# Root、Hook、模拟器与进程完整性

为了隐藏 VPN，却给目标进程添加明显的 Xposed 或 Zygisk 层，是很不划算的交换。RKNHardering 会分别检查 root 权限、挂载、SELinux 状态、系统属性、`su`、Hook 标记、RWX 内存、链接器与库完整性、Java/原生层差异以及模拟环境。本节的目标是尽量缩小暴露面，而不是承诺 root 可以完全不可检测。

## 无 root

对这些检查而言，最可靠的布局是：使用物理设备，运行原厂且 SELinux enforcing 的系统；在受支持的安装流程完成后，尽可能重新锁定启动状态；不安装 `su`、`/data/adb` 模块或 Xposed，也不使用重新打包的 APK。

修改 `Build.MODEL` 不会把模拟器变成物理设备。RKNHardering 会检查 QEMU 属性、管道与驱动、Goldfish 痕迹、BlueStacks 指标以及整体构建特征。应使用真实手机作为对照基线。模拟器仍适合功能测试，但应预期出现 `NATIVE_EMULATOR` 或待复核状态。

不要对 RKNHardering 使用免 root Xposed 或 NPatch。重新打包会改变 APK 签名和结构，而运行时注入会制造进程内 Hook。这会直接触及 `LIBRARY_INTEGRITY`、`HOOK_MARKERS`、`RWX_MEMORY_REGIONS`、`beta.linker_integrity` 和 `beta.direct_syscall_consistency`。

## 有 root

### 在添加隐藏措施前先缩小暴露面

1. 永远不要向 RKNHardering 授予 root 权限。
2. 在 root 管理器中，为目标 UID 启用卸载或拒绝行为。该功能在 Magisk、KernelSU 和 APatch 中名称不同。
3. 如果存在内核后端，不要为目标启用 VPNHide 的 Zygisk 后端。
4. 在 Vector 或 LSPosed 中，作用域只保留 `System Framework`。
5. 不要把 SELinux 切换到 permissive，也不要让 `/system` 可写。
6. 不要随意添加 `resetprop` 替换。互相矛盾的属性比原始值更显眼。
7. 每添加一个模块后，都要检查挂载命名空间、`maps` 以及原生/库完整性信号。

### Root 信号检查什么

`ROOT_SU_BINARY` 会在常见路径查找可执行的 `su`。`ROOT_MANAGEMENT` 覆盖 `/data/adb/magisk`、`/data/adb/modules`、KernelSU 或 APatch 目录及类似痕迹。`ROOT_PROPERTY` 与 `ROOT_MAGISK_PROPERTY` 覆盖不安全或具有特征性的属性。`ROOT_SYSTEM_RW`、`ROOT_SUSPICIOUS_MOUNT` 和 `ROOT_OVERLAY_MOUNT` 覆盖可写系统分区及异常 bind/overlay 挂载。`ROOT_SELINUX` 覆盖 permissive 状态或未处于 enforcing 的情况。`ROOT_UID` 覆盖 UID 或 GID 0。

拒绝列表或命名空间卸载，只对确实从目标挂载命名空间中隐藏的路径有效。它不会改变全局内核属性、修复 SELinux 状态，也不会移除进程内 Zygisk 代码。

### Magisk

只能从[官方仓库](https://github.com/topjohnwu/Magisk/releases/latest)下载。内置 DenyList 与 Zygisk 的行为在不同版本间有所变化，因此应阅读对应发布说明。对 RKNHardering 的规则很简单：目标不得获得 root 权限，也不得看到模块挂载。当 VPNHide 通过内核和 `system_server` 工作时，目标进程可以完全不接受 Zygisk 注入。

### KernelSU Next

App Profile 可以按应用限制 root，并卸载模块改动。官方资料：[仓库](https://github.com/KernelSU-Next/KernelSU-Next)与[文档](https://kernelsu-next.github.io/webpage/)。尤其是在工作资料或私密资料中，应确认配置作用于正确 UID。

### APatch

使用强 SuperKey，且绝不能在日志或截图中泄露。APatch 文档要求备份原始 `boot.img`。VPNHide 的 KPM 后端可能依赖正常工作的 KernelPatch 运行时，但这不表示 root 痕迹会自动被隐藏。

### Zygisk Next、NoHello、SUSFS 与 Hide My Applist

[Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext/releases/latest) 提供 Zygisk API，以及链接器、内存和卸载模式。[NoHello](https://github.com/MhmRdd/NoHello/releases/latest) 声称可以隐藏 root 和 Zygisk，并提供挂载规则。[SUSFS core](https://gitlab.com/simonpunk/susfs4ksu) 及其[用户空间模块](https://github.com/sidex15/susfs4ksu-module/releases/latest)旨在内核层隐藏挂载与路径，但要求内核已经集成兼容的 SUSFS 补丁。把一个 ZIP 安装到普通内核上，并不会补上缺失的内核补丁。

这些都是额外的外部项目，并非 VPNHide 的必需组件。它们可能有助于处理个别 `ROOT_*` 或挂载信号，但也会加入自己的代码、配置和兼容性风险。每次迭代只添加一个新组件。不要安装来自 Telegram 或文件分享网站的不明构建；应核验仓库、发布签名或校验和，并且绝不能向第三方透露 SuperKey 或其他秘密。

SUSFS 对内核版本和集成方式尤其敏感。内核补丁、用户空间模块和 root 管理器必须互相兼容。组合不匹配可能导致加载失败、挂载损坏或 boot loop。对没有恢复路径的主力设备而言，它不适合作为第一步。

[Hide My Applist](https://github.com/Dr-TSNG/Hide-My-Applist/releases/latest) 及当前分支能够过滤软件包列表通道，但通常需要在所选应用进程内运行 Xposed 或 Zygisk。对 RKNHardering 来说，这不是好的默认方案：隐藏 `INSTALLED_APP` 的同时，可能引入 `HOOK_MARKERS`、`LSPOSED`、链接器或 RWX 发现，或直接系统调用不一致。VPNHide 的 Apps 角色通过 `system_server` 工作，不需要把 HMA 加入目标作用域，因此更可取。应把 HMA 保留为独立对照实验，而不是叠加到已经正常工作的 PackageManager 过滤之上。

### SELinux 与系统属性

让 `getenforce` 保持 `Enforcing`。`Permissive` 会削弱设备安全，并且本身就是直接信号。不要随机修改 `ro.secure`、`ro.debuggable`、`ro.build.tags`、`service.adb.root` 或类似属性。任何替换都必须与 build fingerprint 和固件模式在内部保持一致，否则会制造新的完整性冲突。

### Hook 与内存

`HOOK_MARKERS`、`RWX_MEMORY_REGIONS`、`LIBRARY_INTEGRITY`、`LSPOSED`、`HOOK_PROPERTY`，以及 β 链接器和直接系统调用检查，关注的是干预造成的效果，而不只是模块名称。因此，重命名 LSPosed APK 或软件包并不足够。

从目标进程最难观察到的方案到最明显的方案，推荐顺序如下：

1. 外部路由器——手机上不存在 root 或 Hook。
2. 内核 VPNHide + `system_server` Hook——目标进程不被注入。
3. Zygisk 原生隐藏——仍有进程内痕迹；只作为后备方案。
4. 把 RKNHardering 加入 Xposed 作用域，或使用重打包 APK——完整性方面最差的选择。

## 只读检查

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

Shell 输出不足以检查应用自身命名空间：shell 与目标进程可能看到不同的挂载。应结合 RKNHardering 结果和 root 管理器诊断。不要在未脱敏的情况下公开完整的 `mountinfo`、`getprop` 或模块列表；其中可能包含路径、与序列号相关的数据和私有模块名称。

仅 root 可读：

```bash
adb shell su -c 'ls -la /data/adb'
adb shell su -c 'ls -la /data/adb/modules'
adb shell su -c 'cat /sys/fs/selinux/enforce'
```

无 `su` 时出现 `permission denied` 是正常的；有 `su` 时则表示权限仍不足、策略限制或处于不同命名空间。不要通过给应用授予宽泛权限来“修复”它。

## 验证与回滚

安装隐藏组件后，应比较四组结果：本地 VPN 信号、root 信号、Hook 与完整性信号，以及网络稳定性。如果 VPN 指标消失，但出现 `LIBRARY_INTEGRITY` 和 `RWX`，应切换到内核后端，或从注入作用域中移除目标。

回滚时，禁用最后安装的模块、重启、强制停止 RKNHardering，再重复基线检查。若手机无法启动，应使用 root 管理器的官方模块安全模式或救援流程，或恢复已保存的原厂 boot 镜像。不要在 recovery 中随意删除 `/data/adb` 目录，因为你可能并不知道其中各目录由哪个管理器负责。

[返回反检测指南首页](../)
