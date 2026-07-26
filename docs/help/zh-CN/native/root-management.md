---
title: "Root 管理器目录与文件"
permalink: /help/zh-CN/native/root-management/
---

# Root 管理器目录与文件

> **ID：** `ROOT_MANAGEMENT`
> **类别：** Root 与系统状态
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`nativeDetectRoot()` 检查 `/data/adb/magisk`、`/data/adb/modules`、`/data/adb/ksu`、`/data/adb/ksud`，旧版 Superuser/SuperSU APK 与目录、`daemonsu`、一个 init.d 脚本，以及 `/dev/com.koushikdutta.superuser.daemon`。任一路径可访问都会生成高置信度待复核项。

### 精确触发条件

对固定列表中的任一路径执行 `access(F_OK)` 成功。

## 结果含义

这是已安装或未完全移除 root 栈的强痕迹，但不能证明对应模块目前仍在运行。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

现代管理器可能把数据存放在其他位置，SELinux 或挂载命名空间也可能隐藏路径。即使 `su` 已不再工作，`/data/adb/modules` 仍可能是旧安装残留。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

若不需要 root，可靠的修复方法是通过官方流程让设备恢复原厂状态：使用对应管理器卸载 root，或刷入与当前构建完全匹配的原厂 `boot`/`init_boot` 和系统分区。即使管理器已移除，解锁的 bootloader、自定义内核和残留目录仍可能暴露修改痕迹。恢复前必须备份设备；在固件已修改时重新锁定 bootloader，可能导致数据丢失或设备无法启动。 正常取消 root 后，可只读检查残留。不要盲目删除 `/data/adb`：其中可能包含模块数据和恢复机制。

### 有 root 权限

Root 权限只能减少可观察表面，不能证明 root 不存在。尽量只向少数应用授予 `su`，不要向 RKNHardering 授权，禁用不必要的模块，也不要把 SELinux 改为 permissive。App Profile/DenyList 行为与挂载隔离必须在具体固件上验证。SUSFS 等方案属于实验性技术，需要兼容内核，也可能产生自身痕迹。参考测试仍需要一台独立的原厂设备。 针对目标 UID 的路径隔离必须与 `/proc/self/mounts` 和 overlay 状态一致。若路径被隐藏而挂载仍可见，相邻检查会触发。

### 如何验证结果

```bash
adb shell 'for p in /data/adb/magisk /data/adb/modules /data/adb/ksu /data/adb/ksud /system/app/Superuser.apk /system/app/SuperSU.apk /system/app/SuperSU /system/xbin/daemonsu /system/etc/init.d/99SuperSUDaemon /dev/com.koushikdutta.superuser.daemon; do [ -e "$p" ] && echo "$p"; done'
```
没有 root 时，shell 无法读取部分 `/data/adb` 路径。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

手工删除模块目录可能同时删除安全模式或回滚支持，并让挂载处于半配置状态。应使用 root 管理器 UI。

### 回滚

若测试过隐藏模块，请通过正常机制禁用。若要彻底移除，请使用官方卸载流程并恢复 boot 镜像。

## 证据等级

**中。**已根据 `kRootMgmtPaths` 核验；每条匹配结果都会获得高置信度待复核状态。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Magisk](https://github.com/topjohnwu/Magisk).
- 外部第一方文档或官方项目：[KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next).
- 外部第一方文档或官方项目：[APatch](https://github.com/bmax121/APatch).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `root-su-binary`, `root-suspicious-mount`, `root-overlay-mount`.

[返回原生检查参考](../)
