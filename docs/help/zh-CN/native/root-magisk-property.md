---
title: "Magisk 专用系统属性"
permalink: /help/zh-CN/native/root-magisk-property/
---

# Magisk 专用系统属性

> **ID：** `ROOT_MAGISK_PROPERTY`
> **类别：** Root 与系统状态
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针检查 `init.svc.magisk_daemon`、`init.svc.magisk_pfs` 和 `persist.magisk.hide`。任一非空值都会生成 `magisk_prop` 与高置信度待复核项。

### 精确触发条件

三个属性中至少一个在当前进程的属性视图中存在且非空。

## 结果含义

这是较强的 Magisk 痕迹，尤其常见于旧版或兼容性配置。当前版本不一定继续使用全部名称，因此干净结果不能排除 Magisk。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

OEM 组件或第三方模块理论上可能创建同名属性。`resetprop` 也可能只在部分上下文隐藏它，同时仍留下挂载或路径痕迹。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

若不需要 root，可靠的修复方法是通过官方流程让设备恢复原厂状态：使用对应管理器卸载 root，或刷入与当前构建完全匹配的原厂 `boot`/`init_boot` 和系统分区。即使管理器已移除，解锁的 bootloader、自定义内核和残留目录仍可能暴露修改痕迹。恢复前必须备份设备；在固件已修改时重新锁定 bootloader，可能导致数据丢失或设备无法启动。

### 有 root 权限

Root 权限只能减少可观察表面，不能证明 root 不存在。尽量只向少数应用授予 `su`，不要向 RKNHardering 授权，禁用不必要的模块，也不要把 SELinux 改为 permissive。App Profile/DenyList 行为与挂载隔离必须在具体固件上验证。SUSFS 等方案属于实验性技术，需要兼容内核，也可能产生自身痕迹。参考测试仍需要一台独立的原厂设备。 若属性来自旧模块，请通过官方管理器更新或移除该模块。不要使用任意脚本批量重写 `init.svc.*` 属性。

### 如何验证结果

```bash
adb shell getprop init.svc.magisk_daemon
adb shell getprop init.svc.magisk_pfs
adb shell getprop persist.magisk.hide
```
对应用执行 `force-stop` 并重新启动后，把值与报告详情比较。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

替换 init 服务属性可能干扰服务管理并使诊断更困难。修改启动脚本可能造成启动循环。

### 回滚

删除新增的 `resetprop` 规则或旧模块，然后重启。若要完全取消 root，请遵循 Magisk 官方说明。

## 证据等级

**中。**已根据 `kMagiskProps` 核验；Kotlin 会生成高置信度待复核项。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Magisk official repository](https://github.com/topjohnwu/Magisk).
- 外部第一方文档或官方项目：[Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `root-property`, `root-management`, `root-suspicious-mount`.

[返回原生检查参考](../)
