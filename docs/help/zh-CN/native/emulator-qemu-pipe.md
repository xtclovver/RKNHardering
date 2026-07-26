---
title: "QEMU 通信管道与套接字"
permalink: /help/zh-CN/native/emulator-qemu-pipe/
---

# QEMU 通信管道与套接字

> **ID：** `EMULATOR_QEMU_PIPE`
> **类别：** 模拟器、用户资料与隔离环境
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针检查 `/dev/qemu_pipe`、`/dev/socket/qemud`、`/dev/socket/genyd` 和 `/dev/socket/baseband_genyd`。任一路径可访问都会生成 `qemu_pipe` 和高置信度待复核项。

### 精确触发条件

对四个路径之一执行 `access(F_OK)` 成功。

## 结果含义

这是很强的模拟器设备节点标记。与构建属性不同，它反映真实的来宾机/宿主机基础设施。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

SELinux 可能向应用隐藏路径，厂商测试设备理论上也可能暴露相似套接字。缺少这些节点不能排除其他虚拟机监控器。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

要避免这一类指标，应使用运行正式生产版本的物理设备。QEMU 属性、goldfish/ranchu 标记、特殊设备节点和构建指纹都属于环境本身；普通应用无法在不修改系统的情况下让所有层保持一致。云手机或 OEM 克隆环境也应视为独立环境，并与物理设备基线比较。

### 有 root 权限

仅伪造少量 `getprop` 值并不能把模拟器变成物理设备：驱动、`/dev` 节点、硬件配置、ABI 和内核行为仍然存在。用于伪装的 root 模块可能消除一个标记，却制造 Hook、属性或库完整性不一致。这些方案可在开发阶段作为实验，但要获得有效结果，仍应在真实设备上运行 RKNHardering。 隐藏设备节点可能直接破坏模拟器控制功能。

### 如何验证结果

```bash
adb shell ls -l /dev/qemu_pipe /dev/socket/qemud /dev/socket/genyd /dev/socket/baseband_genyd 2>/dev/null
```
若有可调试构建，应特别从应用上下文验证访问结果。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

删除或遮盖 QEMU pipe 会破坏模拟器与宿主机通信、电话功能以及关机/控制操作。

### 回滚

恢复快照，或移除挂载隐藏模块并重启 AVD。

## 证据等级

**中。**已根据 `kPipePaths` 核验；检查器为该结果分配高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Android Emulator architecture](https://developer.android.com/studio/run/emulator-acceleration).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `emulator-qemu-property`, `emulator-qemu-driver`, `emulator-build-profile`.

[返回原生检查参考](../)
