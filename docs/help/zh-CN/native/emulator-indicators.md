---
title: "模拟器指标汇总项"
permalink: /help/zh-CN/native/emulator-indicators/
---

# 模拟器指标汇总项

> **ID：** `EMULATOR_INDICATORS`
> **类别：** 模拟器、用户资料与隔离环境
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 服务状态

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

这是该类别的汇总 ID。当前 `evaluateEmulator()` 会为 QEMU 属性、pipe、goldfish/ranchu、驱动、BlueStacks 和构建配置分配具体 ID，但不会另外生成一条阳性的 `EMULATOR_INDICATORS`。

### 精确触发条件

该 ID 本身没有信号生成器；它是稳定的文档入口，也是未来聚合逻辑的占位符。

## 结果含义

应查看各子信号。即使所有列出的标记都不存在，也不能证明设备一定是物理设备；现代模拟器可能遮盖标准指标。

**该行如何影响报告：**这是一个汇总或回退 ID，用于把一组输出行关联到文档，并不一定拥有独立的阳性信号生成器。

## 限制与可能的误报

当前列表不包括硬件证明、传感器、电话功能、图形时序或完整 fingerprint 分析。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

要避免这一类指标，应使用运行正式生产版本的物理设备。QEMU 属性、goldfish/ranchu 标记、特殊设备节点和构建指纹都属于环境本身；普通应用无法在不修改系统的情况下让所有层保持一致。云手机或 OEM 克隆环境也应视为独立环境，并与物理设备基线比较。

### 有 root 权限

仅伪造少量 `getprop` 值并不能把模拟器变成物理设备：驱动、`/dev` 节点、硬件配置、ABI 和内核行为仍然存在。用于伪装的 root 模块可能消除一个标记，却制造 Hook、属性或库完整性不一致。这些方案可在开发阶段作为实验，但要获得有效结果，仍应在真实设备上运行 RKNHardering。 与其为了通过汇总页大范围伪造属性，更应把模拟器结果明确标记为独立测试环境。

### 如何验证结果

```bash
adb shell getprop ro.kernel.qemu
adb shell getprop ro.hardware
adb shell getprop ro.product.board
adb shell getprop ro.build.fingerprint
adb shell ls -l /dev/qemu_pipe /dev/socket/qemud 2>/dev/null
```
各项精确条件请参阅对应子页面。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

大范围伪造构建属性可能破坏 OTA 更新、Play 服务和应用兼容性。

### 回滚

移除伪装模块或属性规则，并恢复模拟器快照或原始 boot 镜像。

## 证据等级

**服务状态。**已根据目录与 `evaluateEmulator()` 核验；2.10.0 不会把该汇总 ID 直接分配给阳性结果。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Android Emulator](https://developer.android.com/studio/run/emulator).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `emulator-qemu-property`, `emulator-build-profile`, `emulator-qemu-pipe`.

[返回原生检查参考](../)
