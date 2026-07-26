---
title: "Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT 启发式检查"
permalink: /help/zh-CN/native/emulator-build-profile/
---

# Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT 启发式检查

> **ID：** `EMULATOR_BUILD`
> **类别：** 模拟器、用户资料与隔离环境
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

Kotlin 会在以下情况标记构建信息：fingerprint 以 `generic` 或 `unknown` 开头，或包含 `vbox`、`emulator`、`test-keys`；model 包含 `google_sdk`、`Emulator` 或 `Android SDK built for`；hardware 精确等于 `goldfish`、`ranchu` 或 `vbox86`；product 为 `sdk_gphone*`、`vbox86p`、`emulator`、`sdk` 或 `google_sdk`；manufacturer 精确等于 `Genymotion`。每个事实都会生成中等置信度待复核项。

### 精确触发条件

任一构建字段匹配上述模式。

## 结果含义

这是宽泛的启发式检查，因此 `test-keys` 也可能表示物理设备上的自定义固件，而不是模拟器。应与 QEMU 和设备节点标记结合判断。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

构建字段容易伪造，也会随 OEM 而变化。正式 GSI 或开发板可能合法地呈现通用特征。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

要避免这一类指标，应使用运行正式生产版本的物理设备。QEMU 属性、goldfish/ranchu 标记、特殊设备节点和构建指纹都属于环境本身；普通应用无法在不修改系统的情况下让所有层保持一致。云手机或 OEM 克隆环境也应视为独立环境，并与物理设备基线比较。 对运行自定义 ROM 的物理设备而言，唯一干净的基线是官方生产构建；恢复出厂设置不会改变 fingerprint。

### 有 root 权限

仅伪造少量 `getprop` 值并不能把模拟器变成物理设备：驱动、`/dev` 节点、硬件配置、ABI 和内核行为仍然存在。用于伪装的 root 模块可能消除一个标记，却制造 Hook、属性或库完整性不一致。这些方案可在开发阶段作为实验，但要获得有效结果，仍应在真实设备上运行 RKNHardering。 要让 fingerprint、model、product 和 hardware 全部一致非常困难；局部伪装仍会在其他层暴露，并可能破坏 Play Integrity。

### 如何验证结果

```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.product.model
adb shell getprop ro.hardware
adb shell getprop ro.product.name
adb shell getprop ro.product.manufacturer
```
按实现使用的精确子串进行检查。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

无效 fingerprint 可能破坏 OTA 更新或 Play 服务；伪造 hardware/product 还可能选择不兼容的 HAL。

### 回滚

移除伪装模块，并从原始镜像恢复构建属性。

## 证据等级

**中。**已根据 `collectBuildEmulatorFacts()` 核验；所有输出行都是中等置信度待复核项。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Android Build API](https://developer.android.com/reference/android/os/Build).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `emulator-qemu-property`, `emulator-goldfish`, `root-property`.

[返回原生检查参考](../)
