---
title: "加载原生检查库"
permalink: /help/zh-CN/native/native-library/
---

# 加载原生检查库

> **ID：** `NATIVE_LIBRARY`
> **类别：** 服务状态信号
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 可用性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

在任何 JNI 探针运行前，`NativeSignsBridge` 会加载原生库。若 `System.loadLibrary` 失败，`NativeSignsChecker` 与深度 VPN 检测器都会返回 ID 为 `NATIVE_LIBRARY` 的结果，并在可用时附带异常文本。发生该错误后，不能认为接口、路由、root 和 Hook 探针已经完成。

### 精确触发条件

`.so` 加载失败、ABI 不兼容、库缺失、linker/命名空间错误或 JNI 异常。成功加载不会另外生成阳性行。

## 结果含义

这既不是设备干净指标，也不是 VPN 指标。它表示大部分原生覆盖不可用，因此整体结果必须视为不完整。

**该行如何影响报告：**该信号表示探针无法执行。`unavailable` 绝不能解释为没有 VPN 的证据。

## 限制与可能的误报

可能原因包括 APK 损坏、split APK 缺少所需 ABI、32/64 位进程不兼容、加壳干扰、构建错误或环境限制。重新打包后尤其容易发生。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

重新安装同版本官方 APK，不要解包后重新签名。确认设备支持构建所需 ABI，且安装没有 split 冲突。开发时应使用标准 Gradle 任务构建，并检查 APK 内的 `lib/*` 条目。

### 有 root 权限

先禁用所有会改变 RKNHardering linker 命名空间、Zygote 或库加载行为的模块。不要通过故意破坏 JNI 来隐藏 VPN：应用会明确报告检查不可用，而不会把它当作干净结果。

### 如何验证结果

```bash
adb shell pm path com.notcvnt.rknhardering
adb shell dumpsys package com.notcvnt.rknhardering | grep -E 'primaryCpuAbi|secondaryCpuAbi'
adb logcat -c
adb shell am force-stop com.notcvnt.rknhardering
# 随后打开应用，并在 logcat 中查找 UnsatisfiedLinkError/dlopen：
adb logcat | grep -Ei 'rknhardering|UnsatisfiedLinkError|dlopen|linker'
```
本地构建还可运行 `unzip -l app-release.apk | grep '/lib/'`。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

若先卸载应用，或使用签名不兼容的 `adb install -r`，重新安装可能清除本地数据。请先保存导出的报告与设置。

### 回滚

恢复带原始签名的 APK，并只撤销影响加载的改动。若问题始于某个 root 模块，请禁用该模块并重启。

## 证据等级

**可用性。**已根据两个 Kotlin 检查器中的 `libraryUnavailableResult()` 分支和 JNI 方法注册核验。该信号描述检查覆盖，而不是网络状态。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsBridge.kt` — JNI 加载与原生桥接](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/probe/NativeSignsBridge.kt).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Android ABI management](https://developer.android.com/ndk/guides/abis).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `general-diagnostics`, `syscall-unavailable`, `library-integrity`.

[返回原生检查参考](../)
