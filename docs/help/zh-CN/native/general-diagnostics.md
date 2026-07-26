---
title: "深度原生检测器没有返回任何行"
permalink: /help/zh-CN/native/general-diagnostics/
---

# 深度原生检测器没有返回任何行

> **ID：** `GENERAL_DIAGNOSTICS`
> **类别：** 服务状态信号
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 服务状态

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

只有在解析完成后 `findings` 为空时，`VpnNativeDetectorChecker` 才会添加 `GENERAL_DIAGNOSTICS`。这可能表示所有信号生成函数在干净状态下保持静默、扫描在产生输出前被取消，或解析器丢弃了输出行。若原生库不可用，则使用另一个 ID。

### 精确触发条件

执行 `detectVpnDetector()` 和 `parseRow()` 后，`findings.isEmpty()`。

## 结果含义

“未发现异常”只适用于深度检测类别和成功解析的输出行。它不能保证没有 VPN，也不会覆盖旧版、Java、服务端或 beta 检查。

**该行如何影响报告：**这是一个汇总或回退 ID，用于把一组输出行关联到文档，并不一定拥有独立的阳性信号生成器。

## 限制与可能的误报

部分探针在干净状态下刻意不输出，但 `route_count`、`normal_pmtu`、timing 和 UDP PMTU 通常会产生遥测。因此完全空白也可能表示扫描取消、解析器行为或 ABI 专用问题。`gso_ok` 当前因没有 detail 字段而被丢弃，但其他行通常仍会保留。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

确认扫描确实完成、原生库成功加载，并且该类别没有被取消。查看日志后，在稳定网络上重复完整扫描。

### 有 root 权限

暂时把 RKNHardering 排除在所有模块和作用域之外，然后重复测试。不要把“空输出”当作反检测目标：受损的诊断本身可见，并会降低报告可信度。

### 如何验证结果

```bash
adb logcat -c
adb shell am force-stop com.notcvnt.rknhardering
# 运行完整扫描，然后执行：
adb logcat -d | grep -Ei 'RKNHardering|native|vpn detector|cancel|JNI' | tail -200
```
同时检查相邻的 `native-library` 结果。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

故意破坏 JNI 或扫描过程可能掩盖真实错误，不能作为通过检查的有效方式。

### 回滚

恢复官方 APK，禁用造成干扰的模块并重启。重新执行完整基线扫描。

## 证据等级

**服务状态。**已根据 `findings.isEmpty()` 分支与解析器行为核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignsBridge.kt` — JNI 加载与原生桥接](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/probe/NativeSignsBridge.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Android JNI guidance](https://developer.android.com/training/articles/perf-jni).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `native-library`, `unknown-signals`, `route-count`.

[返回原生检查参考](../)
