---
title: "通过 CNTVCT_EL0 测量 ARM64 socket/sendto 时序"
permalink: /help/zh-CN/native/timing-oracle/
---

# 通过 CNTVCT_EL0 测量 ARM64 socket/sendto 时序

> **ID：** `TIMING_ORACLE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

在 arm64 上，探针执行 10 次迭代：读取周期计数器，创建 UDP 套接字，向 `127.0.0.1:53` 发送 64 字节，关闭套接字，再次读取计数器。随后报告最小、最大和平均周期数。其他 ABI 会报告 `not_arm64`。两种结果都只是低置信度信息。

### 精确触发条件

函数执行时总会生成一行：arm64 上为数值，其他平台为 `not_arm64`。不存在“检测到 VPN”的阈值。

## 结果含义

这是原始性能遥测。没有基线、统计分析和 CPU 频率控制时，这些数值无法解释。当前版本中，时序不会影响 `detected` 或待复核状态。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

10 次测量太少；调度器行为、DVFS、热降频、模拟器、后台负载和计时器频率的影响通常大于 VPN。对回环地址的发送不会经过 VPN 数据路径，结果也没有按 `cntfrq` 归一化。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有两组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 每组测试前停止后台负载，等待设备温度稳定，并至少采集 20 次运行。比较分布，而不是某一个平均值。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚流程之前，不要启用最大范围的内核 Hook。 不要为了本页而替换 `CNTVCT` 或改变调度器行为；这会影响密码学、计时器和反篡改逻辑。基准测试应在专用构建中使用 Perfetto 或 Simpleperf。

### 如何验证结果

```bash
adb shell getprop ro.product.cpu.abi
adb shell dumpsys thermalservice | head -80
adb shell top -b -n 1 | head -30
```
使用在完全相同条件下采集的多份 RKNHardering 报告进行比较。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

固定 CPU 频率或 governor 需要 root，会增加发热；长时间测试还可能损伤电池。不要持续开启性能模式。

### 回滚

恢复默认 governor 和热管理设置并重启。信息性信号不需要绕过。

## 证据等级

**低。**已根据 10 次迭代、`CNTVCT_EL0` 以及 `INFORMATIONAL_KINDS` 核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Arm generic timer documentation](https://developer.arm.com/documentation/102379/latest/).
- 外部第一方文档或官方项目：[Perfetto](https://perfetto.dev/docs/).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `backpressure`, `gso-ok`, `general-diagnostics`.

[返回原生检查参考](../)
