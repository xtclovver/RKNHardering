---
title: "环回 UDP 洪泛：50,000 个 1,400 字节数据报"
permalink: /help/zh-CN/native/backpressure/
---

# 环回 UDP 洪泛：50,000 个 1,400 字节数据报

> **ID：** `BACKPRESSURE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

支持取消的探针使用 `MSG_DONTWAIT`，尝试向 `127.0.0.1:53` 最多发送 50,000 个、每个 1,400 字节的数据报。遇到第一个错误即停止，并报告已发送/总数、耗时和估算 MB/s。结果仅供参考。

### 精确触发条件

只要扫描未被取消且套接字创建成功，无论成功发送多少次，通常都会生成该行；没有阈值。

## 结果含义

它显示本地发送路径的吞吐量，以及何时出现 backpressure。它不确认数据报是否送达，也不测量互联网或 VPN 吞吐量。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

环回行为、套接字缓冲区、CPU 负载、调度和数据包丢弃都会影响结果。约 70 MB 的用户态负载会造成明显但短暂的压力；操作被取消时，该行可能缺失。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有多组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 不要在低性能或过热设备上连续大量重复测试。设备冷却后进行三到五组测试已经足够。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚路径之前，不要启用最大范围的内核 Hook。 不要仅为得到“好看”的数字而增大全局套接字缓冲区或关闭防火墙。任何修改都应属于独立性能基准，而不是反检测配置。

### 如何验证结果

```bash
adb shell dumpsys thermalservice | head -80
adb shell 'cat /proc/net/softnet_stat 2>/dev/null | head'
```
只在等价状态之间比较 sent/time 数值，不要人为设定所谓“正常”阈值。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

反复洪泛会增加 CPU、电池和本地网络栈负载；部分设备可能短暂卡顿或产生 watchdog 压力。

### 回滚

停止扫描、`force-stop` 应用并让设备冷却。该探针不会修改任何持久设置。

## 证据等级

**低。**已根据 50,000 × 1,400 字节的环回循环、取消检查和信息性映射核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- 外部第一方文档或官方项目：[sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `timing-oracle`, `udp-pmtu-ok`, `gso-ok`.

[返回原生检查参考](../)
