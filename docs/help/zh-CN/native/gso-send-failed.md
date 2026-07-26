---
title: "`UDP_SEGMENT` 已接受，但发送 4,800 字节失败"
permalink: /help/zh-CN/native/gso-send-failed/
---

# `UDP_SEGMENT` 已接受，但发送 4,800 字节失败

> **ID：** `GSO_SEND_FAILED`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

成功设置 `UDP_SEGMENT=1200` 后，探针向 `127.0.0.1:53` 发送一个 4,800 字节数据报。若 `sendto` 返回 -1，则生成 `gso_send_failed|errno=N`。检查器以低置信度信息显示该行。

### 精确触发条件

GSO 套接字选项已被接受，但通过环回地址发送大缓冲区失败。

## 结果含义

该结果诊断的是特定发送路径。失败可能与 offload 支持、套接字缓冲区、策略或内核缺陷有关，不能证明存在 VPN。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

检查不会分析 errno 或实际分段情况。环回接口不等同于物理或隧道设备；不需要接收端，也不会验证是否送达。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有多组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 重启后，在禁用防火墙和 VPN 的状态下重复测试并记录 errno。不要凭猜测降低 MTU。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚路径之前，不要启用最大范围的内核 Hook。 检查内核日志和厂商支持。不要只伪造 `sendto` 的返回值；这会制造虚假成功并掩盖真实应用错误。

### 如何验证结果

```bash
adb shell dmesg 2>/dev/null | grep -Ei 'udp|gso|segmentation|skb' | tail -80
adb shell uname -r
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

内核或网络 sysctl 实验可能降低 UDP/QUIC 与 DNS 的可靠性。不要在主力设备上全局应用。

### 回滚

把 sysctl、内核和模块设置恢复到基线，重启后重新测试 DNS/QUIC。

## 证据等级

**低。**已根据 setsockopt 成功、send 失败的分支核验；该结果仅供参考。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- 外部第一方文档或官方项目：[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `gso-failed`, `gso-ok`, `udp-pmtu-fail`.

[返回原生检查参考](../)
