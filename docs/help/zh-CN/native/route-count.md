---
title: "信息性的路由与接口数量"
permalink: /help/zh-CN/native/route-count/
---

# 信息性的路由与接口数量

> **ID：** `ROUTE_COUNT`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectRouteCount()` 调用共享的 `netlinkRouteDump(0)`，统计带 `route|` 前缀的行，并统计 `|dev=` 后的唯一值。无论 N 是否为 0，它都会生成 `route_count|total=N interfaces=M`；检查器把该 `kind` 标记为低置信度信息。

### 精确触发条件

只要函数执行完成就会生成该行；它属于遥测数据，而不是异常阈值。

## 结果含义

这些数值可作为基线，并帮助发现启用 VPN 或模块后的突变。不存在通用的“正常路由数量”，该值也不会影响 `detected`。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

快照受 Wi-Fi/移动数据、IPv4/IPv6、OEM、网络共享、用户资料及执行时机影响。函数只统计内部解析器成功生成的行；netlink 错误可能表现为 0。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有两组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 在同一网络下，分别在 VPN 关闭与开启状态采集至少三到五次。不要仅为让数量一致而删除路由。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚流程之前，不要启用最大范围的内核 Hook。 若过滤器改变计数，结果必须与 `RTM_GETLINK`、`getifaddrs()` 和真实路由查询保持一致；目标不是伪造固定 N。

### 如何验证结果

```bash
adb shell 'ip -4 route show table all; ip -6 route show table all'
adb shell 'ip -o link show | wc -l'
```
比较趋势即可，不要期待 shell 与应用快照精确相等。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

手工删除路由可能立即中断网络 ADB、DNS、移动数据和 VPN。

### 回滚

不要为信息性记录修改路由。若已经修改，请禁用实验模块并重启网络或设备。

## 证据等级

**低。**已根据无条件生成结果以及 `INFORMATIONAL_KINDS` 核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- 外部第一方文档或官方项目：[ip-route(8)](https://man7.org/linux/man-pages/man8/ip-route.8.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `route-table`, `vpn-policy-rules-netlink`, `trim-oracle`.

[返回原生检查参考](../)
