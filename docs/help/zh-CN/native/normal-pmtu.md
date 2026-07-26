---
title: "第一个非隧道接口的 MTU"
permalink: /help/zh-CN/native/normal-pmtu/
---

# 第一个非隧道接口的 MTU

> **ID：** `NORMAL_PMTU`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针遍历 `getifaddrs()`，选择第一个名称不是 `lo`，且不包含子串 `tun`、`wg` 或 `ppp` 的条目。它通过 `fetchMtu()` 获取 MTU，并报告接口名称和数值。这里不会排除 `xfrm`、`utun` 或 `tailscale`。该行只提供信息。

### 精确触发条件

找到第一个符合条件且 MTU 大于 0 的接口；没有数值阈值。

## 结果含义

它为比较其他指标时的物理路径 MTU 提供参考。1500、1400、1350 或类似数值本身都不能证明存在 VPN。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

`getifaddrs()` 的返回顺序不能保证所选接口承载主默认路由，同一接口也可能有多条地址记录。子串过滤不完整，可能选中 VPN 风格接口；结果也没有与路由目标关联。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有两组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 把接口名称与默认路由进行比较。不要仅为得到“典型”的 1500 而修改 MTU；移动网络和 overlay 网络合法使用其他数值。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚流程之前，不要启用最大范围的内核 Hook。 任何 MTU 替换都必须在 ioctl、sysfs、netlink、TCP MSS 和实际转发中保持一致。数值不一致会产生额外信号和丢包。

### 如何验证结果

```bash
adb shell ip route get 1.1.1.1
adb shell 'for i in /sys/class/net/*; do echo -n "${i##*/} "; cat "$i/mtu" 2>/dev/null; done'
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

MTU 过高可能造成黑洞路由或分片，过低则降低性能。未测试 ICMP、QUIC 和 TCP 前，不要全局修改。

### 回滚

在 VPN 或接口配置中恢复原始 MTU，或重启 NetworkStack 与 VPN。修改前先记录原值。

## 证据等级

**低。**已根据“第一个匹配项”算法和不存在阈值这一事实核验；仅供参考。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[netdevice(7) MTU](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- 外部第一方文档或官方项目：[Path MTU Discovery](https://docs.kernel.org/networking/ip-sysctl.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `pmtu-mss-combined`, `udp-pmtu-ok`, `tuntap-type`.

[返回原生检查参考](../)
