---
title: "MAC 地址为全零或广播地址的 ARP 条目"
permalink: /help/zh-CN/native/hidden-mac-neighbors/
---

# MAC 地址为全零或广播地址的 ARP 条目

> **ID：** `HIDDEN_MAC_NEIGHBORS`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectArpNeighbors()` 读取 `/proc/net/arp`，统计所有条目，并统计 MAC 为 `00:00:00:00:00:00` 或包含 `ff:ff:ff:ff:ff:ff` 的条目。只要 hidden > 0，旧版策略就把该 `kind` 归为高置信度。

### 精确触发条件

至少有一条 ARP 记录使用全零或广播 MAC 地址。

## 结果含义

项目的高置信度策略把它视为“隐藏邻居”的证据，但 ARP/NUD 解析尚未完成或存在陈旧条目，也可能是普通网络状态。因此 total/hidden 详情非常重要。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

ARP 只适用于 IPv4 和二层网络。地址解析期间可能暂时出现全零 MAC，广播 MAC 也可能合法。检查不会判断该条目所属接口是否具有 VPN 特征。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

在 Wi-Fi 稳定后重新检查，并先向网关产生少量流量。如果某条记录长期卡住，可切换网络。不要在不理解对应地址的情况下，仅为得到绿色结果而清空 ARP。

### 有 root 权限

不要隐藏整个 ARP 表；这会造成计数不一致并破坏 LAN 诊断。若某个 VPN 模块生成合成邻居记录，应修正其配置或使用外部网关。

### 如何验证结果

```bash
adb shell cat /proc/net/arp 2>&1
adb shell ip neigh show 2>/dev/null
```
间隔一小段时间采集两次结果；临时的 `INCOMPLETE` 条目可能会自行消失。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

清空邻居表会暂时中断本地连接，并增加 ARP 流量。

### 回滚

重新连接 Wi-Fi 或当前网络；邻居缓存会自动重新填充。

## 证据等级

**高。**已根据精确 MAC 条件核验；旧版策略把它标记为高置信度，但仍存在误报可能。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[arp(7)](https://man7.org/linux/man-pages/man7/arp.7.html).
- 外部第一方文档或官方项目：[ip-neighbour](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `arp-vpn-interface`, `interface-enumeration`.

[返回原生检查参考](../)
