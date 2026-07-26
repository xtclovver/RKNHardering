---
title: "VPN 接口的保留旧版 ARP ID"
permalink: /help/zh-CN/native/arp-vpn-interface/
---

# VPN 接口的保留旧版 ARP ID

> **ID：** `ARP_VPN_INTERFACE`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`ARP_VPN_INTERFACE`/`arp_vpn_iface` 仍存在于信号目录中，并被标记为旧版高置信度信号；但 2.10.0 的 `detectArpNeighbors()` 不会生成这一 `kind`。该函数只统计全零 MAC 地址和广播 MAC 地址，并仅生成 `hidden_mac_neighbors`。

### 精确触发条件

不存在独立的信号生成器。

## 结果含义

程序仍会读取 ARP，但当前实际启用的信号是 `hidden-mac-neighbors`。现有代码不会把 ARP 行中的接口名称与 VPN 风格名称进行匹配。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

未来的解析器可能会重新加入 `arp_vpn_iface`；目前保留该 URL 只是为了兼容性。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无需绕过一个并不存在的 `kind`。请在相邻页面检查实际出现的全零 MAC 条目。

### 有 root 权限

无需为了这个 ID 添加 root 级 ARP 过滤。不要清空邻居表，否则会造成延迟并中断本地网络连接。

### 如何验证结果

```bash
rg -n 'arp_vpn_iface|hidden_mac_neighbors|detectArpNeighbors' app/src/main
adb shell cat /proc/net/arp 2>&1
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

`ip neigh flush all` 会中断当前 LAN 连接，而且不会消除该信号的生成来源。

### 回滚

通常无需回滚；如果误清空了邻居表，后续流量或重新连接会自动重建它。

## 证据等级

**目录项/兼容性。**已通过确认不存在独立生成器，以及实际只输出 `hidden_mac_neighbors` 进行核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[arp(7)](https://man7.org/linux/man-pages/man7/arp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `hidden-mac-neighbors`.

[返回原生检查参考](../)
