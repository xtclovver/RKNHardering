---
title: "已全局禁用反向路径过滤"
permalink: /help/zh-CN/native/sysctl-rp-filter/
---

# 已全局禁用反向路径过滤

> **ID：** `SYSCTL_RP_FILTER`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectSysctl()` 读取 `/proc/sys/net/ipv4/conf/all/rp_filter`；精确值 `0` 会生成 `sysctl_rp_filter|rp_filter=0`。旧版策略把它作为中等置信度待复核项。

### 精确触发条件

全局 `rp_filter == 0`。

## 结果含义

复杂策略路由、VPN、网络共享和多宿主环境中都可能禁用反向路径过滤。这在 Android 上并不罕见，也不是直接证据。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

实际行为取决于各接口的值以及内核采用 `max(all, interface)` 的语义。该检查只读取 `all`。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

不要仅为消除待复核项而修改 sysctl。应与同一固件的干净基线比较；OEM 可能合法地使用 0。

### 有 root 权限

把值改为 1 或 2 可能破坏非对称路由和 VPN。测试前保存 `all`、`default` 以及每个接口的值，然后验证网络连通性。

### 如何验证结果

```bash
adb shell cat /proc/sys/net/ipv4/conf/all/rp_filter
adb shell 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do printf "%s=" "$f"; cat "$f"; done' 2>/dev/null
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

严格的 `rp_filter` 设置可能丢弃合法的分流隧道或多 WAN 流量。

### 回滚

恢复保存的 sysctl 值；若改动不是持久化的，也可重启设备。

## 证据等级

**中。**已根据精确的 `rp_filter==0` 条件核验；该结果为中等置信度待复核项。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[ip-sysctl rp_filter](https://docs.kernel.org/networking/ip-sysctl.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `sysctl-forwarding`, `vpn-policy-rules-netlink`.

[返回原生检查参考](../)
