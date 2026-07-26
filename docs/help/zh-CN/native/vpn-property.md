---
title: "旧版 VPN/DNS 系统属性"
permalink: /help/zh-CN/native/vpn-property/
---

# 旧版 VPN/DNS 系统属性

> **ID：** `VPN_PROPERTY`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectVpnPropertiesAll()` 读取 `net.vpn.dns1..4`、`dhcp.tun0.dns1/2`、`net.interfaces.default.type` 和 `net.interfaces.default.name`。任何非空值都会生成 `vpn_prop`。此外，代码还会再次检查 `net.interfaces.default.type` 是否包含子串 `tun` 或 `vpn`。旧版策略把该 `kind` 设为高置信度并设置 `detected=true`。

### 精确触发条件

任一固定 VPN 属性非空，或 `default.type` 包含 `tun` 或 `vpn`。

## 结果含义

当固件确实导出这些属性时，这是很强的旧版指标。较新的 Android 即使 VPN 正在运行，也通常没有这些属性。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

该属性列表不是稳定 Android API 的一部分。OEM 可能在 VPN 关闭后留下陈旧值，也可能完全不使用这些键。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

完全停止 VPN 客户端并重启网络，然后检查属性是否消失。若固件设置了该值，普通应用无法修改。外部网关不一定在重启前清除陈旧属性，但不会创建新的 `VpnService`。

### 有 root 权限

`resetprop` 可以隐藏旧版键，但只覆盖一个表面。不要在真实解析器路径不一致的情况下替换 DNS 值。优先移除属性来源，或使用不会改变全局网络的系统过滤器。

### 如何验证结果

```bash
for p in net.vpn.dns1 net.vpn.dns2 net.vpn.dns3 net.vpn.dns4 dhcp.tun0.dns1 dhcp.tun0.dns2 net.interfaces.default.type net.interfaces.default.name; do
  printf '%s=' "$p"; adb shell getprop "$p"
done
```
禁用 VPN 并重启后重复检查。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

全局替换 DNS 或属性值可能造成 DNS 泄漏或域名解析中断。不要用脚本清空所有 `net.*` 属性。

### 回滚

删除定向 `resetprop` 规则并重启；恢复原有 VPN 与 DNS 配置。

## 证据等级

**高。**已根据精确属性列表核验；`vpn_prop` 位于旧版高置信度 `kind` 集合中。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Android system properties](https://source.android.com/docs/core/architecture/configuration/sysprops-apis).
- 外部第一方文档或官方项目：[VpnService.Builder DNS](https://developer.android.com/reference/android/net/VpnService.Builder).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `dns-property`, `hook-property`, `interface-enumeration`.

[返回原生检查参考](../)
