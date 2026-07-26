---
title: "保留的旧版 UDP VPN 端口 ID"
permalink: /help/zh-CN/native/udp-vpn-port/
---

# 保留的旧版 UDP VPN 端口 ID

> **ID：** `UDP_VPN_PORT`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`UDP_VPN_PORT` 和 `udp_vpn_port` 仍保留在信号目录中，甚至被标记为旧版高置信度信号，但当前 C++ 代码不会生成这一类型的行。启用中的 UDP 检查覆盖物理 IP 上的端口冲突以及 PMTU/GSO 诊断。

### 精确触发条件

不存在独立生成器；没有输出行时，高置信度策略也不会被触发。

## 结果含义

保留本页是为了兼容性。UDP 端口 500、4500、1194、1701 和 51820 的占用情况由 `udp-port-conflict-physical` 检查。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

Kotlin 中存在一个高置信度 ID，容易让人误以为检查已启用；本页明确区分信号目录项与真正的生成器。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

关闭不必要的 UDP 监听器，或把 VPN 移到网关。仅存在于信号目录中的 ID 无需绕过。

### 有 root 权限

只有在确实找到对应监听器后，才适合使用精确限定到 UID 的防火墙规则。VPN 需要 IKE 或 WireGuard 时，不要全局阻断相关端口。

### 如何验证结果

```bash
rg -n 'udp_vpn_port|udp_port_conflict_physical' app/src/main
adb shell ss -lun 2>/dev/null | head -80
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

全局阻断 UDP 500/4500 会破坏 IPsec；端口 51820 可能正被 WireGuard 使用。

### 回滚

只删除你新增的那条防火墙规则，并重新启动 VPN。

## 证据等级

**目录项/兼容性。**已根据信号目录映射以及不存在生成器这一事实核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `udp-port-conflict-physical`, `udp-pmtu-ok`, `udp-pmtu-fail`.

[返回原生检查参考](../)
