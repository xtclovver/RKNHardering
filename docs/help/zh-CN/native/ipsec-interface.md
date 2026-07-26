---
title: "IPsec/XFRM 接口"
permalink: /help/zh-CN/native/ipsec-interface/
---

# IPsec/XFRM 接口

> **ID：** `IPSEC_INTERFACE`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

检查器使用正则表达式 `^(ipsec|xfrm).*` 匹配活动接口。与 TUN 模式不同，这一行只提供信息：Android、OEM VPN 和系统 IPsec 组件都可能合法创建此类接口。

### 精确触发条件

任何名称为 `ipsec*` 或 `xfrm*` 的活动接口，都会生成一条包含其名称和索引的信息性记录。

## 结果含义

该信号单独出现时不会把类别标记为 detected，也不要求绕过。只有与路由、XFRM 或 β 数据、外部 IP，或活动 VPN transport 结合时，它才具有分析价值。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

IPsec 可以只使用策略/XFRM 状态而不创建独立接口，OEM 也可能使用其他名称；反过来，企业资料可能会合法创建 XFRM 接口。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

若确实不需要 IPsec，请通过正常系统设置禁用对应的企业 VPN 或 always-on 资料。若业务需要它，不要仅因为一条信息性记录就重命名接口。外部网关可以把 IPsec 状态移出手机。

### 有 root 权限

只有在接口、路由与 XFRM 状态都能保持一致隐藏时，内核过滤才有意义。不要执行 `ip xfrm state flush` 删除 XFRM 状态；这会立即中断连接，并可能违反企业策略。测试时应使用单独设备。

### 如何验证结果

```bash
adb shell ip -details link show | grep -Ei 'ipsec|xfrm'
adb shell ip xfrm state 2>&1 | head -80
adb shell ip xfrm policy 2>&1 | head -80
```
普通 shell 可能无法访问部分 XFRM 数据；这并不表示数据不存在。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

禁用 always-on 或 lockdown VPN 可能移除强制流量保护。修改 XFRM 状态需要特权，并会立即中断当前会话。

### 回滚

恢复企业资料或 VPN 配置，然后重启网络。若使用过 root 模块，请禁用模块并重启设备。

## 证据等级

**低。**已根据 `NetworkInterfacePatterns.IPSEC_INTERFACE_PATTERN` 以及 `evaluateInterfaces()` 的信息性分支核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NetworkInterfacePatterns.kt` — 接口名称规则](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Linux XFRM device documentation](https://docs.kernel.org/networking/xfrm_device.html).
- 外部第一方文档或官方项目：[Android VPN guide](https://developer.android.com/develop/connectivity/vpn).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `interface-enumeration`, `vpn-policy-rules-netlink`, `route-table`.

[返回原生检查参考](../)
