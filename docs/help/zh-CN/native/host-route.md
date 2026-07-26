---
title: "经物理接口的公网 /32 或 /128 主机路由"
permalink: /help/zh-CN/native/host-route/
---

# 经物理接口的公网 /32 或 /128 主机路由

> **ID：** `HOST_ROUTE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`isVpnServerHostRouteCandidate()` 只考虑以下 netlink 行：不是默认路由、前缀为 `/32` 或 `/128`、类型为 `unicast`、scope 为 `global` 或 `link`、不属于本地表 255，且协议不是 kernel。目标必须是可公网路由地址，接口必须是标准物理接口。这种形态类似把 VPN 服务器地址固定在隧道外，但运营商与系统服务也可能合法创建。

### 精确触发条件

匹配的公网主机路由会以中等置信度设置 `needsReview=true`；`detected` 仍为 false。

## 结果含义

这只是候选信号，不是证明。典型 Android `VpnService` 通常通过 `protect()` 或 fwmark 排除 VPN 服务器套接字，并不需要单独主机路由，因此该信号对 root/内核 VPN 或非标准客户端更有意义。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

CDN、强制门户、运营商 IMS、OEM 安全服务或静态网络配置都可能合法创建 /32 路由。缺少进程或套接字关联时，不能把地址认定为 VPN 端点。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

先通过出现时机判断路由来源：分别比较 VPN 启动前、启动后和禁用后的快照。若客户端创建该路由，应优先使用标准 `VpnService.protect()` 或分流机制，不要手工删除。外部网关可以从手机上消除本地主机路由。

### 有 root 权限

内核后端可以隐藏这种路由形态，但按形态过滤可能误删合法 /32。上游 VPNHide 主要针对桌面式或 root VPN 记录了 host-route 逻辑。必须验证目标流量确实经过物理网络，且服务器套接字不会重新被送入隧道。

### 如何验证结果

```bash
adb shell ip -4 route show table all | grep -E '(^| )/32| scope link'
adb shell ip -6 route show table all | grep '/128'
```
采集三种状态：VPN 关闭、VPN 开启、客户端停止。提交 issue 前请对地址做脱敏。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

删除主机路由可能让 VPN 连接进入自身隧道并立即失效。过于宽泛地过滤此类路由还会干扰运营商服务。

### 回滚

重新启动 VPN 客户端或网络，让它重新创建路由。通过管理器禁用任何 root Hook 并重启。

## 证据等级

**中。**已根据 `isVpnServerHostRouteCandidate()` 的严格允许条件和 host-route 单元测试核验。该信号有意只用于 review。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[VpnService.protect()](https://developer.android.com/reference/android/net/VpnService).
- 外部第一方文档或官方项目：[rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- 外部第一方文档或官方项目：[VPNHide host-route notes](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `route-table`, `vpn-policy-rules-netlink`, `established-vpn-socket`.

[返回原生检查参考](../)
